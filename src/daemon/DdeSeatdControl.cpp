// Copyright (C) 2026 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#include "DdeSeatdControl.h"

#include <QLocalSocket>
#include <QDebug>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace DDM {

static constexpr auto controlSocketPath = "/run/dde-seatd-control.sock";
static constexpr uint16_t maxControlPayloadSize = 4096;
static constexpr size_t maxControlStringLength = 64;

enum ControlOpcode : uint16_t {
    ControlCreateGroupVt = 1,
    ControlDestroyGroupVt = 2,
    ControlGetActiveVt = 3,
    ControlFindFreeVt = 4,
    ControlSwitchVt = 5,
    ControlGroupVtCreated = 100,
    ControlVtChanged = 101,
    ControlOk = 102,
    ControlActiveVt = 103,
    ControlFreeVt = 104,
    ControlError = 255,
};

struct ControlHeader {
    uint16_t opcode;
    uint16_t size;
};

struct ControlCreateGroupVtRequest {
    int32_t ownerPid;
    int32_t vt;
    char user[maxControlStringLength];
    char session[maxControlStringLength];
};

struct ControlDestroyGroupVtRequest {
    int32_t vt;
};

struct ControlSwitchVtRequest {
    int32_t vt;
};

struct ControlGroupVtCreatedEvent {
    int32_t ownerPid;
    int32_t vt;
};

struct ControlVtStateEvent {
    int32_t vt;
};

struct ControlVtChangeEvent {
    int32_t oldVt;
    int32_t newVt;
};

struct ControlErrorMessage {
    int32_t error;
};

static int connectUnixSocket(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd == -1)
        return -1;

    sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    const size_t pathLength = strlen(path);
    if (pathLength >= sizeof(addr.sun_path)) {
        close(fd);
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(addr.sun_path, path, pathLength + 1);
    const auto size = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + pathLength + 1);
    if (::connect(fd, reinterpret_cast<sockaddr *>(&addr), size) == -1) {
        close(fd);
        return -1;
    }
    return fd;
}

static ssize_t recvAll(int fd, void *buffer, size_t size) {
    auto *data = static_cast<char *>(buffer);
    size_t received = 0;
    while (received < size) {
        const auto ret = recv(fd, data + received, size - received, 0);
        if (ret == -1) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (ret == 0) {
            errno = ECONNRESET;
            return -1;
        }
        received += static_cast<size_t>(ret);
    }
    return static_cast<ssize_t>(received);
}

static bool sendAll(int fd, const void *buffer, size_t size) {
    const auto *data = static_cast<const char *>(buffer);
    size_t sent = 0;
    while (sent < size) {
        const auto ret = send(fd, data + sent, size - sent, MSG_NOSIGNAL);
        if (ret == -1) {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (ret == 0) {
            errno = EPIPE;
            return false;
        }
        sent += static_cast<size_t>(ret);
    }
    return true;
}

static bool waitForReadable(int fd, int timeoutMs) {
    pollfd pollFd {
        .fd = fd,
        .events = POLLIN,
        .revents = 0,
    };
    int pollResult = -1;
    do {
        pollResult = poll(&pollFd, 1, timeoutMs);
    } while (pollResult == -1 && errno == EINTR);
    if (pollResult == 0) {
        errno = ETIMEDOUT;
        return false;
    }
    if (pollResult < 0)
        return false;
    if ((pollFd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 || (pollFd.revents & POLLIN) == 0) {
        errno = ECONNRESET;
        return false;
    }
    return true;
}

static bool readControlResponse(int fd, uint16_t expectedOpcode, void *payload, uint16_t payloadSize) {
    if (!waitForReadable(fd, 3000))
        return false;

    ControlHeader responseHeader {};
    if (recvAll(fd, &responseHeader, sizeof(responseHeader)) != static_cast<ssize_t>(sizeof(responseHeader)))
        return false;

    if (responseHeader.opcode == ControlError && responseHeader.size == sizeof(ControlErrorMessage)) {
        ControlErrorMessage error {};
        if (recvAll(fd, &error, sizeof(error)) != static_cast<ssize_t>(sizeof(error)))
            return false;
        errno = error.error;
        return false;
    }

    if (responseHeader.opcode != expectedOpcode || responseHeader.size != payloadSize) {
        errno = EPROTO;
        return false;
    }

    if (payloadSize == 0)
        return true;

    return recvAll(fd, payload, payloadSize) == static_cast<ssize_t>(payloadSize);
}

static bool sendControlRequest(int fd, uint16_t opcode, const void *payload, uint16_t payloadSize) {
    ControlHeader header {
        .opcode = opcode,
        .size = payloadSize,
    };
    if (!sendAll(fd, &header, sizeof(header)))
        return false;
    if (payloadSize == 0)
        return true;
    return sendAll(fd, payload, payloadSize);
}

template <size_t N>
static void copyFixedString(char (&target)[N], const QString &source, const char *fieldName) {
    const auto bytes = source.toUtf8();
    memset(target, 0, N);
    if (bytes.size() >= static_cast<qsizetype>(N)) {
        qWarning() << "Truncating dde-seatd control" << fieldName << "from"
                   << bytes.size() << "to" << (N - 1) << "bytes";
    }
    const auto length = std::min(static_cast<size_t>(bytes.size()), N - 1);
    memcpy(target, bytes.constData(), length);
}

DdeSeatdControl::DdeSeatdControl(QObject *parent)
    : QObject(parent) {
}

DdeSeatdControl::~DdeSeatdControl() {
    disconnectEventSocket();
}

bool DdeSeatdControl::connectEventSocket() {
    if (m_eventSocket && m_eventSocket->state() == QLocalSocket::ConnectedState)
        return true;

    disconnectEventSocket();

    m_eventSocket = new QLocalSocket(this);
    connect(m_eventSocket, &QLocalSocket::readyRead, this, &DdeSeatdControl::handleEventSocket);
    connect(m_eventSocket, &QLocalSocket::disconnected, this, &DdeSeatdControl::disconnectEventSocket);
    connect(m_eventSocket, &QLocalSocket::errorOccurred, this, &DdeSeatdControl::handleEventSocketError);

    m_eventSocket->connectToServer(QString::fromLatin1(controlSocketPath));
    if (!m_eventSocket->waitForConnected(3000)) {
        qWarning() << "Failed to connect dde-seatd control event socket"
                   << controlSocketPath << ":" << m_eventSocket->errorString();
        disconnectEventSocket();
        return false;
    }

    m_activeVt = queryActiveVt();
    if (m_activeVt <= 0) {
        qWarning("Failed to initialize cached active VT from dde-seatd: %s", strerror(errno));
        disconnectEventSocket();
        return false;
    }

    qDebug("Connected dde-seatd control event socket");
    return true;
}

void DdeSeatdControl::disconnectEventSocket() {
    if (m_eventSocket) {
        m_eventSocket->blockSignals(true);
        if (m_eventSocket->state() != QLocalSocket::UnconnectedState)
            m_eventSocket->disconnectFromServer();
        m_eventSocket->deleteLater();
        m_eventSocket = nullptr;
    }
    m_eventBuffer.clear();
    m_activeVt = -1;
    m_pendingVt = -1;
}

int DdeSeatdControl::queryActiveVt() {
    const int fd = connectUnixSocket(controlSocketPath);
    if (fd == -1)
        return -1;

    if (!sendControlRequest(fd, ControlGetActiveVt, nullptr, 0)) {
        close(fd);
        return -1;
    }

    ControlVtStateEvent event {};
    const bool ok = readControlResponse(fd, ControlActiveVt, &event, sizeof(event));
    close(fd);
    return ok ? event.vt : -1;
}

int DdeSeatdControl::activeVt() {
    if (m_activeVt > 0)
        return m_activeVt;

    m_activeVt = queryActiveVt();
    if (m_activeVt == m_pendingVt)
        m_pendingVt = -1;
    return m_activeVt;
}

int DdeSeatdControl::findAvailableVt() {
    const int fd = connectUnixSocket(controlSocketPath);
    if (fd == -1)
        return -1;

    if (!sendControlRequest(fd, ControlFindFreeVt, nullptr, 0)) {
        close(fd);
        return -1;
    }

    ControlVtStateEvent event {};
    const bool ok = readControlResponse(fd, ControlFreeVt, &event, sizeof(event));
    close(fd);
    return ok ? event.vt : -1;
}

bool DdeSeatdControl::requestSwitchVt(int vt) {
    const int fd = connectUnixSocket(controlSocketPath);
    if (fd == -1)
        return false;

    ControlSwitchVtRequest request {
        .vt = vt,
    };
    if (!sendControlRequest(fd, ControlSwitchVt, &request, sizeof(request))) {
        close(fd);
        return false;
    }

    const bool ok = readControlResponse(fd, ControlOk, nullptr, 0);
    close(fd);
    if (ok)
        m_pendingVt = m_activeVt == vt ? -1 : vt;
    return ok;
}

int DdeSeatdControl::createGroupVt(int ownerPid, const QString &user, const QString &sessionId) {
    if (ownerPid <= 0) {
        errno = EINVAL;
        return -1;
    }

    const int fd = connectUnixSocket(controlSocketPath);
    if (fd == -1)
        return -1;

    ControlCreateGroupVtRequest request {};
    request.ownerPid = ownerPid;
    request.vt = 0;
    copyFixedString(request.user, user, "user");
    copyFixedString(request.session, sessionId, "session");

    if (!sendControlRequest(fd, ControlCreateGroupVt, &request, sizeof(request))) {
        close(fd);
        return -1;
    }

    ControlGroupVtCreatedEvent event {};
    const bool ok = readControlResponse(fd, ControlGroupVtCreated, &event, sizeof(event));
    close(fd);
    if (!ok)
        return -1;
    if (event.vt <= 0) {
        errno = EINVAL;
        return -1;
    }

    if (!connectEventSocket()) {
        destroyGroupVt(event.vt);
        return -1;
    }
    return event.vt;
}

bool DdeSeatdControl::sendDestroyGroupVt(int vt) {
    const int fd = connectUnixSocket(controlSocketPath);
    if (fd == -1)
        return false;

    ControlDestroyGroupVtRequest request {
        .vt = vt,
    };
    const bool ok = sendControlRequest(fd, ControlDestroyGroupVt, &request, sizeof(request));
    close(fd);
    return ok;
}

void DdeSeatdControl::destroyGroupVt(int vt) {
    if (vt > 0 && !sendDestroyGroupVt(vt))
        qWarning("Failed to destroy grouped VT %d: %s", vt, strerror(errno));
}

void DdeSeatdControl::handleEventSocket() {
    if (!m_eventSocket)
        return;

    const QByteArray chunk = m_eventSocket->readAll();
    if (chunk.isEmpty())
        return;

    m_eventBuffer.append(chunk);
    while (m_eventBuffer.size() >= static_cast<int>(sizeof(ControlHeader))) {
        ControlHeader header {};
        memcpy(&header, m_eventBuffer.constData(), sizeof(header));
        if (header.size > maxControlPayloadSize) {
            qWarning("Invalid dde-seatd control message size %u", header.size);
            disconnectEventSocket();
            return;
        }

        const int messageSize = static_cast<int>(sizeof(ControlHeader) + header.size);
        if (m_eventBuffer.size() < messageSize)
            return;

        const auto *payload = m_eventBuffer.constData() + sizeof(ControlHeader);
        switch (header.opcode) {
        case ControlVtChanged:
            if (header.size != sizeof(ControlVtChangeEvent)) {
                qWarning("Invalid dde-seatd control payload size %u for opcode %u",
                         header.size, header.opcode);
                break;
            }
            {
            ControlVtChangeEvent event {};
            memcpy(&event, payload, sizeof(event));
            m_activeVt = event.newVt;
            if (m_pendingVt == event.newVt)
                m_pendingVt = -1;
            Q_EMIT vtChanged(event.oldVt, event.newVt);
            }
            break;
        default:
            qWarning("Ignoring unknown dde-seatd control opcode %u with payload size %u",
                     header.opcode, header.size);
            break;
        }
        m_eventBuffer.remove(0, messageSize);
    }
}

void DdeSeatdControl::handleEventSocketError(QLocalSocket::LocalSocketError error) {
    if (!m_eventSocket)
        return;

    qWarning() << "dde-seatd control event socket error:" << error
               << m_eventSocket->errorString();
    disconnectEventSocket();
}

}
