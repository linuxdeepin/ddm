// Copyright (C) 2025-2026 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#include "TreelandConnector.h"
#include "Auth.h"
#include "DaemonApp.h"
#include "Display.h"
#include "DisplayManager.h"
#include "SeatManager.h"
#include "treeland-ddm-v1.h"

#include <QObject>
#include <QDBusInterface>
#include <QDBusObjectPath>
#include <QDBusReply>
#include <QDBusVariant>
#include <QLocalSocket>
#include <QSocketNotifier>
#include <QDebug>
#include <QVariant>

#include <wayland-client-core.h>
#include <wayland-client-protocol.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstddef>
#include <errno.h>
#include <fcntl.h>
#include <limits>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

namespace DDM {

static constexpr auto controlSocketPath = "/run/dde-seatd-control.sock";
static constexpr auto systemdService = "org.freedesktop.systemd1";
static constexpr auto systemdPath = "/org/freedesktop/systemd1";
static constexpr auto systemdManagerInterface = "org.freedesktop.systemd1.Manager";
static constexpr auto systemdPropertiesInterface = "org.freedesktop.DBus.Properties";
static constexpr auto systemdServiceInterface = "org.freedesktop.systemd1.Service";
static constexpr auto treelandUnit = "treeland.service";
static constexpr uint16_t maxControlPayloadSize = 4096;

enum ControlOpcode : uint16_t {
    ControlCreateGroupVt = 1,
    ControlDestroyGroupVt = 2,
    ControlGroupVtCreated = 100,
    ControlVtChanged = 101,
    ControlError = 255,
};

struct ControlHeader {
    uint16_t opcode;
    uint16_t size;
};

struct ControlCreateGroupVtRequest {
    int32_t ownerPid;
    int32_t vt;
    char user[64];
    char session[64];
};

struct ControlDestroyGroupVtRequest {
    int32_t vt;
};

struct ControlGroupVtCreatedEvent {
    int32_t ownerPid;
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
    auto data = static_cast<char *>(buffer);
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

template <size_t N>
static void copyFixedString(char (&target)[N], const QString &source) {
    const auto bytes = source.toUtf8();
    const auto length = std::min(static_cast<size_t>(bytes.size()), N - 1);
    memcpy(target, bytes.constData(), static_cast<size_t>(length));
    target[length] = '\0';
}

static bool isVtRunningTreeland(int vtnr) {
    for (Display *display : daemonApp->seatManager()->displays) {
        if (display->terminalId == vtnr)
            return true;
        for (Auth *auth : display->auths)
            if (auth->tty == vtnr && auth->type == Display::Treeland)
                return true;
    }
    return false;
}

static bool isTreelandGreeterVt(int vtnr) {
    for (Display *display : daemonApp->seatManager()->displays) {
        if (display->terminalId == vtnr)
            return true;
    }
    return false;
}

static QString findTreelandUserByVt(int vtnr) {
    if (vtnr <= 0)
        return {};

    auto user = daemonApp->displayManager()->findUserByVt(vtnr);
    if (!user.isEmpty())
        return user;

    for (Display *display : daemonApp->seatManager()->displays) {
        for (Auth *auth : display->auths) {
            if (auth->tty == vtnr && auth->type == Display::Treeland)
                return auth->user;
        }
    }

    if (isVtRunningTreeland(vtnr))
        user = daemonApp->displayManager()->LastActivatedUser();
    if (!user.isEmpty())
        return user;

    for (Display *display : daemonApp->seatManager()->displays) {
        if (display->terminalId == vtnr)
            return QStringLiteral("dde");
    }
    return {};
}

// TreelandConnector

TreelandConnector::TreelandConnector() : QObject(nullptr) {
}

TreelandConnector::~TreelandConnector() {
    disconnectControlSocket();
    delete m_notifier;
    if (m_display)
        wl_display_disconnect(m_display);
}

bool TreelandConnector::isConnected() {
    return m_ddm;
}

void TreelandConnector::setPrivateObject(struct treeland_ddm_v1 *ddm) {
    m_ddm = ddm;
}

void TreelandConnector::setSignalHandler() {
}

// Event implementation

static void switchToVt([[maybe_unused]] void *data, [[maybe_unused]] struct treeland_ddm_v1 *ddm, int32_t vtnr) {
    qWarning("Ignoring deprecated treeland switch_to_vt request for VT %d; wlroots/libseat handles VT switching directly", vtnr);
}

static void acquireVt([[maybe_unused]] void *data, [[maybe_unused]] struct treeland_ddm_v1 *ddm, [[maybe_unused]] int32_t vtnr) {
}

const struct treeland_ddm_v1_listener treelandDDMListener {
    .switch_to_vt = switchToVt,
    .acquire_vt = acquireVt,
};

// wayland object binding

void registerGlobal(void *data, struct wl_registry *registry, uint32_t name, const char *interface, uint32_t version) {
    if (strcmp(interface, "treeland_ddm_v1") == 0) {
        auto connector = static_cast<TreelandConnector *>(data);
        auto ddm = static_cast<struct treeland_ddm_v1 *>(
            wl_registry_bind(registry, name, &treeland_ddm_v1_interface, version)
        );
        treeland_ddm_v1_add_listener(ddm, &treelandDDMListener, connector);
        connector->setPrivateObject(ddm);
        qDebug("Connected to treeland_ddm global object");
    }
}

void removeGlobal([[maybe_unused]] void *data, [[maybe_unused]] struct wl_registry *registry, [[maybe_unused]] uint32_t name) {
    // Do not deregister the global object (set m_ddm to null) here,
    // as wlroots will send global_remove event when session deactivated,
    // which is not what we want. The connection will be preserved after that.
}

const struct wl_registry_listener registryListener {
    .global = registerGlobal,
    .global_remove = removeGlobal,
};

void TreelandConnector::connect(QString socketPath) {
    disconnect();
    if (!connectControlSocket()) {
        qCritical("Cannot connect Treeland without dde-seatd control socket");
        return;
    }

    m_display = wl_display_connect(qPrintable(socketPath));
    if (m_display == nullptr) {
        qWarning("Failed to connect to Treeland Wayland socket %s", qPrintable(socketPath));
        return;
    }
    auto registry = wl_display_get_registry(m_display);

    wl_registry_add_listener(registry, &registryListener, this);

    wl_display_roundtrip(m_display);

    while (wl_display_dispatch_pending(m_display) > 0);
    wl_display_flush(m_display);
    m_notifier = new QSocketNotifier(wl_display_get_fd(m_display), QSocketNotifier::Read);
    QObject::connect(m_notifier, &QSocketNotifier::activated, this, [this] {
        if (wl_display_dispatch(m_display) == -1 || wl_display_flush(m_display) == -1) {
            if (errno != EAGAIN) {
                qWarning("Treeland connection lost!");
                disconnect();
            }
        }
    });
}

void TreelandConnector::disconnect() {
    disconnectControlSocket();
    if (m_display) {
        if (m_notifier)
            m_notifier->setEnabled(false);
        wl_display_disconnect(m_display);
        if (m_notifier) {
            m_notifier->deleteLater();
            m_notifier = nullptr;
        }
        m_display = nullptr;
    }
    m_ddm = nullptr;
}

bool TreelandConnector::connectControlSocket() {
    if (m_controlSocket && m_controlSocket->state() == QLocalSocket::ConnectedState)
        return true;

    disconnectControlSocket();

    m_controlSocket = new QLocalSocket(this);
    QObject::connect(m_controlSocket, &QLocalSocket::readyRead, this, &TreelandConnector::handleControlSocket);
    QObject::connect(m_controlSocket, &QLocalSocket::disconnected, this, &TreelandConnector::disconnectControlSocket);

    m_controlSocket->connectToServer(QString::fromLatin1(controlSocketPath));
    if (!m_controlSocket->waitForConnected(3000)) {
        qWarning() << "Failed to connect dde-seatd control socket"
                   << controlSocketPath << ":" << m_controlSocket->errorString();
        disconnectControlSocket();
        return false;
    }
    qDebug("Connected dde-seatd control event socket via QLocalSocket");
    return true;
}

void TreelandConnector::disconnectControlSocket() {
    if (m_controlSocket) {
        if (m_controlSocket->state() == QLocalSocket::ConnectedState
            || m_controlSocket->state() == QLocalSocket::ClosingState) {
            qDebug("dde-seatd control socket disconnected");
        }
        m_controlSocket->blockSignals(true);
        if (m_controlSocket->state() != QLocalSocket::UnconnectedState)
            m_controlSocket->disconnectFromServer();
        m_controlSocket->deleteLater();
        m_controlSocket = nullptr;
    }
    m_controlBuffer.clear();
}

int TreelandConnector::treelandMainPid() const {
    QDBusInterface systemd(systemdService,
                           systemdPath,
                           systemdManagerInterface,
                           QDBusConnection::systemBus());
    const auto unitReply = systemd.call(QStringLiteral("GetUnit"), QString::fromLatin1(treelandUnit));
    if (unitReply.type() == QDBusMessage::ErrorMessage) {
        qWarning() << "Failed to get" << treelandUnit << "unit:" << unitReply.errorMessage();
        return -1;
    }

    const auto unitPath = qvariant_cast<QDBusObjectPath>(unitReply.arguments().value(0)).path();
    QDBusInterface properties(systemdService,
                              unitPath,
                              systemdPropertiesInterface,
                              QDBusConnection::systemBus());
    const auto reply = properties.call(QStringLiteral("Get"),
                                       QString::fromLatin1(systemdServiceInterface),
                                       QStringLiteral("MainPID"));
    if (reply.type() == QDBusMessage::ErrorMessage) {
        qWarning() << "Failed to get Treeland MainPID:" << reply.errorMessage();
        return -1;
    }

    const auto variant = qvariant_cast<QDBusVariant>(reply.arguments().value(0)).variant();
    bool ok = false;
    const auto pid = variant.toULongLong(&ok);
    if (!ok || pid == 0 || pid > static_cast<qulonglong>(std::numeric_limits<pid_t>::max())) {
        qWarning() << "Invalid Treeland MainPID from systemd:" << variant;
        return -1;
    }
    return static_cast<int>(pid);
}

int TreelandConnector::createGroupVtForTreeland(const QString &user, const QString &sessionId) {
    const int ownerPid = treelandMainPid();
    if (ownerPid <= 0)
        return -1;

    const int fd = connectUnixSocket(controlSocketPath);
    if (fd == -1) {
        qWarning("Failed to connect dde-seatd control socket %s: %s",
                 controlSocketPath, strerror(errno));
        return -1;
    }

    ControlHeader header {
        .opcode = ControlCreateGroupVt,
        .size = sizeof(ControlCreateGroupVtRequest),
    };
    ControlCreateGroupVtRequest request {};
    request.ownerPid = ownerPid;
    request.vt = 0;
    copyFixedString(request.user, user);
    copyFixedString(request.session, sessionId);

    struct {
        ControlHeader header;
        ControlCreateGroupVtRequest request;
    } message {
        .header = header,
        .request = request,
    };

    if (!sendAll(fd, &message, sizeof(message))) {
        qWarning("Failed to send create-group-vt request: %s", strerror(errno));
        close(fd);
        return -1;
    }

    pollfd pollFd {
        .fd = fd,
        .events = POLLIN,
        .revents = 0,
    };
    int pollResult = -1;
    do {
        pollResult = poll(&pollFd, 1, 3000);
    } while (pollResult == -1 && errno == EINTR);
    if (pollResult == -1) {
        qWarning("Failed waiting for dde-seatd create-group-vt response: %s", strerror(errno));
        close(fd);
        return -1;
    }
    if (pollResult == 0) {
        qWarning("Timed out waiting for dde-seatd create-group-vt response");
        close(fd);
        return -1;
    }
    if ((pollFd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 || (pollFd.revents & POLLIN) == 0) {
        qWarning("Invalid dde-seatd create-group-vt poll events: 0x%x", pollFd.revents);
        close(fd);
        errno = ECONNRESET;
        return -1;
    }

    ControlHeader responseHeader {};
    if (recvAll(fd, &responseHeader, sizeof(responseHeader)) != static_cast<ssize_t>(sizeof(responseHeader))) {
        qWarning("Failed to read create-group-vt response header: %s", strerror(errno));
        close(fd);
        return -1;
    }

    int vt = -1;
    if (responseHeader.opcode == ControlGroupVtCreated &&
        responseHeader.size == sizeof(ControlGroupVtCreatedEvent)) {
        ControlGroupVtCreatedEvent event {};
        if (recvAll(fd, &event, sizeof(event)) == static_cast<ssize_t>(sizeof(event)))
            vt = event.vt;
    } else if (responseHeader.opcode == ControlError &&
               responseHeader.size == sizeof(ControlErrorMessage)) {
        ControlErrorMessage error {};
        if (recvAll(fd, &error, sizeof(error)) == static_cast<ssize_t>(sizeof(error)))
            qWarning("dde-seatd create-group-vt failed: %s", strerror(error.error));
    } else {
        qWarning("Unexpected dde-seatd create-group-vt response opcode %u size %u",
                 responseHeader.opcode, responseHeader.size);
    }

    close(fd);
    if (vt > 0 && !connectControlSocket()) {
        qWarning("Failed to reconnect dde-seatd control event socket, rolling back grouped VT %d", vt);
        destroyGroupVt(vt);
        return -1;
    }
    return vt;
}

bool TreelandConnector::sendDestroyGroupVt(int vt) {
    const int fd = connectUnixSocket(controlSocketPath);
    if (fd == -1)
        return false;

    ControlHeader header {
        .opcode = ControlDestroyGroupVt,
        .size = sizeof(ControlDestroyGroupVtRequest),
    };
    ControlDestroyGroupVtRequest request {
        .vt = vt,
    };
    struct {
        ControlHeader header;
        ControlDestroyGroupVtRequest request;
    } message {
        .header = header,
        .request = request,
    };
    const bool ok = sendAll(fd, &message, sizeof(message));
    close(fd);
    return ok;
}

void TreelandConnector::destroyGroupVt(int vt) {
    if (vt > 0 && !sendDestroyGroupVt(vt))
        qWarning("Failed to destroy grouped VT %d: %s", vt, strerror(errno));
}

void TreelandConnector::handleControlSocket() {
    if (!m_controlSocket)
        return;

    const QByteArray chunk = m_controlSocket->readAll();
    if (chunk.isEmpty())
        return;

    m_controlBuffer.append(chunk);
    while (m_controlBuffer.size() >= static_cast<int>(sizeof(ControlHeader))) {
        ControlHeader header {};
        memcpy(&header, m_controlBuffer.constData(), sizeof(header));
        if (header.size > maxControlPayloadSize) {
            qWarning("Invalid dde-seatd control message size %u", header.size);
            disconnectControlSocket();
            return;
        }
        const int messageSize = static_cast<int>(sizeof(ControlHeader) + header.size);
        if (m_controlBuffer.size() < messageSize)
            return;

        const auto payload = m_controlBuffer.constData() + sizeof(ControlHeader);
        if (header.opcode == ControlVtChanged && header.size == sizeof(ControlVtChangeEvent)) {
            ControlVtChangeEvent event {};
            memcpy(&event, payload, sizeof(event));
            const bool oldIsTreelandVt = isVtRunningTreeland(event.oldVt);
            const bool oldIsGreeterVt = isTreelandGreeterVt(event.oldVt);
            const auto oldUser = findTreelandUserByVt(event.oldVt);
            const bool newIsTreelandVt = isVtRunningTreeland(event.newVt);
            const bool newIsGreeterVt = isTreelandGreeterVt(event.newVt);
            const auto newUser = findTreelandUserByVt(event.newVt);
            qInfo("dde-seatd VT change event: oldVt=%d oldIsTreelandVt=%d oldIsGreeterVt=%d oldUser=%s newVt=%d newIsTreelandVt=%d newIsGreeterVt=%d newUser=%s connected=%d",
                  event.oldVt,
                  oldIsTreelandVt,
                  oldIsGreeterVt,
                  qPrintable(oldUser),
                  event.newVt,
                  newIsTreelandVt,
                  newIsGreeterVt,
                  qPrintable(newUser),
                  isConnected());
            if (newIsTreelandVt) {
                if (newIsGreeterVt || newUser == QStringLiteral("dde")) {
                    switchToGreeter();
                } else {
                    switchToUser(newUser);
                }
            } else {
                qInfo("External VT %d became active; leaving seat transition to dde-seatd/libseat", event.newVt);
            }
        } else {
            qDebug("Ignored dde-seatd control message opcode=%u size=%u", header.opcode, header.size);
        }
        m_controlBuffer.remove(0, messageSize);
    }
}

// Request wrapper

void TreelandConnector::switchToGreeter() {
    if (isConnected()) {
        qDebug("Calling treeland switch_to_greeter");
        treeland_ddm_v1_switch_to_greeter(m_ddm);
        wl_display_flush(m_display);
    } else {
        qWarning("Treeland is not connected when trying to call switchToGreeter");
    }
}

void TreelandConnector::switchToUser(const QString username) {
    if (isConnected()) {
        qDebug("Calling treeland switch_to_user: user=%s", qPrintable(username));
        treeland_ddm_v1_switch_to_user(m_ddm, qPrintable(username));
        wl_display_flush(m_display);
    } else {
        qWarning("Treeland is not connected when trying to call switchToUser");
    }
}

}
