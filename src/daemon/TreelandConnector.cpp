// Copyright (C) 2025-2026 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#include "TreelandConnector.h"

#include "treeland-ddm-v1.h"

#include <QDBusInterface>
#include <QDBusObjectPath>
#include <QDBusReply>
#include <QDBusVariant>
#include <QDebug>
#include <QVariant>

#include <wayland-client-core.h>
#include <wayland-client-protocol.h>

#include <errno.h>
#include <limits>
#include <string.h>
#include <unistd.h>

namespace DDM {

static constexpr auto systemdService = "org.freedesktop.systemd1";
static constexpr auto systemdPath = "/org/freedesktop/systemd1";
static constexpr auto systemdManagerInterface = "org.freedesktop.systemd1.Manager";
static constexpr auto systemdPropertiesInterface = "org.freedesktop.DBus.Properties";
static constexpr auto systemdServiceInterface = "org.freedesktop.systemd1.Service";
static constexpr auto treelandUnit = "treeland.service";

TreelandConnector::TreelandConnector(QObject *parent)
    : QObject(parent) {
}

TreelandConnector::~TreelandConnector() {
    disconnect();
}

bool TreelandConnector::isConnected() {
    return m_ddm;
}

int TreelandConnector::mainPid() {
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

void TreelandConnector::setPrivateObject(struct treeland_ddm_v1 *ddm) {
    m_ddm = ddm;
}

static void switchToVt([[maybe_unused]] void *data,
                       [[maybe_unused]] struct treeland_ddm_v1 *ddm,
                       int32_t vtnr) {
    qWarning("Ignoring deprecated treeland switch_to_vt request for VT %d; wlroots/libseat handles VT switching directly", vtnr);
}

static void acquireVt([[maybe_unused]] void *data,
                      [[maybe_unused]] struct treeland_ddm_v1 *ddm,
                      [[maybe_unused]] int32_t vtnr) {
}

const struct treeland_ddm_v1_listener treelandDDMListener {
    .switch_to_vt = switchToVt,
    .acquire_vt = acquireVt,
};

static void registerGlobal(void *data, struct wl_registry *registry, uint32_t name, const char *interface, uint32_t version) {
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

static void removeGlobal([[maybe_unused]] void *data,
                         [[maybe_unused]] struct wl_registry *registry,
                         [[maybe_unused]] uint32_t name) {
}

const struct wl_registry_listener registryListener {
    .global = registerGlobal,
    .global_remove = removeGlobal,
};

void TreelandConnector::connect(const QString &socketPath) {
    disconnect();

    m_display = wl_display_connect(qPrintable(socketPath));
    if (m_display == nullptr) {
        qWarning("Failed to connect to Treeland Wayland socket %s", qPrintable(socketPath));
        return;
    }
    auto registry = wl_display_get_registry(m_display);

    wl_registry_add_listener(registry, &registryListener, this);

    wl_display_roundtrip(m_display);

    while (wl_display_dispatch_pending(m_display) > 0) {
    }
    wl_display_flush(m_display);
    m_notifier = new QSocketNotifier(wl_display_get_fd(m_display), QSocketNotifier::Read, this);
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
    if (m_notifier) {
        m_notifier->setEnabled(false);
        delete m_notifier;
        m_notifier = nullptr;
    }
    if (m_display) {
        wl_display_disconnect(m_display);
        m_display = nullptr;
    }
    m_ddm = nullptr;
}

void TreelandConnector::switchToGreeter() {
    if (isConnected()) {
        qDebug("Calling treeland switch_to_greeter");
        treeland_ddm_v1_switch_to_greeter(m_ddm);
        wl_display_flush(m_display);
    } else {
        qWarning("Treeland is not connected when trying to call switchToGreeter");
    }
}

void TreelandConnector::switchToUser(const QString &username) {
    if (isConnected()) {
        qDebug("Calling treeland switch_to_user: user=%s", qPrintable(username));
        treeland_ddm_v1_switch_to_user(m_ddm, qPrintable(username));
        wl_display_flush(m_display);
    } else {
        qWarning("Treeland is not connected when trying to call switchToUser");
    }
}

}
