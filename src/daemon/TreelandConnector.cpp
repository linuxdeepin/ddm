// Copyright (C) 2025 April Lu <apr3vau@outlook.com>.
// SPDX-License-Identifier: Apache-2.0 OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only

#include "TreelandConnector.h"
#include "DaemonApp.h"
#include "DisplayManager.h"
#include "VirtualTerminal.h"
#include "treeland-ddm-v1.h"

#include <QObject>
#include <QSocketNotifier>
#include <QSocketDescriptor>
#include <QDebug>

#include <wayland-client-core.h>
#include <wayland-client-protocol.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/vt.h>
#include <sys/ioctl.h>

namespace DDM {

// Virtural Terminal helper from VirturalTerminal.h

static const char *defaultVtPath = "/dev/tty0";

static void onAcquireDisplay() {
    int fd = open(defaultVtPath, O_RDWR | O_NOCTTY);
    ioctl(fd, VT_RELDISP, VT_ACKACQ);
    int vtnr = VirtualTerminal::getVtActive(fd);
    close(fd);
    auto user = daemonApp->displayManager()->findUserByVt(vtnr);
    if (!user.isEmpty()) {
        qDebug("Activate session at VT %d for user %s", vtnr, qPrintable(user));
        daemonApp->treelandConnector()->switchToUser(user);
        daemonApp->treelandConnector()->activateSession();
    }
}

static void onReleaseDisplay() {
    int fd = open(defaultVtPath, O_RDWR | O_NOCTTY);
    ioctl(fd, VT_RELDISP, 1);
    close(fd);
    int activeVtFd = open(defaultVtPath, O_RDWR | O_NOCTTY);
    int activeVt = VirtualTerminal::getVtActive(activeVtFd);
    auto user = daemonApp->displayManager()->findUserByVt(activeVt);
    qDebug("Next VT: %d, user: %s", activeVt, qPrintable(user));
    if (user.isEmpty()) {
        // We must switch Treeland to greeter mode before we switch back to it,
        // or it will get stuck.
        daemonApp->treelandConnector()->switchToGreeter();
        daemonApp->treelandConnector()->deactivateSession();
    } else {
        // If user is not empty, it means the switching can be issued by
        // ddm-helper. It uses VT signals from VirtualTerminal.h,
        // which is not what we want, so we should acquire VT control here.
        VirtualTerminal::handleVtSwitches(activeVtFd);
    }
    close(activeVtFd);
}

// TreelandConnector

TreelandConnector::TreelandConnector() : QObject(nullptr) {
    VirtualTerminal::setVtSignalHandler(onAcquireDisplay, onReleaseDisplay);
}

TreelandConnector::~TreelandConnector() {
    delete m_notifier;
    wl_display_disconnect(m_display);
}

bool TreelandConnector::isConnected() {
    return m_ddm;
}

void TreelandConnector::setPrivateObject(struct treeland_ddm *ddm) {
    m_ddm = ddm;
}

// Event implementation

void switchToVt([[maybe_unused]] void *data, [[maybe_unused]] struct treeland_ddm *ddm, int32_t vtnr) {
    int fd = open(qPrintable(VirtualTerminal::path(vtnr)), O_RDWR | O_NOCTTY);
    if (ioctl(fd, VT_ACTIVATE, vtnr) < 0)
        qWarning("Failed to switch to VT %d: %s", vtnr, strerror(errno));
    close(fd);
}

void acquireVt([[maybe_unused]] void *data, [[maybe_unused]] struct treeland_ddm *ddm, int32_t vtnr) {
    int fd = open(qPrintable(VirtualTerminal::path(vtnr)), O_RDWR | O_NOCTTY);
    VirtualTerminal::handleVtSwitches(fd);
    close(fd);
}

const struct treeland_ddm_listener treelandDDMListener {
    .switch_to_vt = switchToVt,
    .acquire_vt = acquireVt,
};

// wayland object binding

void registerGlobal(void *data, struct wl_registry *registry, uint32_t name, const char *interface, uint32_t version) {
    if (strcmp(interface, "treeland_ddm") == 0) {
        auto connector = static_cast<TreelandConnector *>(data);
        auto ddm = static_cast<struct treeland_ddm *>(
            wl_registry_bind(registry, name, &treeland_ddm_interface, version)
        );
        treeland_ddm_add_listener(ddm, &treelandDDMListener, connector);
        connector->setPrivateObject(ddm);
        qDebug("Connected to treeland_ddm global object");
    }
}

void removeGlobal([[maybe_unused]] void *data, [[maybe_unused]] struct wl_registry *registry, [[maybe_unused]] uint32_t name) {
    // Do not deregister the global object (set m_priv to null) here,
    // as wlroots will send global_remove event when session deactivated,
    // which is not what we want. The connection will be preserved after that.
}

const struct wl_registry_listener registryListener {
    .global = registerGlobal,
    .global_remove = removeGlobal,
};

void TreelandConnector::connect(QString socketPath) {
    m_display = wl_display_connect(qPrintable(socketPath));
    auto registry = wl_display_get_registry(m_display);

    wl_registry_add_listener(registry, &registryListener, this);

    wl_display_roundtrip(m_display);

    while (wl_display_prepare_read(m_display) != 0)
        wl_display_dispatch_pending(m_display);
    wl_display_flush(m_display);
    m_notifier = new QSocketNotifier(wl_display_get_fd(m_display), QSocketNotifier::Read);
    QObject::connect(m_notifier, &QSocketNotifier::activated, this, [this] {
      wl_display_read_events(m_display);
      while (wl_display_prepare_read(m_display) != 0)
        wl_display_dispatch_pending(m_display);
      wl_display_flush(m_display);
    });
}

// Request wrapper

void TreelandConnector::switchToGreeter() {
    if (isConnected()) {
        treeland_ddm_switch_to_greeter(m_ddm);
        wl_display_flush(m_display);
    } else {
        qWarning("Treeland is not connected when trying to call switchToGreeter");
    }
}

void TreelandConnector::switchToUser(const QString username) {
    if (isConnected()) {
        treeland_ddm_switch_to_user(m_ddm, qPrintable(username));
        wl_display_flush(m_display);
    } else {
        qWarning("Treeland is not connected when trying to call switchToUser");
    }
}

void TreelandConnector::activateSession() {
    if (isConnected()) {
        treeland_ddm_activate_session(m_ddm);
        wl_display_flush(m_display);
    } else {
        qWarning("Treeland is not connected when trying to call activateSession");
    }
}

void TreelandConnector::deactivateSession() {
    if (isConnected()) {
        treeland_ddm_deactivate_session(m_ddm);
        wl_display_flush(m_display);
    } else {
        qWarning("Treeland is not connected when trying to call deactivateSession");
    }
}

}
