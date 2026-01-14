// Copyright (C) 2025 April Lu <apr3vau@outlook.com>.
// SPDX-License-Identifier: GPL-2.0-or-later

#include "TreelandConnector.h"
#include "Auth.h"
#include "DaemonApp.h"
#include "Display.h"
#include "DisplayManager.h"
#include "SeatManager.h"
#include "VirtualTerminal.h"
#include "treeland-ddm-v1.h"

#include <QObject>
#include <QSocketNotifier>
#include <QSocketDescriptor>
#include <QDebug>
#include <QFile>

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

/**
 * Callback function of disableRender
 *
 * This will be called after treeland render has been disabled, which is
 * happened after a VT release-display signal, to finalize VT switching (see
 * onReleaseDisplay()).
 */
static void renderDisabled([[maybe_unused]] void *data, struct wl_callback *callback, [[maybe_unused]] uint32_t serial) {
    wl_callback_destroy(callback);

    // Acknowledge kernel to release display
    int fd = open(defaultVtPath, O_RDWR | O_NOCTTY);
    ioctl(fd, VT_RELDISP, 1);
    close(fd);

    // Get active VT by reading /sys/class/tty/tty0/active .
    // Note that we cannot use open(defaultVtPath, ...) here, as the open() will
    // block VT file access, causing error to systemd-getty-generator, and stop
    // getty from spawning if current VT is empty.
    int activeVt = -1;
    QFile tty("/sys/class/tty/tty0/active");
    if (!tty.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qWarning("Failed to open active tty file");
    } else {
        auto active = tty.readAll();
        tty.close();
        int scanResult = sscanf(qPrintable(active), "tty%d", &activeVt);
        if (scanResult != 1) {
            qWarning("Failed to parse active VT from /sys/class/tty/tty0/active with content %s", qPrintable(active));
            activeVt = -1;
        }
    }

    auto user = daemonApp->displayManager()->findUserByVt(activeVt);
    bool isTreeland = isVtRunningTreeland(activeVt);
    auto conn = daemonApp->treelandConnector();
    qDebug("Next VT: %d, user: %s", activeVt, user.isEmpty() ? "None" : qPrintable(user));

    if (isTreeland) {
        // If user is not empty, it means the switching can be issued by
        // ddm-helper. It uses VT signals from VirtualTerminal.h,
        // which is not what we want, so we should acquire VT control here.
        int activeVtFd = open(defaultVtPath, O_RDWR | O_NOCTTY);
        VirtualTerminal::handleVtSwitches(activeVtFd);
        close(activeVtFd);

        conn->enableRender();
        conn->switchToUser(user.isEmpty() ? "dde" : user);
    } else {
        // Switch to a TTY, deactivate treeland session.
        conn->switchToGreeter();
        conn->deactivateSession();
    }
}

static const wl_callback_listener renderDisabledListener {
    .done = renderDisabled,
};

static void onAcquireDisplay() {
    int fd = open(defaultVtPath, O_RDWR | O_NOCTTY);

    // Activate treeland session before we acknowledge VT switch.
    // This will queue our rendering jobs before any keyboard event, to ensure
    // all GUI elements are under a prepared state before next possible VT
    // switch issued by keyboard.
    int vtnr = VirtualTerminal::getVtActive(fd);
    auto user = daemonApp->displayManager()->findUserByVt(vtnr);
    auto conn = daemonApp->treelandConnector();
    if (isVtRunningTreeland(vtnr)) {
        qDebug("Activate session at VT %d for user %s", vtnr, qPrintable(user));
        conn->activateSession();
        conn->enableRender();
        conn->switchToUser(user);
    }

    ioctl(fd, VT_RELDISP, VT_ACKACQ);
    close(fd);
}

static void onReleaseDisplay() {
    auto callback = daemonApp->treelandConnector()->disableRender();
    wl_callback_add_listener(callback, &renderDisabledListener, nullptr);
}

// TreelandConnector

TreelandConnector::TreelandConnector() : QObject(nullptr) {
    setSignalHandler();
}

TreelandConnector::~TreelandConnector() {
    delete m_notifier;
    wl_display_disconnect(m_display);
}

bool TreelandConnector::isConnected() {
    return m_ddm;
}

void TreelandConnector::setPrivateObject(struct treeland_ddm_v1 *ddm) {
    m_ddm = ddm;
}

void TreelandConnector::setSignalHandler() {
    VirtualTerminal::setVtSignalHandler(onAcquireDisplay, onReleaseDisplay);
}

// Event implementation

static void switchToVt([[maybe_unused]] void *data, [[maybe_unused]] struct treeland_ddm_v1 *ddm, int32_t vtnr) {
    int fd = open(qPrintable(VirtualTerminal::path(vtnr)), O_RDWR | O_NOCTTY);
    if (ioctl(fd, VT_ACTIVATE, vtnr) < 0)
        qWarning("Failed to switch to VT %d: %s", vtnr, strerror(errno));
    close(fd);
}

static void acquireVt([[maybe_unused]] void *data, [[maybe_unused]] struct treeland_ddm_v1 *ddm, int32_t vtnr) {
    int fd = open(qPrintable(VirtualTerminal::path(vtnr)), O_RDWR | O_NOCTTY);
    VirtualTerminal::handleVtSwitches(fd);
    close(fd);
}

const struct treeland_ddm_v1_listener treelandDDMListener {
    .switch_to_vt = switchToVt,
    .acquire_vt = acquireVt,
};

// wayland object binding

void registerGlobal(void *data, struct wl_registry *registry, uint32_t name, const char *interface, uint32_t version) {
    if (strcmp(interface, "treeland_ddm") == 0) {
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
    if (m_display) {
        wl_display_disconnect(m_display);
        QObject::disconnect(m_notifier, &QSocketNotifier::activated, nullptr, nullptr);
        delete m_notifier;
    }

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
        treeland_ddm_v1_switch_to_greeter(m_ddm);
        wl_display_flush(m_display);
    } else {
        qWarning("Treeland is not connected when trying to call switchToGreeter");
    }
}

void TreelandConnector::switchToUser(const QString username) {
    if (isConnected()) {
        treeland_ddm_v1_switch_to_user(m_ddm, qPrintable(username));
        wl_display_flush(m_display);
    } else {
        qWarning("Treeland is not connected when trying to call switchToUser");
    }
}

void TreelandConnector::activateSession() {
    if (isConnected()) {
        treeland_ddm_v1_activate_session(m_ddm);
        wl_display_flush(m_display);
    } else {
        qWarning("Treeland is not connected when trying to call activateSession");
    }
}

void TreelandConnector::deactivateSession() {
    if (isConnected()) {
        treeland_ddm_v1_deactivate_session(m_ddm);
        wl_display_flush(m_display);
    } else {
        qWarning("Treeland is not connected when trying to call deactivateSession");
    }
}

void TreelandConnector::enableRender() {
    if (isConnected()) {
        treeland_ddm_v1_enable_render(m_ddm);
        wl_display_flush(m_display);
    } else {
        qWarning("Treeland is not connected when trying to call enableRender");
    }
}

struct wl_callback *TreelandConnector::disableRender() {
    if (isConnected()) {
        auto callback = treeland_ddm_v1_disable_render(m_ddm);
        wl_display_flush(m_display);
        return callback;
    } else {
        qWarning("Treeland is not connected when trying to call disableRender");
        return nullptr;
    }
}

}
