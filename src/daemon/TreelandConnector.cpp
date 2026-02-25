// Copyright (C) 2025 April Lu <apr3vau@outlook.com>.
// SPDX-License-Identifier: GPL-2.0-or-later

#include "TreelandConnector.h"

// DDM
#include "Auth.h"
#include "DaemonApp.h"
#include "Display.h"
#include "DisplayManager.h"
#include "Login1Manager.h"
#include "PowerManager.h"
#include "SeatManager.h"
#include "Session.h"
#include "VirtualTerminal.h"
#include "treeland-ddm-v2.h"

// Qt
#include <QDebug>
#include <QFile>
#include <QObject>
#include <QScopeGuard>
#include <QSocketDescriptor>
#include <QSocketNotifier>

// Wayland
#include <wayland-client.h>

// System
#include <linux/vt.h>
#include <sys/ioctl.h>
#include <systemd/sd-device.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

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

    static Display *findSeatOfDevice(QString path) {
        // Get the seat of the active VT
        sd_device *device = nullptr;
        const char *idSeat = nullptr;
        auto guard = qScopeGuard([&] {
            if (device)
                sd_device_unref(device);
            if (idSeat)
                free((void *)idSeat);
        });
        sd_device_new_from_path(&device, qPrintable(path));
        if (!device) {
            qWarning() << "Failed to get seat for device" << path;
            return nullptr;
        }
        sd_device_get_property_value(device, "ID_SEAT", &idSeat);
        QString idSeatStr = !idSeat || idSeat[0] == '\0' ? "seat0" : QString::fromLocal8Bit(idSeat);
        auto res = std::ranges::find_if(daemonApp->seatManager()->displays, [&](const Display *d) {
            return d->name == idSeatStr;
        });
        return res == daemonApp->seatManager()->displays.end() ? nullptr : *res;
    }

    static inline Display *displayForVt(int vtnr)
    {
        return findSeatOfDevice(VirtualTerminal::path(vtnr));
    }

    /**
     * Callback function of disableRender
     *
     * This will be called after treeland render has been disabled, which is
     * happened after a VT release-display signal, to finalize VT switching (see
     * onReleaseDisplay()).
     */
    static void renderDisabled([[maybe_unused]] void *data,
                               struct wl_callback *callback,
                               [[maybe_unused]] uint32_t serial) {
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
                qWarning(
                    "Failed to parse active VT from /sys/class/tty/tty0/active with content %s",
                    qPrintable(active));
                return;
            }
        }

        auto display = displayForVt(activeVt);
        if (!display) {
            qWarning() << "Failed to find seat for active VT" << activeVt;
            return;
        }
        auto conn = display->connector;
        auto user = daemonApp->displayManager()->findUserByVt(activeVt);
        bool isTreeland = isVtRunningTreeland(activeVt);
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

    static const wl_callback_listener renderDisabledListener{
        .done = renderDisabled,
    };

    static void onAcquireDisplay() {
        int fd = open(defaultVtPath, O_RDWR | O_NOCTTY);

        // Activate treeland session before we acknowledge VT switch.
        // This will queue our rendering jobs before any keyboard event, to ensure
        // all GUI elements are under a prepared state before next possible VT
        // switch issued by keyboard.
        int vtnr = VirtualTerminal::getVtActive(fd);
        auto guard = qScopeGuard([&] {
            ioctl(fd, VT_RELDISP, VT_ACKACQ);
            close(fd);
        });

        auto display = displayForVt(vtnr);
        if (!display) {
            qWarning() << "Failed to find seat for VT" << vtnr;
            return;
        }
        auto conn = display->connector;
        auto user = daemonApp->displayManager()->findUserByVt(vtnr);
        if (isVtRunningTreeland(vtnr)) {
            qDebug("Activate session at VT %d for user %s", vtnr, qPrintable(user));
            conn->activateSession();
            conn->enableRender();
            conn->switchToUser(user);
        }
    }

    static void onReleaseDisplay() {
        int vtnr = VirtualTerminal::currentVt();
        auto display = displayForVt(vtnr);
        if (!display) {
            qWarning() << "Failed to find seat for VT" << vtnr;
            return;
        }
        auto callback = display->connector->disableRender();
        wl_callback_add_listener(callback, &renderDisabledListener, nullptr);
    }

    //////////////////////
    // Class definition //
    //////////////////////

    TreelandConnector::TreelandConnector(Display *display)
        : QObject(display) {
        m_connectTimer = new QTimer(this);
        m_connectTimer->setInterval(300);
        QObject::connect(m_connectTimer, &QTimer::timeout, this, &TreelandConnector::tryConnect);

        VirtualTerminal::setVtSignalHandler(onAcquireDisplay, onReleaseDisplay);
    }

    TreelandConnector::~TreelandConnector() {
        if (m_notifier)
            delete m_notifier;
        if (m_display)
            wl_display_disconnect(m_display);
    }

    //////////////////////////
    // Event implementation //
    //////////////////////////

    static void login(void *data,
                      [[maybe_unused]] struct treeland_ddm_v2 *ddm,
                      const char *username,
                      const char *secret,
                      uint32_t session_type,
                      const char *session_file) {
        auto connector = static_cast<TreelandConnector *>(data);
        auto display = static_cast<Display *>(connector->parent());
        display->login(QString::fromLocal8Bit(username),
                       QString::fromLocal8Bit(secret),
                       Session(Session::Type(session_type), QString::fromUtf8(session_file)));
    }

    static void logout(void *data,
                       [[maybe_unused]] struct treeland_ddm_v2 *ddm,
                       const char *session) {
        auto connector = static_cast<TreelandConnector *>(data);
        auto display = static_cast<Display *>(connector->parent());
        display->logout(QString::fromLocal8Bit(session));
    }

    static void lock(void *data,
                     [[maybe_unused]] struct treeland_ddm_v2 *ddm,
                     const char *session) {
        auto connector = static_cast<TreelandConnector *>(data);
        auto display = static_cast<Display *>(connector->parent());
        display->lock(QString::fromLocal8Bit(session));
    }

    static void unlock(void *data,
                       [[maybe_unused]] struct treeland_ddm_v2 *ddm,
                       const char *username,
                       const char *secret) {
        auto connector = static_cast<TreelandConnector *>(data);
        auto display = static_cast<Display *>(connector->parent());
        display->unlock(QString::fromLocal8Bit(username), QString::fromLocal8Bit(secret));
    }

    static void poweroff([[maybe_unused]] void *data,
                         [[maybe_unused]] struct treeland_ddm_v2 *ddm) {
        daemonApp->powerManager()->powerOff();
    }

    static void reboot([[maybe_unused]] void *data,
                       [[maybe_unused]] struct treeland_ddm_v2 *ddm) {
        daemonApp->powerManager()->reboot();
    }

    static void suspend([[maybe_unused]] void *data,
                        [[maybe_unused]] struct treeland_ddm_v2 *ddm) {
        daemonApp->powerManager()->suspend();
    }

    static void hibernate([[maybe_unused]] void *data,
                          [[maybe_unused]] struct treeland_ddm_v2 *ddm) {
        daemonApp->powerManager()->hibernate();
    }

    static void hybridSleep([[maybe_unused]] void *data,
                            [[maybe_unused]] struct treeland_ddm_v2 *ddm) {
        daemonApp->powerManager()->hybridSleep();
    }

    static void switchToVt([[maybe_unused]] void *data,
                           [[maybe_unused]] struct treeland_ddm_v2 *ddm,
                           int32_t vtnr) {
        int fd = open(qPrintable(VirtualTerminal::path(vtnr)), O_RDWR | O_NOCTTY);
        if (ioctl(fd, VT_ACTIVATE, vtnr) < 0)
            qWarning("Failed to switch to VT %d: %s", vtnr, strerror(errno));
        close(fd);
    }

    const struct treeland_ddm_v2_listener treelandDDMListener{
        .login = login,
        .logout = logout,
        .lock = lock,
        .unlock = unlock,
        .poweroff = poweroff,
        .reboot = reboot,
        .suspend = suspend,
        .hibernate = hibernate,
        .hybrid_sleep = hybridSleep,
        .switch_to_vt = switchToVt,
    };

    ///////////////////////////////
    // Handle wayland connection //
    ///////////////////////////////

    void registerGlobal(void *data,
                        struct wl_registry *registry,
                        uint32_t name,
                        const char *interface,
                        uint32_t version) {
        if (strcmp(interface, "treeland_ddm_v2") == 0) {
            auto conn = static_cast<TreelandConnector *>(data);
            auto proxy = static_cast<struct treeland_ddm_v2 *>(
                wl_registry_bind(registry, name, &treeland_ddm_v2_interface, version));
            treeland_ddm_v2_add_listener(proxy, &treelandDDMListener, conn);
            conn->proxy = proxy;
            qDebug("Connected to treeland_ddm_v2 global object");

            // Acquire VT control immediately
            int fd = open(qPrintable(VirtualTerminal::path(0)), O_RDWR | O_NOCTTY);
            VirtualTerminal::handleVtSwitches(fd);
            close(fd);

            // Send capabilities
            conn->capabilities(daemonApp->powerManager()->capabilities());

            auto display = static_cast<Display *>(conn->parent());
            for (Auth *auth : std::as_const(display->auths))
                if (auth->sessionOpened)
                    conn->userLoggedIn(auth->user, auth->session);
        }
    }

    void removeGlobal([[maybe_unused]] void *data,
                      [[maybe_unused]] struct wl_registry *registry,
                      [[maybe_unused]] uint32_t name) {
        // Do not deregister the global object (set proxy to null) here,
        // as wlroots will send global_remove event when session deactivated,
        // which is not what we want. The connection will be preserved after that.
    }

    const struct wl_registry_listener registryListener{
        .global = registerGlobal,
        .global_remove = removeGlobal,
    };

    void TreelandConnector::connect() {
        if (m_connectTimer->isActive())
            return;
        disconnect();
        tryConnect();
    }

    void TreelandConnector::tryConnect() {
        m_display = wl_display_connect("/run/treeland/wayland-0");
        if (!m_display) {
            qInfo("Failed to connect to treeland, retrying...");
            if (!m_connectTimer->isActive())
                m_connectTimer->start();
        } else {
            if (m_connectTimer->isActive())
                m_connectTimer->stop();
            connected();
        }
    }

    void TreelandConnector::connected() {
        wl_registry *registry = wl_display_get_registry(m_display);
        wl_registry_add_listener(registry, &registryListener, this);
        wl_display_roundtrip(m_display);

        while (wl_display_dispatch_pending(m_display) > 0);
        wl_display_flush(m_display);
        m_notifier = new QSocketNotifier(wl_display_get_fd(m_display), QSocketNotifier::Read);
        QObject::connect(m_notifier, &QSocketNotifier::activated, this, [&] {
            if ((wl_display_dispatch(m_display) == -1 || wl_display_flush(m_display) == -1)
                && errno != EAGAIN) {
                qWarning("Treeland connection lost!");
                disconnect();
                // Auto reconnect
                QTimer::singleShot(1000, this, &TreelandConnector::tryConnect);
            }
        });
    }

    void TreelandConnector::disconnect() {
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
        proxy = nullptr;
        qInfo("Disconnected from treeland");
    }

    /////////////////////
    // Request wrapper //
    /////////////////////

    void TreelandConnector::capabilities(uint32_t capabilities) const {
        if (proxy) {
            treeland_ddm_v2_capabilities(proxy, capabilities);
            wl_display_flush(m_display);
        } else {
            qWarning("Treeland is not connected when trying to call capabilities");
        }
    }

    void TreelandConnector::userLoggedIn(const QString &username, const QString &session) const {
        if (proxy) {
            treeland_ddm_v2_user_logged_in(proxy, qPrintable(username), qPrintable(session));
            wl_display_flush(m_display);
        } else {
            qWarning("Treeland is not connected when trying to call userLoggedIn");
        }
    }

    void TreelandConnector::authenticationFailed(uint32_t error) const {
        if (proxy) {
            treeland_ddm_v2_authentication_failed(proxy, error);
            wl_display_flush(m_display);
        } else {
            qWarning("Treeland is not connected when trying to call authenticationFailed");
        }
    }

    void TreelandConnector::switchToGreeter() const {
        if (proxy) {
            treeland_ddm_v2_switch_to_greeter(proxy);
            wl_display_flush(m_display);
        } else {
            qWarning("Treeland is not connected when trying to call switchToGreeter");
        }
    }

    void TreelandConnector::switchToUser(const QString &username) const {
        if (proxy) {
            treeland_ddm_v2_switch_to_user(proxy, qPrintable(username));
            wl_display_flush(m_display);
        } else {
            qWarning("Treeland is not connected when trying to call switchToUser");
        }
    }

    void TreelandConnector::activateSession() const {
        if (proxy) {
            treeland_ddm_v2_activate_session(proxy);
            wl_display_flush(m_display);
        } else {
            qWarning("Treeland is not connected when trying to call activateSession");
        }
    }

    void TreelandConnector::deactivateSession() const {
        if (proxy) {
            treeland_ddm_v2_deactivate_session(proxy);
            wl_display_flush(m_display);
        } else {
            qWarning("Treeland is not connected when trying to call deactivateSession");
        }
    }

    void TreelandConnector::enableRender() const {
        if (proxy) {
            treeland_ddm_v2_enable_render(proxy);
            wl_display_flush(m_display);
        } else {
            qWarning("Treeland is not connected when trying to call enableRender");
        }
    }

    struct wl_callback *TreelandConnector::disableRender() const {
        if (proxy) {
            auto callback = treeland_ddm_v2_disable_render(proxy);
            wl_display_flush(m_display);
            return callback;
        } else {
            qWarning("Treeland is not connected when trying to call disableRender");
            return nullptr;
        }
    }

} // namespace DDM
