/***************************************************************************
* Copyright (c) 2014-2015 Pier Luigi Fiorini <pierluigi.fiorini@gmail.com>
* Copyright (c) 2014 Martin Bříza <mbriza@redhat.com>
* Copyright (c) 2013 Abdurrahman AVCI <abdurrahmanavci@gmail.com>
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the
* Free Software Foundation, Inc.,
* 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
***************************************************************************/

#include "Display.h"

#include "Auth.h"
#include "Configuration.h"
#include "DaemonApp.h"
#include "DisplayManager.h"
#include "Messages.h"
#include "SeatManager.h"
#include "SocketServer.h"
#include "SocketWriter.h"
#include "TreelandConnector.h"
#include "TreelandDisplayServer.h"
#include "XorgDisplayServer.h"

#include "config.h"
#include "Login1Manager.h"
#include "VirtualTerminal.h"

#include <QDBusConnection>
#include <QDebug>
#include <QFile>
#include <QLocalSocket>
#include <QScopeGuard>
#include <QTimer>

#include <fcntl.h>
#include <linux/vt.h>
#include <pwd.h>
#include <qstringliteral.h>
#include <systemd/sd-login.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>

#define STRINGIFY(x) #x

namespace DDM {
    static bool isTtyInUse(const QString &desiredTty) {
        char **sessions = nullptr;
        auto guard = qScopeGuard([&sessions] {
            if (sessions) {
                for (char **s = sessions; s && *s; ++s)
                    free(*s);
                free(sessions);
            }
        });
        sd_get_sessions(&sessions);
        for (char **s = sessions; s && *s; ++s) {
            char *tty = nullptr;
            char *state = nullptr;
            auto guard2 = qScopeGuard([&tty, &state] {
                if (tty)
                    free(tty);
                if (state)
                    free(state);
            });
            if (sd_session_get_tty(*s, &tty) < 0 || sd_session_get_state(*s, &state) < 0)
                continue;
            if (desiredTty == tty && strcmp(state, "closing") != 0) {
                qDebug() << "tty" << desiredTty << "already in use by session" << *s;
                return true;
            }
        }
        return false;
    }

    static int fetchAvailableVt() {
        if (!isTtyInUse(QStringLiteral("tty" STRINGIFY(DDM_INITIAL_VT)))) {
            return DDM_INITIAL_VT;
        }
        const auto vt = VirtualTerminal::currentVt();
        if (vt > 0 && !isTtyInUse(QStringLiteral("tty%1").arg(vt))) {
            return vt;
        }
        return VirtualTerminal::setUpNewVt();
    }

    Display::Display(SeatManager *parent, QString name)
        : QObject(parent)
        , name(name)
        , m_socketServer(new SocketServer(this)) {

        // Create display server
        terminalId = fetchAvailableVt();
        qDebug("Using VT %d", terminalId);
        m_treeland = new TreelandDisplayServer(m_socketServer, this);

        // Record current VT as ddm user session
        DaemonApp::instance()->displayManager()->AddSession(
            {},
            name,
            "dde",
            static_cast<uint>(VirtualTerminal::currentVt()));

        // connect connected signal
        connect(m_socketServer, &SocketServer::connected, this, &Display::connected);

        // connect login signal
        connect(m_socketServer, &SocketServer::login, this, &Display::login);

        // connect logout signal
        connect(m_socketServer, &SocketServer::logout, this, &Display::logout);

        // connect lock signal
        connect(m_socketServer, &SocketServer::lock, this, &Display::lock);

        // connect unlock signal
        connect(m_socketServer, &SocketServer::unlock,this, &Display::unlock);

        // connect login result signals
        connect(this, &Display::loginFailed, m_socketServer, &SocketServer::loginFailed);
    }

    Display::~Display() {
        stop();
    }

    void Display::activateSession(const QString &user, int xdgSessionId) {
        if (xdgSessionId <= 0 && user != QStringLiteral("dde")) {
            qCritical() << "Invalid xdg session id" << xdgSessionId << "for user" << user;
            return;
        }

        m_treeland->activateUser(user, xdgSessionId);

        if (xdgSessionId > 0 && Logind::isAvailable()) {
            OrgFreedesktopLogin1ManagerInterface manager(Logind::serviceName(), Logind::managerPath(), QDBusConnection::systemBus());
            manager.ActivateSession(QString::number(xdgSessionId));
        }
    }

    bool Display::start() {
        if (m_started)
            return true;

        VirtualTerminal::jumpToVt(terminalId, false);
        if (!m_treeland->start())
            return false;

        // start socket server
        m_socketServer->start("treeland");

        // Update dbus info
        DaemonApp::instance()->displayManager()->setAuthInfo(m_socketServer->socketAddress());

        // change the owner and group of the socket to avoid permission denied errors
        struct passwd *pw = getpwnam("dde");
        if (pw && chown(qPrintable(m_socketServer->socketAddress()), pw->pw_uid, pw->pw_gid) == -1)
            qWarning() << "Failed to change owner of the socket";

        // set flags
        m_started = true;

        return true;
    }

    void Display::stop() {
        // check flag
        if (!m_started)
            return;

        for (auto *auth : std::as_const(auths)) {
            disconnect(auth, &Auth::sessionFinished, nullptr, nullptr);
            delete auth;
        }
        auths.clear();

        // stop socket server
        m_socketServer->stop();

        if (m_x11Server)
            m_x11Server->stop();

        // stop display server
        m_treeland->stop();

        // reset flag
        m_started = false;

        // emit signal
        emit stopped();
    }

    void Display::connected(QLocalSocket *socket) {
        // send logged in users (for possible crash recovery)
        SocketWriter writer(socket);
        for (Auth *auth : std::as_const(auths)) {
            if (auth->sessionOpened)
                writer << quint32(DaemonMessages::UserLoggedIn) << auth->user << auth->xdgSessionId;
        }
    }

    void Display::login(QLocalSocket *socket,
                        const QString &user, const QString &password,
                        const Session &session) {
        if (user == QLatin1String("dde")) {
            qWarning() << "Login attempt for user dde";
            emit loginFailed(socket, user);
            return;
        }

        qInfo() << "Start login for user" << user;

        // Get Auth object
        Auth *auth = nullptr;
        for (auto *item : std::as_const(auths)) {
            if (item->user == user) {
                auth = item;
                break;
            }
        }

        if (!auth)
            auth = new Auth(this, user);

        if (auth->authenticated) {
            qWarning() << "Existing authentication ongoing, aborting";
            return;
        }

        // sanity check
        if (!session.isValid()) {
            qCritical() << "Invalid session" << session.fileName();
            return;
        }
        if (session.xdgSessionType().isEmpty()) {
            qCritical() << "Failed to find XDG session type for session" << session.fileName();
            return;
        }
        if (session.exec().isEmpty()) {
            qCritical() << "Failed to find command for session" << session.fileName();
            return;
        }

        // Run password check
        if (session.isSingleMode())
            auth->tty = VirtualTerminal::setUpNewVt();
        else
            auth->tty = terminalId;
        if (!auth->authenticate(password.toLocal8Bit())) {
            Q_EMIT loginFailed(socket, user);
            return;
        }

        // some information
        qInfo() << "Authentication succeeded for user" << user << ", opening session"
                << session.fileName() << ", command:" << session.exec() << ", VT:" << auth->tty;

        // save last user and last session
        DaemonApp::instance()->displayManager()->setLastActivatedUser(user);
        if (mainConfig.Users.RememberLastUser.get())
            stateConfig.Last.User.set(auth->user);
        else
            stateConfig.Last.User.setDefault();
        if (mainConfig.Users.RememberLastSession.get())
            stateConfig.Last.Session.set(session.fileName());
        else
            stateConfig.Last.Session.setDefault();
        stateConfig.save();

        // Prepare session environment
        QProcessEnvironment env;
        env.insert(session.additionalEnv());

        // session id
        const QString sessionId = QStringLiteral("Session%1").arg(daemonApp->newSessionId());
        env.insert(QStringLiteral("XDG_SESSION_PATH"), daemonApp->displayManager()->sessionPath(sessionId));
        auth->sessionId = sessionId;

        env.insert(QStringLiteral("PATH"), mainConfig.Users.DefaultPath.get());
        env.insert(QStringLiteral("DESKTOP_SESSION"), session.desktopSession());
        if (!session.desktopNames().isEmpty())
            env.insert(QStringLiteral("XDG_CURRENT_DESKTOP"), session.desktopNames());
        env.insert(QStringLiteral("XDG_SESSION_CLASS"), QStringLiteral("user"));
        env.insert(QStringLiteral("XDG_SESSION_TYPE"), session.xdgSessionType());
        env.insert(QStringLiteral("XDG_VTNR"), QString::number(auth->tty));
        env.insert(QStringLiteral("XDG_SEAT"), name);
        env.insert(QStringLiteral("XDG_SEAT_PATH"), daemonApp->displayManager()->seatPath(name));
        env.insert(QStringLiteral("XDG_SESSION_DESKTOP"), session.desktopNames());

        // Special preparation for each display server type
        //
        // TODO: Let Treeland drop DRM master when inactive, so that X
        // server and other Wayland compositor can co-exist with
        // greeter (the Treeland)
        QByteArray cookie;
        if (session.isSingleMode()) {
            auth->type = Treeland;
            env.insert("DDE_CURRENT_COMPOSITOR", "TreeLand");
        } else if (session.xdgSessionType() == QLatin1String("x11")) {
            auth->type = X11;

            qInfo() << "Stopping Treeland";
            daemonApp->treelandConnector()->disconnect();
            m_treeland->stop();
            QThread::msleep(500); // give some time to treeland to stop properly

            // Start X server
            qInfo() << "Starting X11 display server";
            m_x11Server = new XorgDisplayServer(this);
            connect(m_x11Server, &XorgDisplayServer::stopped, this, &Display::stop);
            if (!m_x11Server->start(auth->tty)) {
                qCritical() << "Failed to start X11 display server";
                return;
            }
            m_x11Server->setupDisplay();
            auth->display = m_x11Server->display;
            env.insert(QStringLiteral("DISPLAY"), m_x11Server->display);
            cookie = m_x11Server->cookie();
        } else {
            auth->type = Wayland;

            qInfo() << "Stopping Treeland";
            daemonApp->treelandConnector()->disconnect();
            m_treeland->stop();
            QThread::msleep(500); // give some time to treeland to stop properly
        }

        // Open Logind session & Exec the desktop process
        int xdgSessionId = auth->openSession(session.exec(), env, cookie);

        if (xdgSessionId <= 0) {
            qCritical() << "Failed to open logind session for user" << user;
            delete auth;
            return;
        }

        connect(auth, &Auth::sessionFinished, this, [this, auth]() {
            qWarning() << "Session for user" << auth->user << "finished";
            auths.removeAll(auth);
            daemonApp->displayManager()->RemoveSession(auth->sessionId);
            delete auth;
        });
        daemonApp->displayManager()->AddSession(sessionId, name, user, auth->tty);
        daemonApp->displayManager()->setLastSession(sessionId);

        // The user process is ongoing, append to active auths
        // The auth will be delete later in userProcessFinished()
        auths << auth;
        qInfo() << "Successfully logged in user" << user;
    }

    void Display::logout([[maybe_unused]] QLocalSocket *socket, int id) {
        qDebug() << "Logout requested for session id" << id;
        // Do not kill the session leader process before
        // TerminateSession! Logind will only kill the session's
        // cgroup (session_stop_scope) when the session is not in
        // "stopping" state, killing the session leader beforehand
        // will put the session in "stopping" early.

        // https://github.com/systemd/systemd/blob/main/src/login/logind-session.c#L938
        OrgFreedesktopLogin1ManagerInterface manager(Logind::serviceName(),
                                                     Logind::managerPath(),
                                                     QDBusConnection::systemBus());
        manager.TerminateSession(QString::number(id));
    }

    void Display::lock([[maybe_unused]] QLocalSocket *socket, int id) {
        qDebug() << "Lock requested for session id" << id;

        OrgFreedesktopLogin1ManagerInterface manager(Logind::serviceName(),
                                                     Logind::managerPath(),
                                                     QDBusConnection::systemBus());
        manager.LockSession(QString::number(id));
    }

    void Display::unlock(QLocalSocket *socket, const QString &user, const QString &password) {
        if (user == QLatin1String("dde")) {
            emit loginFailed(socket, user);
            return;
        }

        qInfo() << "Start identify user" << user;

        // Only run password check
        //
        // No user process execution, so the auth can be thrown away
        // immediately after use
        Auth auth(this, user);
        if (!auth.authenticate(password.toLocal8Bit())) {
            Q_EMIT loginFailed(socket, user);
            return;
        }

        // Save last user
        DaemonApp::instance()->displayManager()->setLastActivatedUser(user);
        if (mainConfig.Users.RememberLastUser.get())
            stateConfig.Last.User.set(user);
        else
            stateConfig.Last.User.setDefault();
        stateConfig.save();

        // Find the auth that started the session, which contains full informations
        for (auto *auth : std::as_const(auths)) {
            if (auth->user == user && auth->xdgSessionId > 0) {
                OrgFreedesktopLogin1ManagerInterface manager(Logind::serviceName(),
                                                             Logind::managerPath(),
                                                             QDBusConnection::systemBus());
                manager.UnlockSession(QString::number(auth->xdgSessionId));
                VirtualTerminal::jumpToVt(auth->tty, false);
                qInfo() << "Successfully identified user" << user;
                return;
            }
        }
        qWarning() << "No active session found for user" << user;
        Q_EMIT loginFailed(socket, user);
    }
}
