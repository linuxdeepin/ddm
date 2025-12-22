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
#include "XorgDisplayServer.h"
#include "TreelandDisplayServer.h"
#include "Seat.h"
#include "SocketServer.h"
#include "Messages.h"
#include "SocketWriter.h"

#include <QDebug>
#include <QFile>
#include <QTimer>
#include <QLocalSocket>

#include <linux/vt.h>
#include <pwd.h>
#include <qstringliteral.h>
#include <unistd.h>
#include <sys/time.h>

#include <sys/ioctl.h>
#include <fcntl.h>

#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusReply>

#include "Login1Manager.h"
#include "Login1Session.h"
#include "VirtualTerminal.h"
#include "config.h"

#define STRINGIFY(x) #x

namespace DDM {
    static bool isTtyInUse(const QString &desiredTty) {
        if (Logind::isAvailable()) {
            OrgFreedesktopLogin1ManagerInterface manager(Logind::serviceName(), Logind::managerPath(), QDBusConnection::systemBus());
            auto reply = manager.ListSessions();
            reply.waitForFinished();

            const auto info = reply.value();
            for(const SessionInfo &s : info) {
                OrgFreedesktopLogin1SessionInterface session(Logind::serviceName(), s.sessionPath.path(), QDBusConnection::systemBus());
                if (desiredTty == session.tTY() && session.state() != QLatin1String("closing")) {
                    qDebug() << "tty" << desiredTty << "already in use by" << session.user().path.path() << session.state()
                                      << session.display() << session.desktop() << session.vTNr();
                    return true;
                }
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

    Display::Display(Seat *parent)
        : QObject(parent)
        , seat(parent)
        , m_socketServer(new SocketServer(this)) {

        // Create display server
        terminalId = fetchAvailableVt();
        qDebug("Using VT %d", terminalId);
        m_treeland = new TreelandDisplayServer(m_socketServer, this);

        // Record current VT as ddm user session
        DaemonApp::instance()->displayManager()->AddSession(
            {},
            seat->name(),
            "ddm",
            static_cast<uint>(VirtualTerminal::currentVt()));

        // connect connected signal
        connect(m_socketServer, &SocketServer::connected, this, &Display::connected);

        // connect login signal
        connect(m_socketServer, &SocketServer::login, this, &Display::login);

        // connect logout signal
        connect(m_socketServer, &SocketServer::logout, this, &Display::logout);

        // connect unlock signal
        connect(m_socketServer, &SocketServer::unlock,this, &Display::unlock);

        // connect login result signals
        connect(this, &Display::loginFailed, m_socketServer, &SocketServer::loginFailed);
        connect(this, &Display::loginSucceeded, m_socketServer, &SocketServer::loginSucceeded);
    }

    Display::~Display() {
        for (auto *item : m_auths)
            disconnect(item, &Auth::userProcessFinished, this, &Display::userProcessFinished);
        stop();
    }

    void Display::switchToUser(const QString &user, int xdgSessionId) {
        if (xdgSessionId <= 0) {
            qFatal() << "Invalid xdg session id" << xdgSessionId << "for user" << user;
            return;
        }

        m_treeland->activateUser(user, xdgSessionId);

        if (Logind::isAvailable()) {
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

        for (auto *item : m_auths) {
            item->stop();
        }

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
        m_socket = socket;
        // send logined user (for possible crash recovery)
        SocketWriter writer(socket);
        for (Auth *auth : m_auths) {
            if (auth->active)
                writer << quint32(DaemonMessages::UserLoggedIn) << auth->user << auth->xdgSessionId;
        }
    }

    void Display::login(QLocalSocket *socket,
                        const QString &user, const QString &password,
                        const Session &session) {
        m_socket = socket;

        //the DDM user has special privileges that skip password checking so that we can load the greeter
        //block ever trying to log in as the DDM user
        if (user == QLatin1String("dde")) {
            emit loginFailed(m_socket, user);
            return;
        }

        // authenticate
        startAuth(user, password, session);
    }

    void Display::logout([[maybe_unused]] QLocalSocket *socket, int id) {
        OrgFreedesktopLogin1ManagerInterface manager(Logind::serviceName(), Logind::managerPath(), QDBusConnection::systemBus());
        manager.TerminateSession(QString::number(id));
    }

    void Display::unlock(QLocalSocket *socket,
                        const QString &user, const QString &password) {
        m_socket = socket;

        //the DDM user has special privileges that skip password checking so that we can load the greeter
        //block ever trying to log in as the DDM user
        if (user == QLatin1String("dde")) {
            emit loginFailed(m_socket, user);
            return;
        }

        // authenticate
        startIdentify(user, password);
    }

    void Display::startIdentify(const QString &user, const QString &password) {
        qDebug() << "start Identify user" << user;
        Auth auth(this);
        auth.setObjectName("userIdentify");

        auth.user = user;
        if (auth.authenticate(password.toLocal8Bit())) {
            DaemonApp::instance()->displayManager()->setLastActivatedUser(user);
            if (mainConfig.Users.RememberLastUser.get())
                stateConfig.Last.User.set(user);
            else
                stateConfig.Last.User.setDefault();
            stateConfig.save();

            m_treeland->onLoginSucceeded(user);
            // TODO: Use exact ID when there're multiple sessions for a user
            int xdgSessionId = 0;
            for (auto *auth : std::as_const(m_auths)) {
                if (auth->user == user && auth->xdgSessionId > 0) {
                    xdgSessionId = auth->xdgSessionId;
                    break;
                }
            }
            switchToUser(user, xdgSessionId);
        }
    }

    void Display::startAuth(const QString &user, const QString &password, const Session &session) {

        // respond to authentication requests
        Auth *auth = nullptr;
        for (auto *item : m_auths) {
            if (item->user == user) {
                auth = item;
                break;
            }
        }

        if (!auth)
            auth = new Auth(this);

        if (auth->active) {
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

        auth->user = user;
        auth->tty = terminalId;
        auth->singleMode = session.isSingleMode();
        if (!auth->authenticate(password.toLocal8Bit()))
            return;

        // some information
        qDebug() << "Session" << session.fileName() << "selected, command:" << session.exec()
                 << "for VT" << auth->tty;

        DaemonApp::instance()->displayManager()->setLastActivatedUser(user);

        // save last user and last session
        if (mainConfig.Users.RememberLastUser.get())
            stateConfig.Last.User.set(auth->user);
        else
            stateConfig.Last.User.setDefault();
        if (mainConfig.Users.RememberLastSession.get())
            stateConfig.Last.Session.set(session.fileName());
        else
            stateConfig.Last.Session.setDefault();
        stateConfig.save();

        QProcessEnvironment env;
        env.insert(session.additionalEnv());

        // session id
        const QString sessionId = QStringLiteral("Session%1").arg(daemonApp->newSessionId());
        daemonApp->displayManager()->AddSession(sessionId, seat->name(), user, auth->tty);
        daemonApp->displayManager()->setLastSession(sessionId);
        env.insert(QStringLiteral("XDG_SESSION_PATH"), daemonApp->displayManager()->sessionPath(sessionId));
        auth->sessionId = sessionId;

        env.insert(QStringLiteral("PATH"), mainConfig.Users.DefaultPath.get());
        env.insert(QStringLiteral("DESKTOP_SESSION"), session.desktopSession());
        if (!session.desktopNames().isEmpty())
            env.insert(QStringLiteral("XDG_CURRENT_DESKTOP"), session.desktopNames());
        env.insert(QStringLiteral("XDG_SESSION_CLASS"), QStringLiteral("user"));
        env.insert(QStringLiteral("XDG_SESSION_TYPE"), session.xdgSessionType());
        env.insert(QStringLiteral("XDG_VTNR"), QString::number(auth->tty));
        env.insert(QStringLiteral("XDG_SEAT"), seat->name());
        env.insert(QStringLiteral("XDG_SEAT_PATH"), daemonApp->displayManager()->seatPath(seat->name()));
        env.insert(QStringLiteral("XDG_SESSION_DESKTOP"), session.desktopNames());

        DisplayServerType type;
        QByteArray cookie;
        if (session.isSingleMode()) {
            type = Treeland;
            env.insert("DDE_CURRENT_COMPOSITOR", "TreeLand");
            m_treeland->onLoginSucceeded(user);
        } else if (session.xdgSessionType() == QLatin1String("x11")) {
            type = X11;

            // stop treeland
            m_treeland->stop();
            sleep(1); // give some time to treeland to stop before starting Xorg

            m_x11Server = new XorgDisplayServer(this);
            connect(m_x11Server, &XorgDisplayServer::stopped, this, &Display::stop);
            if (!m_x11Server->start(auth->tty)) {
                qCritical() << "Failed to start X11 display server";
                return;
            }
            m_x11Server->setupDisplay();
            env.insert(QStringLiteral("DISPLAY"), m_x11Server->display);
            cookie = m_x11Server->cookie();
        } else {
            type = Wayland;
            // stop treeland
            m_treeland->stop();
            sleep(1); // give some time to treeland to stop before starting Wayland session
        }

        int xdgSessionId = auth->openSession(env);
        if (xdgSessionId <= 0) {
            auth->stop();
            delete auth;
            return;
        }
        if (type == Treeland)
            switchToUser(auth->user, xdgSessionId);

        connect(auth, &Auth::userProcessFinished, this, &Display::userProcessFinished);
        auth->startUserProcess(session.exec(), type, cookie);

        m_auths << auth;
    }

    void Display::userProcessFinished([[maybe_unused]] int status) {
        Auth* auth = qobject_cast<Auth*>(sender());

        daemonApp->displayManager()->RemoveSession(auth->sessionId);

        m_auths.removeOne(auth);
        delete auth;

        // TODO: switch to greeter
        m_treeland->activateUser("dde", 0);
    }
}
