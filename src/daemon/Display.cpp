/***************************************************************************
 * Copyright (C) 2025-2026 UnionTech Software Technology Co., Ltd.
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
#include "DdeSeatdControl.h"
#include "DisplayManager.h"
#include "Login1Manager.h"
#include "Login1Session.h"
#include "SeatManager.h"
#include "SocketServer.h"
#include "TreelandConnector.h"
#include "TreelandDisplayServer.h"
#include "XorgDisplayServer.h"
#include "config.h"

#include <linux/vt.h>
#include <systemd/sd-login.h>

#include <QDBusConnection>
#include <QDBusObjectPath>
#include <QDBusPendingCallWatcher>
#include <QDBusPendingReply>
#include <QDebug>
#include <QFile>
#include <QScopeGuard>
#include <qstringliteral.h>

#include <chrono>
#include <pwd.h>
#include <sys/time.h>
#include <unistd.h>
#include <utility>

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
        const auto vt = daemonApp->seatdControl()->activeVt();
        if (vt > 0 && !isTtyInUse(QStringLiteral("tty%1").arg(vt))) {
            return vt;
        }
        return daemonApp->seatdControl()->findAvailableVt();
    }

    static bool isVtReservedByDdm(int vt) {
        for (Display *display : std::as_const(daemonApp->seatManager()->displays)) {
            if (display->terminalId == vt)
                return true;
            for (Auth *auth : std::as_const(display->auths)) {
                if (auth->tty == vt)
                    return true;
            }
        }
        return false;
    }

    static int fetchAvailableUserVt() {
        for (int vt = DDM_INITIAL_VT; vt <= MAX_NR_CONSOLES; ++vt) {
            if (isVtReservedByDdm(vt))
                continue;
            if (!isTtyInUse(QStringLiteral("tty%1").arg(vt)))
                return vt;
        }

        return daemonApp->seatdControl()->findAvailableVt();
    }

    Display::Display(SeatManager *parent, QString name)
        : QObject(parent)
        , name(name)
        , m_socketServer(new SocketServer(this, this)) {

        // Create display server
        terminalId = fetchAvailableVt();
        qDebug("Using VT %d", terminalId);
        m_treeland = new TreelandDisplayServer(m_socketServer, this);

        // Record current VT as ddm user session
        DaemonApp::instance()->displayManager()->AddSession({ }, name, "dde", terminalId);

        // connect login result signals
        connect(this, &Display::loginFailed, m_socketServer, &SocketServer::loginFailed);

        // connect Treeland lock state → sync to logind
        connect(daemonApp->treelandConnector(),
                &TreelandConnector::lockStateChanged,
                this,
                &Display::onTreelandLockStateChanged);
    }

    Display::~Display() {
        stop();
    }

    void Display::activateSession(const QString &user, int xdgSessionId) {
        qWarning() << "Display activateSession requested for user" << user << "xdgSessionId"
                   << xdgSessionId << "display VT" << terminalId;
        if (xdgSessionId <= 0 && user != QStringLiteral("dde")) {
            qCritical() << "Invalid xdg session id" << xdgSessionId << "for user" << user;
            return;
        }

        m_activeTreelandSessionId = xdgSessionId;
        m_treeland->activateUser(user, xdgSessionId);

        if (xdgSessionId > 0 && Logind::isAvailable()) {
            OrgFreedesktopLogin1ManagerInterface manager(Logind::serviceName(),
                                                         Logind::managerPath(),
                                                         QDBusConnection::systemBus());
            manager.ActivateSession(QString::number(xdgSessionId));
        }
    }

    bool Display::start() {
        if (m_started)
            return true;

        if (!daemonApp->seatdControl()->requestSwitchVt(terminalId)) {
            qCritical() << "Failed to switch to greeter VT" << terminalId;
            return false;
        }
        // start socket server before treeland so the greeter can connect back to DDM
        if (!m_socketServer->start())
            return false;

        if (!m_treeland->start()) {
            m_socketServer->stop();
            return false;
        }

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

    void Display::connected() {
        m_socketServer->replayUserSessions();
    }

    void Display::onTreelandLockStateChanged(bool locked) {
        m_treelandLocked = locked;
        if (m_activeTreelandSessionId <= 0)
            return;
        OrgFreedesktopLogin1ManagerInterface manager(Logind::serviceName(),
                                                     Logind::managerPath(),
                                                     QDBusConnection::systemBus());
        if (locked)
            manager.LockSession(QString::number(m_activeTreelandSessionId));
        else
            manager.UnlockSession(QString::number(m_activeTreelandSessionId));
    }

    void Display::watchUserSession(Auth *auth) {
        if (!auth || auth->xdgSessionId <= 0)
            return;

        OrgFreedesktopLogin1ManagerInterface manager(Logind::serviceName(),
                                                     Logind::managerPath(),
                                                     QDBusConnection::systemBus());
        auto reply = manager.GetSession(QString::number(auth->xdgSessionId));
        auto *watcher = new QDBusPendingCallWatcher(reply, this);
        QPointer<Auth> authPtr(auth);
        connect(watcher, &QDBusPendingCallWatcher::finished, this, [this, watcher, authPtr] {
            QDBusPendingReply<QDBusObjectPath> reply = *watcher;
            watcher->deleteLater();
            if (!authPtr)
                return;
            if (reply.isError()) {
                qWarning() << "Failed to get logind session path" << authPtr->xdgSessionId
                           << reply.error().message();
                return;
            }

            auto *session = new OrgFreedesktopLogin1SessionInterface(Logind::serviceName(),
                                                                     reply.value().path(),
                                                                     QDBusConnection::systemBus(),
                                                                     authPtr);
            session->setObjectName(QStringLiteral("logindSessionWatcher"));
            connect(session, &OrgFreedesktopLogin1SessionInterface::Lock, this, [this, authPtr] {
                if (!authPtr)
                    return;
                if (m_activeTreelandSessionId != authPtr->xdgSessionId)
                    return;
                daemonApp->treelandConnector()->lock();
            });
            connect(session, &OrgFreedesktopLogin1SessionInterface::Unlock, this, [this, authPtr] {
                if (!authPtr)
                    return;
                if (m_activeTreelandSessionId != authPtr->xdgSessionId) {
                    OrgFreedesktopLogin1ManagerInterface manager(Logind::serviceName(),
                                                                 Logind::managerPath(),
                                                                 QDBusConnection::systemBus());
                    manager.LockSession(QString::number(authPtr->xdgSessionId));
                    return;
                }
                if (m_treelandLocked) {
                    constexpr int windowMs = 2000;
                    constexpr int maxLockBacks = 3;
                    const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
                    if (now - m_lockBackWindowStart > windowMs) {
                        m_lockBackWindowStart = now;
                        m_lockBackCount = 0;
                    }
                    if (m_lockBackCount >= maxLockBacks)
                        return;
                    OrgFreedesktopLogin1ManagerInterface manager(Logind::serviceName(),
                                                                 Logind::managerPath(),
                                                                 QDBusConnection::systemBus());
                    manager.LockSession(QString::number(authPtr->xdgSessionId));
                    ++m_lockBackCount;
                }
            });
        });
    }

    void Display::unwatchUserSession(Auth *auth) {
        if (!auth)
            return;

        const auto watchers = auth->findChildren<OrgFreedesktopLogin1SessionInterface *>(
            QStringLiteral("logindSessionWatcher"));
        for (auto *watcher : watchers)
            watcher->deleteLater();
    }

    void Display::login(const QString &user, const QString &password, const Session &session) {
        if (user == QLatin1String("dde")) {
            qWarning() << "Login attempt for user dde";
            emit loginFailed(user);
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
        const bool insertedAuth = !auths.contains(auth);
        if (insertedAuth)
            auths << auth;

        // sanity check
        if (!session.isValid()) {
            qCritical() << "Invalid session" << session.fileName();
            if (insertedAuth) {
                auths.removeAll(auth);
                delete auth;
            }
            return;
        }
        if (session.xdgSessionType().isEmpty()) {
            qCritical() << "Failed to find XDG session type for session" << session.fileName();
            if (insertedAuth) {
                auths.removeAll(auth);
                delete auth;
            }
            return;
        }
        if (session.exec().isEmpty()) {
            qCritical() << "Failed to find command for session" << session.fileName();
            if (insertedAuth) {
                auths.removeAll(auth);
                delete auth;
            }
            return;
        }

        const QString sessionId = QStringLiteral("Session%1").arg(daemonApp->newSessionId());

        // Run password check
        if (!auth->authenticate(password.toLocal8Bit())) {
            if (insertedAuth) {
                auths.removeAll(auth);
                delete auth;
            }
            Q_EMIT loginFailed(user);
            return;
        }

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

        auth->sessionId = sessionId;

        // Special preparation for each display server type
        //
        // TODO: Let Treeland drop DRM master when inactive, so that X
        // server and other Wayland compositor can co-exist with
        // greeter (the Treeland)
        QByteArray cookie;
        if (session.isSingleMode()) {
            auth->type = Treeland;
            const int ownerPid = daemonApp->treelandConnector()->treelandMainPid();
            auth->tty = daemonApp->seatdControl()->createGroupVt(ownerPid, user, sessionId);
            if (auth->tty <= 0) {
                qCritical() << "Failed to allocate grouped VT for Treeland user session";
                auths.removeAll(auth);
                delete auth;
                return;
            }
        } else if (session.xdgSessionType() == QLatin1String("x11")) {
            auth->type = X11;
            auth->tty = fetchAvailableUserVt();
        } else {
            auth->type = Wayland;
            auth->tty = fetchAvailableUserVt();
        }

        if (auth->tty <= 0) {
            qCritical() << "Failed to allocate VT for user session";
            auths.removeAll(auth);
            delete auth;
            return;
        }

        qInfo() << "Authentication succeeded for user" << user << ", opening session"
                << session.fileName() << ", command:" << session.exec() << ", VT:" << auth->tty;

        // Prepare session environment
        QProcessEnvironment env;
        env.insert(session.additionalEnv());

        env.insert(QStringLiteral("XDG_SESSION_PATH"),
                   daemonApp->displayManager()->sessionPath(sessionId));

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

        if (session.isSingleMode()) {
            env.insert("DDE_CURRENT_COMPOSITOR", "TreeLand");
        } else if (session.xdgSessionType() == QLatin1String("x11")) {
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
                delete m_x11Server;
                m_x11Server = nullptr;
                auths.removeAll(auth);
                delete auth;
                return;
            }
            m_x11Server->setupDisplay();
            auth->display = m_x11Server->display;
            env.insert(QStringLiteral("DISPLAY"), m_x11Server->display);
            cookie = m_x11Server->cookie();
        } else {
            qInfo() << "Stopping Treeland";
            daemonApp->treelandConnector()->disconnect();
            m_treeland->stop();
            QThread::msleep(500); // give some time to treeland to stop properly
        }

        // Open Logind session & Exec the desktop process
        int xdgSessionId = auth->openSession(session.exec(), env, cookie);

        if (xdgSessionId <= 0) {
            qCritical() << "Failed to open logind session for user" << user;
            if (auth->type == Treeland)
                daemonApp->seatdControl()->destroyGroupVt(auth->tty);
            auths.removeAll(auth);
            delete auth;
            return;
        }

        connect(auth, &Auth::sessionFinished, this, [this, auth]() {
            qWarning() << "Session for user" << auth->user << "finished";
            unwatchUserSession(auth);
            m_socketServer->removeUserSession(auth->user, auth->xdgSessionId);
            auths.removeAll(auth);
            daemonApp->displayManager()->RemoveSession(auth->sessionId);
            if (auth->type == Treeland)
                daemonApp->seatdControl()->destroyGroupVt(auth->tty);
            delete auth;
        });
        daemonApp->displayManager()->AddSession(sessionId, name, user, auth->tty);
        daemonApp->displayManager()->setLastSession(sessionId);
        m_socketServer->addUserSession(user, xdgSessionId);
        watchUserSession(auth);

        if (auth->type == Treeland)
            activateSession(user, xdgSessionId);
        qInfo() << "Successfully logged in user" << user;
    }

    void Display::logout(int id) {
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

} // namespace DDM
