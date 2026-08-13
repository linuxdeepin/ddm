/***************************************************************************
 * Copyright (c) 2015 Pier Luigi Fiorini <pierluigi.fiorini@gmail.com>
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

#include "SocketServer.h"

#include "Auth.h"
#include "Configuration.h"
#include "DaemonApp.h"
#include "Display.h"
#include "PowerManager.h"
#include "TreelandConnector.h"

#include <QAbstractSocket>
#include <QDir>
#include <QFileInfo>
#include <QProcessEnvironment>
#include <QRemoteObjectHost>
#include <QUrl>

static constexpr auto ddmRemoteUrl = "local:org.deepin.dde.ddm.qro";
static constexpr auto ddmRemoteSourceName = "DDMRemote";

namespace {
    bool executableAllowed(const QString &tryExec) {
        if (tryExec.isEmpty())
            return true;

        QFileInfo executable(tryExec);
        if (executable.isAbsolute())
            return executable.exists() && executable.isExecutable();

        const auto paths = QProcessEnvironment::systemEnvironment()
                               .value(QStringLiteral("PATH"))
                               .split(QLatin1Char(':'), Qt::SkipEmptyParts);
        for (const auto &path : paths) {
            executable.setFile(QDir(path), tryExec);
            if (executable.exists() && executable.isExecutable())
                return true;
        }

        return false;
    }

    void appendSessions(QList<SessionEntry> &entries,
                        DDM::Session::Type type,
                        const QStringList &directories) {
        QStringList sessionFiles;
        for (const auto &path : directories) {
            QDir dir(path);
            dir.setNameFilters({ QStringLiteral("*.desktop") });
            dir.setFilter(QDir::Files);
            sessionFiles += dir.entryList();
        }
        sessionFiles.removeDuplicates();

        for (const auto &sessionFile : std::as_const(sessionFiles)) {
            DDM::Session session(type, sessionFile);
            if (!session.isValid() || session.isHidden() || session.isNoDisplay()
                || !executableAllowed(session.tryExec())) {
                continue;
            }

            SessionEntry entry;
            entry.setFileName(session.fileName());
            entry.setType(session.type());
            entry.setDisplayName(session.displayName());
            entry.setComment(session.comment());
            entry.setExec(session.exec());

            if (entry.displayName() == QStringLiteral("Treeland"))
                entries.prepend(entry);
            else
                entries.append(entry);
        }
    }
} // namespace

namespace DDM {
    SocketServer::SocketServer(Display *display, QObject *parent)
        : DDMRemoteSimpleSource(parent)
        , m_display(display)
        , m_powerManager(daemonApp->powerManager()) { }

    bool SocketServer::canPowerOff() {
        return m_powerManager->canPowerOff();
    }

    bool SocketServer::canReboot() {
        return m_powerManager->canReboot();
    }

    bool SocketServer::canSuspend() {
        return m_powerManager->canSuspend();
    }

    bool SocketServer::canHibernate() {
        return m_powerManager->canHibernate();
    }

    QList<SessionEntry> SocketServer::sessions() {
        QList<SessionEntry> entries;
        if (QFileInfo::exists(QStringLiteral("/dev/dri")))
            appendSessions(entries, Session::WaylandSession, mainConfig.Wayland.SessionDir.get());
        appendSessions(entries, Session::X11Session, mainConfig.X11.SessionDir.get());
        return entries;
    }

    QString SocketServer::lastSession() {
        return stateConfig.Last.Session.get();
    }

    QString SocketServer::lastUser() {
        return stateConfig.Last.User.get();
    }

    bool SocketServer::rememberLastSession() {
        return mainConfig.Users.RememberLastSession.get();
    }

    bool SocketServer::canHybridSleep() {
        return m_powerManager->canHybridSleep();
    }

    bool SocketServer::start() {
        if (m_host)
            return false;

        qDebug() << "Socket server starting...";

        m_host = new QRemoteObjectHost(QUrl(QString::fromLatin1(ddmRemoteUrl)), this);
        if (!m_host->enableRemoting(this, QString::fromLatin1(ddmRemoteSourceName))) {
            qCritical() << "Failed to enable DDMRemote source.";
            delete m_host;
            m_host = nullptr;
            return false;
        }

        setHostName(daemonApp->hostName());
        qDebug() << "Socket server started on" << ddmRemoteUrl;
        return true;
    }

    void SocketServer::stop() {
        if (!m_host)
            return;

        qDebug() << "Socket server stopping...";
        m_host->deleteLater();
        m_host = nullptr;
        qDebug() << "Socket server stopped.";
    }

    bool SocketServer::connectGreeter() {
        qDebug() << "Message received from greeter: Connect";
        if (!daemonApp->treelandConnector()->connect())
            return false;
        m_display->connected();
        return true;
    }

    void SocketServer::replayUserSessions() {
        for (Auth *auth : std::as_const(m_display->auths)) {
            if (auth->sessionOpened)
                addUserSession(auth->user, auth->xdgSessionId);
        }
    }

    void SocketServer::addUserSession(const QString &user, int sessionId) {
        if (sessionId > 0)
            emit userSessionAdded(user, sessionId);
    }

    void SocketServer::removeUserSession(const QString &user, int sessionId) {
        if (sessionId > 0)
            emit userSessionRemoved(user, sessionId);
    }

    bool SocketServer::login(QString user, QString password, int sessionType, QString sessionFile) {
        qDebug() << "Message received from greeter: Login";
        Session session(static_cast<Session::Type>(sessionType), sessionFile);
        m_display->login(user, password, session);
        return true;
    }

    bool SocketServer::logout(int id) {
        qDebug() << "Message received from greeter: Logout";
        m_display->logout(id);
        return true;
    }

    bool SocketServer::powerOff() {
        qDebug() << "Message received from greeter: PowerOff";
        m_powerManager->powerOff();
        return true;
    }

    bool SocketServer::reboot() {
        qDebug() << "Message received from greeter: Reboot";
        m_powerManager->reboot();
        return true;
    }

    bool SocketServer::suspend() {
        qDebug() << "Message received from greeter: Suspend";
        m_powerManager->suspend();
        return true;
    }

    bool SocketServer::hibernate() {
        qDebug() << "Message received from greeter: Hibernate";
        m_powerManager->hibernate();
        return true;
    }

    bool SocketServer::hybridSleep() {
        qDebug() << "Message received from greeter: HybridSleep";
        m_powerManager->hybridSleep();
        return true;
    }
} // namespace DDM
