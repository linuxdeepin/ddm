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

#include "DaemonApp.h"
#include "Messages.h"
#include "PowerManager.h"
#include "SocketWriter.h"
#include "TreelandConnector.h"
#include "Utils.h"

#include <QLocalServer>

namespace DDM {
    SocketServer::SocketServer(QObject *parent) : QObject(parent) {
    }

    QString SocketServer::socketAddress() const {
        if (m_server)
            return m_server->fullServerName();
        return QString();
    }

    bool SocketServer::start(const QString &displayName) {
        // check if the server has been created already
        if (m_server)
            return false;

        QString socketName = QStringLiteral("ddm-%1-%2").arg(displayName).arg(generateName(6));

        // log message
        qDebug() << "Socket server starting...";

        // create server
        m_server = new QLocalServer(this);

        // set server options
        m_server->setSocketOptions(QLocalServer::UserAccessOption);

        // start listening
        if (!m_server->listen(socketName)) {
            // log message
            qCritical() << "Failed to start socket server.";

            // return fail
            return false;
        }


        // log message
        qDebug() << "Socket server started.";

        // connect signals
        connect(m_server, &QLocalServer::newConnection, this, &SocketServer::newConnection);

        // return success
        return true;
    }

    void SocketServer::stop() {
        // check flag
        if (!m_server)
            return;

        // log message
        qDebug() << "Socket server stopping...";

        // delete server
        m_server->deleteLater();
        m_server = nullptr;

        // log message
        qDebug() << "Socket server stopped.";
    }

    void SocketServer::newConnection() {
        // get pending connection
        QLocalSocket *socket = m_server->nextPendingConnection();

        // connect signals
        connect(socket, &QLocalSocket::readyRead, this, &SocketServer::readyRead);
        connect(socket, &QLocalSocket::disconnected, socket, &QLocalSocket::deleteLater);
        connect(socket, &QLocalSocket::disconnected, this, [this, socket] {
            emit disconnected(socket);
        });
    }

    void SocketServer::readyRead() {
        QLocalSocket *socket = qobject_cast<QLocalSocket *>(sender());

        // check socket
        if (!socket)
            return;

        // input stream
        QDataStream input(socket);

        // QLocalSocket is stream-oriented: a message header may arrive before
        // the complete variable-length payload (e.g. a QString). Read each
        // message inside a QDataStream transaction and only act after the
        // whole payload has been committed; otherwise the stream is rolled
        // back and we wait for more data, avoiding emitting with incomplete
        // values and desynchronizing the stream.
        while(socket->bytesAvailable()) {
            input.startTransaction();

            // read message
            quint32 message = 0;
            input >> message;

            switch (GreeterMessages(message)) {
                case GreeterMessages::Connect: {
                    // Connect wayland socket
                    QString socketPath;
                    input >> socketPath;
                    if (!input.commitTransaction())
                        return;

                    // log message
                    qDebug() << "Message received from greeter: Connect";
                    daemonApp->treelandConnector()->connect(socketPath);

                    // send capabilities
                    SocketWriter(socket) << quint32(DaemonMessages::Capabilities) << quint32(daemonApp->powerManager()->capabilities());

                    // send host name
                    SocketWriter(socket) << quint32(DaemonMessages::HostName) << daemonApp->hostName();

                    // emit signal
                    emit connected(socket);
                }
                break;
                case GreeterMessages::Login: {
                    // read username, pasword etc.
                    QString user, password;
                    Session session;
                    input >> user >> password >> session;
                    if (!input.commitTransaction())
                        return;

                    // log message
                    qDebug() << "Message received from greeter: Login";

                    // emit signal
                    emit login(socket, user, password, session);
                }
                break;
                case GreeterMessages::Logout: {
                    // read session id
                    QString id;
                    input >> id;
                    if (!input.commitTransaction())
                        return;

                    // log message
                    qDebug() << "Message received from greeter: Logout";

                    // emit signal
                    emit logout(socket, id);
                }
                break;
                case GreeterMessages::Lock : {
                    QString id;
                    input >> id;
                    if (!input.commitTransaction())
                        return;

                    // log message
                    qDebug() << "Message received from greeter: Lock";

                    emit lock(socket, id);
                }
                break;
                case GreeterMessages::Unlock : {
                    QString user;
                    QString password;
                    input >> user >> password;
                    if (!input.commitTransaction())
                        return;

                    // log message
                    qDebug() << "Message received from greeter: Unlock";

                    emit unlock(socket, user, password);
                }
                break;
                case GreeterMessages::PowerOff: {
                    if (!input.commitTransaction())
                        return;

                    // log message
                    qDebug() << "Message received from greeter: PowerOff";

                    // power off
                    daemonApp->powerManager()->powerOff();
                }
                break;
                case GreeterMessages::Reboot: {
                    if (!input.commitTransaction())
                        return;

                    // log message
                    qDebug() << "Message received from greeter: Reboot";

                    // reboot
                    daemonApp->powerManager()->reboot();
                }
                break;
                case GreeterMessages::Suspend: {
                    if (!input.commitTransaction())
                        return;

                    // log message
                    qDebug() << "Message received from greeter: Suspend";

                    // suspend
                    daemonApp->powerManager()->suspend();
                }
                break;
                case GreeterMessages::Hibernate: {
                    if (!input.commitTransaction())
                        return;

                    // log message
                    qDebug() << "Message received from greeter: Hibernate";

                    // hibernate
                    daemonApp->powerManager()->hibernate();
                }
                break;
                case GreeterMessages::HybridSleep: {
                    if (!input.commitTransaction())
                        return;

                    // log message
                    qDebug() << "Message received from greeter: HybridSleep";

                    // hybrid sleep
                    daemonApp->powerManager()->hybridSleep();
                }
                break;
                case GreeterMessages::BackToNormal: {
                    if (!input.commitTransaction())
                        return;

                    // log message
                    qDebug() << "Message received from greeter: Back to normal";

                    // back to normal
                    daemonApp->backToNormal();
                }
                break;
                default: {
                    // Unknown message type: its payload length is unknown, so
                    // it cannot be framed safely. Consume the header and stop
                    // to avoid treating trailing bytes as a new message header.
                    input.commitTransaction();
                    qWarning() << "Unknown message" << message;
                    return;
                }
            }
        }

    }

    void SocketServer::loginFailed(QLocalSocket *socket, const QString &user) {
        SocketWriter(socket) << quint32(DaemonMessages::LoginFailed) << user;
    }

    void SocketServer::informationMessage(QLocalSocket *socket, const QString &message) {
        SocketWriter(socket) << quint32(DaemonMessages::InformationMessage) << message;
    }
}
