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

#ifndef DDM_DISPLAY_H
#define DDM_DISPLAY_H

#include <QObject>
#include <QPointer>
#include <QDir>

#include "Session.h"

class QLocalSocket;

namespace DDM {
    class Auth;
    class XorgDisplayServer;
    class TreelandDisplayServer;
    class Seat;
    class SocketServer;

    class Display : public QObject {
        Q_OBJECT
        Q_DISABLE_COPY(Display)
    public:
        enum DisplayServerType {
            X11,
            Wayland,
            Treeland
        };
        Q_ENUM(DisplayServerType)

        explicit Display(Seat *parent);
        ~Display();

        void switchToUser(const QString &user, int xdgSessionId);

        Seat *seat{ nullptr };
        int terminalId = 0;

    public slots:
        bool start();
        void stop();

        void connected(QLocalSocket *socket);
        void login(QLocalSocket *socket,
                   const QString &user, const QString &password,
                   const Session &session);
        void logout(QLocalSocket *socket,
                    int id);
        void unlock(QLocalSocket *socket,
                   const QString &user, const QString &password);

    signals:
        void stopped();

        void loginFailed(QLocalSocket *socket, const QString &user);
        void loginSucceeded(QLocalSocket *socket, const QString &user);

    private:
        void startAuth(const QString &user, const QString &password,
                       const Session &session);
        void startIdentify(const QString &user, const QString &password);

        bool m_started{ false };
        QVector<Auth*> m_auths;
        TreelandDisplayServer *m_treeland{ nullptr };
        XorgDisplayServer *m_x11Server{ nullptr };
        SocketServer *m_socketServer { nullptr };
        QPointer<QLocalSocket> m_socket;

    private slots:
        void userProcessFinished(int status);
    };
}

#endif // DDM_DISPLAY_H
