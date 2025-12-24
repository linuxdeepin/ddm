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
    class SeatManager;
    class SocketServer;

    /** Class represents a display (seat) */
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

        /**
         * Constructor
         *
         * @param parent The SeatManager
         * @param name Seat name
         */
        explicit Display(SeatManager *parent, QString name);

        ~Display();

        /**
         * Tell Treeland to activate a certain session.
         *
         * Called with user = "dde" and xdgSessionId <= 0
         * will send Treeland into lockscreen.
         *
         * @param user Username
         * @param xdgSessionId Logind session ID
         */
        void activateSession(const QString &user, int xdgSessionId);

        /** Seat name */
        QString name{};

        /** VT number of the greeter */
        int terminalId{ 0 };

        /** List of active authentications */
        QList<Auth *> auths;

    public slots:
        /**
         * Start the display.
         * This will start Treeland and show greeter.
         *
         * @return true on success, false on failure
         */
        bool start();

        /**
         * Stop the display.
         * Will be called automatically when destructed.
         */
        void stop();

        ///////////////////////////////////////////////////
        // Slots for socket to communicate with Treeland //
        ///////////////////////////////////////////////////

        void connected(QLocalSocket *socket);
        void login(QLocalSocket *socket,
                   const QString &user, const QString &password,
                   const Session &session);
        void logout(QLocalSocket *socket,
                    int id);
        void unlock(QLocalSocket *socket,
                   const QString &user, const QString &password);

    signals:
        /** Emitted when stop() */
        void stopped();

        /////////////////////////////////////////////////////
        // Signals for socket to communicate with Treeland //
        /////////////////////////////////////////////////////
        
        void loginFailed(QLocalSocket *socket, const QString &user);
        void loginSucceeded(QLocalSocket *socket, const QString &user);

    private:
        /** Indicates whether the display is started */
        bool m_started{ false };

        /** Treeland display server */
        TreelandDisplayServer *m_treeland{ nullptr };

        /** X11 display server, if started */
        XorgDisplayServer *m_x11Server{ nullptr };

        /** Socket server for communication with Treeland */
        SocketServer *m_socketServer { nullptr };

    private slots:
        void userProcessFinished(int status);
    };
}

#endif // DDM_DISPLAY_H
