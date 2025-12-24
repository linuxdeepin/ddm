/*
 * Qt Authentication library
 * Copyright (C) 2013 Martin Bříza <mbriza@redhat.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 *
 */

#ifndef DDM_AUTH_H
#define DDM_AUTH_H

#include "Display.h"

#include <QtCore/QObject>
#include <QtCore/QProcessEnvironment>

namespace DDM {
    class Pam;
    class UserSession;

    /** Authentication handler, manage login and session */
    class Auth : public QObject {
        Q_OBJECT
    public:
        Auth(QObject *parent, QString user);
        ~Auth();

        /** Indicates whether the Auth is active (PAM module started) */
        bool active{ false };

        /** Username. Must be set before authenticate() */
        QString user{};

        /** Display sever type of the session. Must be set before startUserProcess() */
        Display::DisplayServerType type{};

        /** The "Session ID" (defined and used by DisplayManager) */
        QString sessionId{};

        /** X Display identifier (e.g. :0), if presents */
        QString display{};

        /** Virtual terminal number (e.g. 7 for tty7) */
        int tty{ 0 };

        /** Logind session ID (the XDG_SESSION_ID env var) */
        int xdgSessionId{ 0 };

    public Q_SLOTS:
        /**
         * Sets up the environment and starts the authentication.
         *
         * @param secret Password or other secret data acceptable by PAM
         * @return true on success, false on failure
         */
        bool authenticate(const QByteArray &secret);

        /**
         * Opens user session via PAM and returns the XDG_SESSION_ID.
         * Must be called after authenticate().
         *
         * @param env Environment variables to set for the session
         * @return XDG_SESSION_ID on success, -1 on failure
         */
        int openSession(const QProcessEnvironment &env);

        /**
         * Starts process inside opened session.
         * Must be called after openSession().
         * Only 1 process can be started per Auth instance,
         * userProcessFinished() is emitted when the process ends.
         * Implemented in UserSession.
         *
         * @param command Command to exec
         * @param cookie XAuth cookie (must be set for X11)
         */
        void startUserProcess(const QString &command, const QByteArray &cookie = QByteArray());

        /**
         * Stop PAM, close opened session and end up user process.
         * This will be automatically called in the destructor.
         */
        void stop();

    Q_SIGNALS:
        /**
         * Emitted when the user process ends.
         *
         * @param status Exit code of the user process
         */
        void userProcessFinished(int status);

    private:
        /** The PAM module */
        Pam *m_pam{ nullptr };

        /** The user process */
        UserSession *m_session{ nullptr };

        /** Cached environment inside the opened logind session, for the user process */
        QProcessEnvironment m_env{};
    };
}

#endif // DDM_AUTH_H
