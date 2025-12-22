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

    class Auth : public QObject {
        Q_OBJECT
    public:
        Auth(QObject *parent);
        ~Auth();

        bool active{ false };
        QString user{};
        QByteArray cookie{};
        bool singleMode{ false };
        bool skipAuth{ false };
        
        int id{ 0 };
        static int lastId;
        QString sessionId{};
        QString display{};
        int tty{ 0 };
        int xdgSessionId{ 0 };
    public Q_SLOTS:
        /**
        * Sets up the environment and starts the authentication
        */
        bool authenticate(const QByteArray &secret);

        int openSession(const QProcessEnvironment &env);

        void startUserProcess(const QString &command,
                              Display::DisplayServerType type,
                              const QByteArray &cookie = QByteArray());

        /**
         * Indicates that we do not need the process anymore.
         */
        void stop();

    Q_SIGNALS:
        /**
         * Emitted when the session ends.
         *
         * @param success true if every underlying task went fine
         */
        void userProcessFinished(int status);

    private:
        Pam *m_pam { nullptr };
        UserSession *m_session{ nullptr };
        QProcessEnvironment m_env{};

        /**
         * Write utmp/wtmp/btmp records when a user logs in
         * @param vt  Virtual terminal (tty7, tty8,...)
         * @param displayName  Display (:0, :1,...)
         * @param user  User logging in
         * @param pid  User process ID (e.g. PID of startkde)
         * @param authSuccessful  Was authentication successful
         */
        void utmpLogin(const QString &vt, const QString &displayName, const QString &user, qint64 pid, bool authSuccessful);

        /**
         * Write utmp/wtmp records when a user logs out
         * @param vt  Virtual terminal (tty7, tty8,...)
         * @param displayName  Display (:0, :1,...)
         * @param pid  User process ID (e.g. PID of startkde)
        */
        void utmpLogout(const QString &vt, const QString &displayName, qint64 pid);
    };
}

#endif // DDM_AUTH_H
