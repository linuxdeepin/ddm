/*
 * Session process wrapper
 * Copyright (C) 2015 Pier Luigi Fiorini <pierluigi.fiorini@gmail.com>
 * Copyright (C) 2014 Martin Bříza <mbriza@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#ifndef DDM_AUTH_SESSION_H
#define DDM_AUTH_SESSION_H

#include <QtCore/QObject>
#include <QtCore/QProcess>
#include <QtCore/QTemporaryFile>

#include "Display.h"

namespace DDM {
    class Auth;
    class XOrgUserHelper;
    class WaylandHelper;
    class UserSession : public QProcess
    {
        Q_OBJECT
    public:
        explicit UserSession(Auth *parent);

        void start(const QString &command,
                   Display::DisplayServerType type,
                   const QByteArray &cookie = QByteArray());
        void stop();

        /**
         * Needed for getting the PID of a finished UserSession and calling HelperApp::utmpLogout
         */
        qint64 cachedProcessId = -1;

    private:
        // Don't call it directly, it will be invoked by the child process only
        void childModifier();

        QTemporaryFile m_xauthFile;
    };
}

#endif // DDM_AUTH_SESSION_H
