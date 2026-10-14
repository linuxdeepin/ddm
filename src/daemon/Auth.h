// Copyright (C) 2026 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef DDM_AUTH_H
#define DDM_AUTH_H

#include "Display.h"

#include <QObject>
#include <QProcess>
#include <QProcessEnvironment>

namespace DDM {
    class AuthPrivate;
    class UserSession;

    /** Authentication handler, manage login and session */
    class Auth : public QObject {
        Q_OBJECT
    public:
        Auth(QObject *parent, QString user);
        ~Auth();

        /** Indicates whether authenticated (authenticate() is called and succeed) */
        bool authenticated{ false };

        /** Indicates whether a session is opened with this handle */
        bool sessionOpened{ false };

        /** Username. Must be set before authenticate() */
        QString user{};

        /** PAM service to use for authentication (defaults to "ddm"). Use
         *  "ddm-autologin" to authenticate without a password. */
        QString pamService{ QStringLiteral("ddm") };

        /** Display sever type of the session. Must be set before startUserProcess() */
        Display::DisplayServerType type{};

        /** The "Session ID" (defined and used by DisplayManager) */
        QString sessionId{};

        /** X Display identifier (e.g. :0), if presents */
        QString display{};

        /** Virtual terminal number (e.g. 7 for tty7) */
        int tty{ 0 };

        /** Logind session ID (the XDG_SESSION_ID env var). Empty means no session */
        QString xdgSessionId{};

        /** PID of the session process started by session helper. Positive values are valid */
        qint64 sessionPid{ 0 };

    public Q_SLOTS:
        /**
         * Sets up the environment and starts the authentication.
         *
         * @param secret Password or other secret data acceptable by PAM
         * @return true on success, false on failure
         */
        bool authenticate(const QByteArray &secret);

        /**
         * Starts user process, opens Logind session and returns the
         * XDG_SESSION_ID. Must be called after authenticate().
         *
         * @param command Command to execute as user process
         * @param env Environment variables to set for the session
         * @param cookie XAuth cookie, must be provided if type=X11
         * @return A valid XDG_SESSION_ID on success, empty string on failure
         */
        QString openSession(const QString &command,
                            QProcessEnvironment env,
                            const QByteArray &cookie = QByteArray());

        /**
         * Close PAM session
         * @return true on success, false on failure
         */
        bool closeSession();

    Q_SIGNALS:
        /**
         * Emitted when the session process ends.
         */
        void sessionFinished();

    private:
        /** Ensure the session helper is spawned and connected. */
        bool ensureHelper();

        /** Send a framed request to the helper and read one framed reply. */
        bool sendRequest(quint32 op, const QByteArray &payload, QByteArray &reply);

        /** Handle helper process exit (session finished). */
        void onHelperFinished(int exitCode, QProcess::ExitStatus status);

        AuthPrivate *d{ nullptr };
    };
}

#endif // DDM_AUTH_H
