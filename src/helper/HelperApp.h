// Copyright (C) 2026 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef DDM_HELPERAPP_H
#define DDM_HELPERAPP_H

#include "Display.h"

#include <QCoreApplication>
#include <QProcess>
#include <QProcessEnvironment>

#include <security/pam_appl.h>

namespace DDM {
    class UserSession;

    /**
     * Session helper run in a clean, single-threaded process.
     *
     * The daemon spawns this binary with fork()+exec() and communicates over an
     * inherited socketpair file descriptor (passed as argv[1]). The helper is a
     * long-running QCoreApplication that services two commands:
     *
     *   - authenticate(user, pamService, secret): full PAM authentication
     *   - openSession(env, cookie, display, tty, type, command, sessionCommand,
     *     sessionLogFile, namespaces): PAM session + start the user's desktop
     *     session
     *
     * Running the whole PAM transaction (authenticate + open_session) here is
     * what makes ddm immune to the fork()-in-a-multithreaded-Qt-process
     * deadlock: gnome-keyring's PAM module forks inside pam_open_session() and
     * calls exit() in the grandchild, which would otherwise trigger Qt's
     * inherited atexit handlers and deadlock on QThread::wait(). Since this
     * helper is exec()'d and never opens a DBus connection, it is
     * single-threaded and safe. Everything a session needs is part of the
     * request, so the helper reads no configuration of its own: creating a
     * DConfig object would start a thread and open a DBus connection again.
     */
    class HelperApp : public QCoreApplication {
        Q_OBJECT
    public:
        HelperApp(int &argc, char **argv);
        ~HelperApp() override;

        enum Result {
            Success = 0,
            InternalError = 1,
            AuthError = 2,
            SessionError = 3,
        };

        // Protocol message opcodes.
        enum Msg : quint32 {
            Authenticate = 1,
            OpenSession = 2,
            AuthResult = 3,
            SessionResult = 4,
            SessionFinished = 5,
        };

    private:
        void onReadyRead();

        void handleAuthenticate(QDataStream &in);
        void handleOpenSession(QDataStream &in);

        bool doAuthenticate(const QString &user, const QString &pamService, const QByteArray &secret);
        bool doOpenSession(const QProcessEnvironment &env, QProcessEnvironment &envOut);

        static int converse(int num_msg,
                            const struct pam_message **msg,
                            struct pam_response **resp,
                            void *secret_ptr);

        void sendMsg(quint32 op, const QByteArray &payload = QByteArray());

        void onSessionFinished(int exitCode, QProcess::ExitStatus status);

        /** Close the PAM session (if open) and end the handle. Idempotent. */
        void closePamSession();

        /** Write utmp/wtmp/btmp records when a user logs in. */
        void utmpLogin(bool success);

        /** Write utmp/wtmp records when a user logs out. */
        void utmpLogout();

        // PAM conversation state (per authenticate transaction).
        QByteArray m_secret;
        // Stable pointer into m_secret. The PAM conversation callback's appdata
        // is &m_secretPtr, so it must outlive m_pamHandle and must not dangle
        // after doAuthenticate() returns.
        const char *m_secretPtr { nullptr };
        pam_handle *m_pamHandle { nullptr };
        // True once pam_open_session() succeeded and the session must be closed.
        bool m_sessionOpened { false };

        // Session parameters (set by the latest authenticate/openSession).
        QString m_user;
        QString m_display;
        int m_tty { 0 };
        Display::DisplayServerType m_type { Display::X11 };
        QString m_command;
        QByteArray m_cookie;

        UserSession *m_session { nullptr };

        // Session process PID (cached for utmp logout after the process ends).
        qint64 m_sessionPid { 0 };
        // True once a session was started and a login record was written.
        bool m_sessionStarted { false };

        int m_socketFd { -1 };
        QByteArray m_recvBuffer;
    };
} // namespace DDM

#endif // DDM_HELPERAPP_H
