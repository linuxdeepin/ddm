// Copyright (C) 2026 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#include "Auth.h"

#include "UserSession.h"

#include "DaemonApp.h"
#include "Login1Manager.h"
#include "Login1Session.h"
#include "SignalHandler.h"
#include "VirtualTerminal.h"

#include <pwd.h>
#include <security/pam_appl.h>
#include <signal.h>
#include <unistd.h>
#include <utmp.h>
#include <utmpx.h>

namespace DDM {

    ///////////////////////////
    // utmp helper functions //
    ///////////////////////////

    void Auth::utmpLogin(bool success) {
        struct utmpx entry { };
        struct timeval tv;

        entry.ut_type = USER_PROCESS;
        entry.ut_pid = sessionPid;

        // ut_line: vt
        if (tty > 0)
            strncpy(entry.ut_line, QStringLiteral("tty%1").arg(tty).toLocal8Bit().constData(), sizeof(entry.ut_line) - 1);

        // ut_host: displayName
        if (!display.isEmpty())
            strncpy(entry.ut_host, display.toLocal8Bit().constData(), sizeof(entry.ut_host) - 1);

        // ut_user: user
        strncpy(entry.ut_user, user.toLocal8Bit().constData(), sizeof(entry.ut_user) -1);

        gettimeofday(&tv, NULL);
        entry.ut_tv.tv_sec = tv.tv_sec;
        entry.ut_tv.tv_usec = tv.tv_usec;

        // write to utmp
        setutxent();
        if (!pututxline (&entry))
            qWarning() << "Failed to write utmpx: " << strerror(errno);
        endutxent();

        // append to failed login database btmp
        if (!success) {
            updwtmpx("/var/log/btmp", &entry);
        } else {
            // append to wtmp
            updwtmpx("/var/log/wtmp", &entry);
        }
    }

    void Auth::utmpLogout() {
        struct utmpx entry { };
        struct timeval tv;

        entry.ut_type = DEAD_PROCESS;
        entry.ut_pid = sessionPid;

        // ut_line: vt
        if (tty > 0)
            strncpy(entry.ut_line, QStringLiteral("tty%1").arg(tty).toLocal8Bit().constData(), sizeof(entry.ut_line) - 1);

        // ut_host: displayName
        if (!display.isEmpty())
            strncpy(entry.ut_host, display.toLocal8Bit().constData(), sizeof(entry.ut_host) - 1);

        gettimeofday(&tv, NULL);
        entry.ut_tv.tv_sec = tv.tv_sec;
        entry.ut_tv.tv_usec = tv.tv_usec;

        // write to utmp
        setutxent();
        if (!pututxline (&entry))
            qWarning() << "Failed to write utmpx: " << strerror(errno);
        endutxent();

        // append to wtmp
        updwtmpx("/var/log/wtmp", &entry);
    }

    ///////////////////////////////
    // PAM conversation function //
    ///////////////////////////////

    /** PAM conversation function */
    static int converse(int num_msg,
                        const struct pam_message **msg,
                        struct pam_response **resp,
                        void *secret_ptr) {
        *resp = (struct pam_response *) calloc(num_msg, sizeof(struct pam_response));
        if (!*resp)
            return PAM_BUF_ERR;

        // We only handle secret (password) sending here, which is
        // prompt by PAM_PROMPT_ECHO_OFF.  Message types (error/info)
        // are just logged.
        //
        // Prompts with PAM_PROMPT_ECHO_ON (most likely asking for
        // username) are not expected, since we required username is
        // set before.
        for (int i = 0; i < num_msg; ++i) {
            switch (msg[i]->msg_style) {
            case PAM_PROMPT_ECHO_OFF:
                resp[i]->resp = strdup(*static_cast<const char **>(secret_ptr));
                resp[i]->resp_retcode = 0;
                break;
            case PAM_ERROR_MSG:
                qWarning() << "[Converse] Error message:" << msg[i]->msg;
                resp[i]->resp = nullptr;
                resp[i]->resp_retcode = 0;
                break;
            case PAM_TEXT_INFO:
                qInfo() << "[Converse] Info message:" << msg[i]->msg;
                resp[i]->resp = nullptr;
                resp[i]->resp_retcode = 0;
                break;
            default:
                qCritical("[Converse] Unsupported message style %d: %s", msg[i]->msg_style, msg[i]->msg);
                for (int j = 0; j < i; j++) {
                    free(resp[j]->resp);
                    resp[j]->resp = nullptr;
                }
                free(*resp);
                *resp = nullptr;
                return PAM_CONV_ERR;
            }
        }
        return PAM_SUCCESS;
    }

    /////////////////////////
    // Auth implementation //
    /////////////////////////

    class AuthPrivate : public QObject {
        Q_OBJECT
    public:
        AuthPrivate(Auth *parent)
            : QObject(parent)
            , secretPtr(new const char *)
            , conv({ converse, static_cast<void *>(secretPtr) }) {
            *secretPtr = nullptr;
        }

        ~AuthPrivate() {
            delete secretPtr;
        }

        pam_handle_t *handle{ nullptr };
        const char **secretPtr{};
        pam_conv conv{};
        int ret{};
    };

    Auth::Auth(QObject *parent, QString user)
        : QObject(parent)
        , user(user)
        , d(new AuthPrivate(this)) {}

    Auth::~Auth() {
        if (sessionOpened) {
            delete m_notifier;
            if (sessionPid > 0)
                kill(sessionPid, SIGTERM);
            if (sessionLeaderPid > 0)
                kill(sessionLeaderPid, SIGTERM);
            closeSession();
            utmpLogout();
        }
        if (d->handle) {
            d->ret = pam_end(d->handle, d->ret);
            if (d->ret != PAM_SUCCESS)
                qWarning() << "[Auth] PAM handle end with error!";
        }
        qInfo() << "[Auth] Auth for user" << user << "ended.";
    }

#define CHECK_RET_AUTH                                                           \
    if (d->ret != PAM_SUCCESS) {                                                 \
        qWarning() << "[Auth] Authenticate:" << pam_strerror(d->handle, d->ret); \
        utmpLogin(false);                                                        \
        return false;                                                            \
    }
    bool Auth::authenticate(const QByteArray &secret) {
        Q_ASSERT(!user.isEmpty());

        qInfo() << "[Auth] Starting...";
        d->ret = pam_start("ddm", user.toLocal8Bit().constData(), &d->conv, &d->handle);
        CHECK_RET_AUTH

        qInfo() << "[Auth] Authenticating user" << user;

        // Set the secret, authenticate, then clear the secret
        // immediately to avoid leak
        *d->secretPtr = secret.constData();
        d->ret = pam_authenticate(d->handle, 0);
        *d->secretPtr = nullptr;

        CHECK_RET_AUTH
        qInfo() << "[Auth] Authenticated.";

        d->ret = pam_acct_mgmt(d->handle, 0);
        CHECK_RET_AUTH

        authenticated = true;
        return true;
    }

    QString Auth::openSession(const QString &command,
                              QProcessEnvironment env,
                              const QByteArray &cookie) {
        Q_ASSERT(authenticated);

        int pipefd[2];
        if (pipe(pipefd) == -1) {
            qWarning() << "[Auth] pipe failed:" << strerror(errno);
            return {};
        }

        char xdgSessionId[128] = {};

        // Here is most safe place to jump VT
        VirtualTerminal::jumpToVt(tty, false, false);

        sessionLeaderPid = fork();
        switch (sessionLeaderPid) {
        case -1: {
            // Fork failed
            qWarning() << "[Auth] fork failed:" << strerror(errno);
            close(pipefd[0]);
            close(pipefd[1]);
            return {};
        }
        case 0: {
            // Child (session leader) process
            close(pipefd[0]);

            // Delete old signal handlers, in order to close old fds
            // which are shared with the parent process.
            delete daemonApp->signalHandler();

            // Restore default SIGINT and SIGTERM handlers. We need
            // the signal hander to terminate ourself, since we're
            // going to enter an infinite waiting loop and no one can
            // interrupt us after fork(), except the signal handler.
            signal(SIGINT, SIG_DFL);
            signal(SIGTERM, SIG_DFL);

            // Insert necessary environment
            struct passwd *pw = getpwnam(qPrintable(user));
            if (pw) {
                env.insert(QStringLiteral("HOME"), QString::fromLocal8Bit(pw->pw_dir));
                env.insert(QStringLiteral("PWD"), QString::fromLocal8Bit(pw->pw_dir));
                env.insert(QStringLiteral("SHELL"), QString::fromLocal8Bit(pw->pw_shell));
                env.insert(QStringLiteral("USER"), QString::fromLocal8Bit(pw->pw_name));
                env.insert(QStringLiteral("LOGNAME"), QString::fromLocal8Bit(pw->pw_name));
            }

            // Open session
            auto sessionEnv = openSessionInternal(env);
            if (!sessionEnv.has_value()) {
                qCritical() << "[SessionLeader] Failed to open session. Exit now.";
                exit(1);
            }
            env = *sessionEnv;

            // Retrieve XDG_SESSION_ID
            session = env.value(QStringLiteral("XDG_SESSION_ID"));
            QByteArray sessionBa = session.toLocal8Bit();
            strcpy(xdgSessionId, sessionBa.constData());
            if (write(pipefd[1], &xdgSessionId, sizeof(char) * 128) != sizeof(char) * 128) {
                qCritical() << "[SessionLeader] Failed to write XDG_SESSION_ID to parent process!";
                exit(1);
            }

            // RUN!!!
            UserSession desktop(this);
            desktop.setProcessEnvironment(env);
            desktop.start(command, type, cookie);
            if (!desktop.waitForStarted()) {
                qCritical() << "[SessionLeader] Failed to start session process. Exit now.";
                exit(1);
            }

            // Send session PID to parent
            sessionPid = desktop.processId();
            if (write(pipefd[1], &sessionPid, sizeof(qint64)) != sizeof(qint64)) {
                qCritical() << "[SessionLeader] Failed to write session PID to parent process!";
                exit(1);
            }
            qInfo() << "[SessionLeader] Session started with PID" << sessionPid;

            desktop.waitForFinished(-1);

            // Handle session end
            if (desktop.exitStatus() == QProcess::CrashExit) {
                qCritical() << "[SessionLeader] Session process crashed. Exit now.";
                exit(1);
            }
            qInfo() << "[SessionLeader] Session process finished with exit code"
                    << desktop.exitCode() << ". Exiting.";
            exit(desktop.exitCode());
        }
        default: {
            // Parent process
            close(pipefd[1]);

            if (read(pipefd[0], &xdgSessionId, sizeof(char) * 128) != sizeof(char) * 128) {
                qWarning() << "[Auth] Failed to read XDG_SESSION_ID from child process:" << strerror(errno);
                close(pipefd[0]);
                return {};
            }
            session = QString::fromLocal8Bit(xdgSessionId);

            if (read(pipefd[0], &sessionPid, sizeof(qint64)) < 0) {
                qWarning() << "[Auth] Failed to read session PID from child process:" << strerror(errno);
                close(pipefd[0]);
                return {};
            }
            utmpLogin(true);

            // Monitor child process ends
            m_notifier = new QSocketNotifier(pipefd[0], QSocketNotifier::Read);
            connect(m_notifier, &QSocketNotifier::activated, this, [this, pipefd] {
                close(pipefd[0]);
                m_notifier->setEnabled(false);
                m_notifier->deleteLater();
                Q_EMIT sessionFinished();
            });

            sessionOpened = true;
            return session;
        }
        }
    }

#define CHECK_RET_CLOSE                                                          \
    if (d->ret != PAM_SUCCESS) {                                                 \
        qWarning() << "[Auth] closeSession:" << pam_strerror(d->handle, d->ret); \
        return false;                                                            \
    }
    bool Auth::closeSession() {
        if (!sessionOpened) {
            qWarning() << "[Auth] closeSession: Session was not opened.";
            return true;
        }
        qWarning() << "[Auth] Closing session for user" << user;

        d->ret = pam_close_session(d->handle, 0);
        CHECK_RET_CLOSE

        sessionOpened = false;
        d->ret = pam_setcred(d->handle, PAM_DELETE_CRED);
        CHECK_RET_CLOSE

        qInfo() << "[Auth] Session closed.";
        return true;
    }

#define CHECK_RET_OPEN                                                                  \
    if (d->ret != PAM_SUCCESS) {                                                        \
        qWarning() << "[Auth] openSessionInternal:" << pam_strerror(d->handle, d->ret); \
        return std::nullopt;                                                            \
    }
    std::optional<QProcessEnvironment> Auth::openSessionInternal(const QProcessEnvironment &sessionEnv) {
        qInfo() << "[Auth] Opening session for user" << user;

        d->ret = pam_setcred(d->handle, PAM_ESTABLISH_CRED);
        CHECK_RET_OPEN

        // Set PAM_TTY
        QString vtPath = VirtualTerminal::path(tty);
        d->ret = pam_set_item(d->handle, PAM_TTY, qPrintable(vtPath));
        CHECK_RET_OPEN

        // Set PAM_XDISPLAY
        if (!display.isEmpty()) {
            d->ret = pam_set_item(d->handle, PAM_XDISPLAY, qPrintable(display));
            CHECK_RET_OPEN
        }

        // Insert environments into new session
        QStringList envStrs = sessionEnv.toStringList();
        for (const QString &s : std::as_const(envStrs)) {
            d->ret = pam_putenv(d->handle, qPrintable(s));
            CHECK_RET_OPEN
        }

        // OPEN!!!
        d->ret = pam_open_session(d->handle, 0);
        CHECK_RET_OPEN

        qInfo() << "[Auth] Session opened.";

        // Retrieve env vars in new session
        QProcessEnvironment env;
        char **envlist = pam_getenvlist(d->handle);
        if (envlist) {
            for (int i = 0; envlist[i] != nullptr; ++i) {
                QString str = QString::fromLocal8Bit(envlist[i]);
                int equalPos = str.indexOf('=');
                if (equalPos != -1)
                    env.insert(str.left(equalPos), str.mid(equalPos + 1));
                free(envlist[i]);
            }
            free(envlist);
        }
        return env;
    }
} // namespace DDM

#include "Auth.moc"
