// Copyright (C) 2026 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#include "Auth.h"

#include "UserSession.h"

#include "Login1Manager.h"
#include "Login1Session.h"
#include "VirtualTerminal.h"

#include <pwd.h>
#include <security/pam_appl.h>
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
        entry.ut_pid = sessionProcessId;

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
        entry.ut_pid = sessionProcessId;

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
        , m_session(new UserSession(this))
        , d(new AuthPrivate(this)) {
        connect(m_session,
                QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                this,
                &Auth::userProcessFinished);
    }

    Auth::~Auth() {
        if (m_session->state() != QProcess::NotRunning)
            m_session->stop();
        if (sessionOpened) {
            closeSession();
            utmpLogout();
        }
        if (d->handle) {
            d->ret = pam_end(d->handle, d->ret);
            if (d->ret != PAM_SUCCESS)
                qWarning() << "[Auth] end:" << pam_strerror(d->handle, d->ret);
        }
        qDebug() << "[Auth] Auth for user" << user << "ended.";
    }

#define CHECK_RET_AUTH                                                           \
    if (d->ret != PAM_SUCCESS) {                                                 \
        qWarning() << "[Auth] Authenticate:" << pam_strerror(d->handle, d->ret); \
        utmpLogin(false);                                                        \
        return false;                                                            \
    }
    bool Auth::authenticate(const QByteArray &secret) {
        Q_ASSERT(!user.isEmpty());

        qDebug() << "[Auth] Starting...";
        d->ret = pam_start("ddm", user.toLocal8Bit().constData(), &d->conv, &d->handle);
        CHECK_RET_AUTH

        qDebug() << "[Auth] Authenticating user" << user;

        // Set the secret, authenticate, then clear the secret
        // immediately to avoid leak
        *d->secretPtr = secret.constData();
        d->ret = pam_authenticate(d->handle, 0);
        *d->secretPtr = nullptr;

        CHECK_RET_AUTH
        qDebug() << "[Auth] Authenticated.";

        d->ret = pam_acct_mgmt(d->handle, 0);
        CHECK_RET_AUTH

        authenticated = true;
        return true;
    }

    int Auth::openSession(const QString &command,
                          QProcessEnvironment env,
                          const QByteArray &cookie) {
        Q_ASSERT(authenticated);
        // Insert necessary environment
        struct passwd *pw = getpwnam(qPrintable(user));
        if (pw) {
            env.insert(QStringLiteral("HOME"), QString::fromLocal8Bit(pw->pw_dir));
            env.insert(QStringLiteral("PWD"), QString::fromLocal8Bit(pw->pw_dir));
            env.insert(QStringLiteral("SHELL"), QString::fromLocal8Bit(pw->pw_shell));
            env.insert(QStringLiteral("USER"), QString::fromLocal8Bit(pw->pw_name));
            env.insert(QStringLiteral("LOGNAME"), QString::fromLocal8Bit(pw->pw_name));
        }
        m_session->setProcessEnvironment(env);

        // RUN!!!
        m_session->start(command, type, cookie);
        if (!m_session->waitForStarted()) {
            qWarning() << "[Auth] Failed to start user process.";
            return -1;
        }
        sessionOpened = true;

        // cache pid for session end
        sessionProcessId = m_session->processId();
        // write successful login to utmp/wtmp
        utmpLogin(true);
        // Get XDG_SESSION_ID via Logind
        OrgFreedesktopLogin1ManagerInterface manager(Logind::serviceName(),
                                                     Logind::managerPath(),
                                                     QDBusConnection::systemBus());
        auto reply = manager.GetSessionByPID(static_cast<uint>(sessionProcessId));
        reply.waitForFinished();
        if (reply.error().isValid()) {
            qWarning() << "[Auth] GetSessionByPID:" << reply.error().message();
            return -1;
        }
        QDBusObjectPath path = reply.value();
        OrgFreedesktopLogin1SessionInterface session(Logind::serviceName(),
                                                     path.path(),
                                                     QDBusConnection::systemBus());
        bool ok;
        xdgSessionId = session.property("Id").toInt(&ok);
        if (!ok) {
            qWarning() << "[Auth] Failed to get XDG_SESSION_ID for user" << user;
            return -1;
        }
        qDebug() << "[Auth] Session opened with XDG_SESSION_ID =" << xdgSessionId;
        return xdgSessionId;
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
        qDebug() << "[Auth] Closing session for user" << user;

        d->ret = pam_close_session(d->handle, 0);
        CHECK_RET_CLOSE

        sessionOpened = false;
        d->ret = pam_setcred(d->handle, PAM_DELETE_CRED);
        CHECK_RET_CLOSE

        qDebug() << "[Auth] Session closed.";
        return true;
    }

#define CHECK_RET_OPEN                                                                  \
    if (d->ret != PAM_SUCCESS) {                                                        \
        qWarning() << "[Auth] openSessionInternal:" << pam_strerror(d->handle, d->ret); \
        return nullptr;                                                                 \
    }
    char **Auth::openSessionInternal(const QProcessEnvironment &sessionEnv) {
        qDebug() << "[Auth] Opening session for user" << user;

        d->ret = pam_setcred(d->handle, PAM_ESTABLISH_CRED);
        CHECK_RET_OPEN

        // Set PAM_TTY
        QString tty = VirtualTerminal::path(sessionEnv.value(QStringLiteral("XDG_VTNR")).toInt());
        d->ret = pam_set_item(d->handle, PAM_TTY, qPrintable(tty));
        CHECK_RET_OPEN

        // Set PAM_XDISPLAY
        QString display = sessionEnv.value(QStringLiteral("DISPLAY"));
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

        qDebug() << "[Auth] Session opened.";

        return pam_getenvlist(d->handle);
    }
} // namespace DDM

#include "Auth.moc"
