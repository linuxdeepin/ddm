// Copyright (C) 2026 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#include "HelperApp.h"

#include "Configuration.h"
#include "SignalHandler.h"
#include "TtyUtils.h"
#include "UserSession.h"

#include <pwd.h>
#include <security/pam_appl.h>
#include <unistd.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <utmp.h>
#include <utmpx.h>

#include <QDataStream>
#include <QDebug>
#include <QProcess>
#include <QSocketNotifier>

namespace DDM {

    namespace {
        // Each frame: [quint32 payloadLen][payload]. Length excludes the header.
        constexpr int kHeaderSize = sizeof(quint32);
        constexpr quint32 kMaxFrameSize = 1 << 20; // 1 MiB guard

        bool writeAll(int fd, const void *buf, size_t len)
        {
            const char *p = static_cast<const char *>(buf);
            size_t off = 0;
            while (off < len) {
                // MSG_NOSIGNAL: the peer (daemon) may already have closed the
                // channel, so write() must return EPIPE instead of SIGPIPE.
                const ssize_t w = ::send(fd, p + off, len - off, MSG_NOSIGNAL);
                if (w < 0) {
                    if (errno == EINTR)
                        continue;
                    return false;
                }
                if (w == 0)
                    return false;
                off += static_cast<size_t>(w);
            }
            return true;
        }
    }

    HelperApp::HelperApp(int &argc, char **argv)
        : QCoreApplication(argc, argv)
    {
        // argv: ddm-helper <socketFd>
        if (argc < 2) {
            qCritical() << "[Helper] This application is not supposed to be executed manually";
            ::exit(InternalError);
        }
        bool ok = false;
        m_socketFd = QString::fromLocal8Bit(argv[1]).toInt(&ok);
        if (!ok || m_socketFd < 0) {
            qCritical() << "[Helper] invalid socket fd";
            ::exit(InternalError);
        }

        // The socket must be non-blocking: QSocketNotifier fires only when
        // data is available, and onReadyRead() must never block on a second
        // read() after draining the available bytes, or the daemon (blocked
        // in sendRequest()) and this helper would deadlock each other.
        ::fcntl(m_socketFd, F_SETFL, ::fcntl(m_socketFd, F_GETFL, 0) | O_NONBLOCK);

        auto *notifier = new QSocketNotifier(m_socketFd, QSocketNotifier::Read, this);
        connect(notifier, &QSocketNotifier::activated, this, &HelperApp::onReadyRead);

        // SIGTERM (sent by Auth::closeSession()/terminate()) must exit the
        // event loop gracefully so ~HelperApp() runs the PAM teardown, rather
        // than the default action of killing the process immediately.
        auto *signalHandler = new SignalHandler(this);
        connect(signalHandler, &SignalHandler::sigtermReceived, this, [] {
            QCoreApplication::instance()->exit(0);
        });

        qInfo() << "[Helper] started, socket fd" << m_socketFd;
    }

    HelperApp::~HelperApp()
    {
        // Stop the desktop process, then run PAM teardown (pam_close_session /
        // PAM_DELETE_CRED / pam_end). This is the single cleanup path shared by
        // every exit route: normal session end, SIGTERM from the daemon, or a
        // failed openSession.
        if (m_session) {
            m_session->stop();
            m_session->deleteLater();
        }
        closePamSession();

        // Write the logout record (utmp/wtmp), mirroring SDDM's ~HelperApp().
        utmpLogout();
    }

    void HelperApp::sendMsg(quint32 op, const QByteArray &payload)
    {
        QByteArray frame;
        {
            QDataStream ds(&frame, QIODevice::WriteOnly);
            ds << static_cast<quint32>(payload.size() + sizeof(quint32));
            ds << op;
            if (!payload.isEmpty())
                ds.writeRawData(payload.constData(), payload.size());
        }
        if (!writeAll(m_socketFd, frame.constData(), frame.size()))
            qCritical() << "[Helper] failed to write reply";
    }

    void HelperApp::onReadyRead()
    {
        // Drain available bytes into the buffer, then try to parse complete
        // frames. Keep any partial frame for the next activation.
        char chunk[4096];
        for (;;) {
            const ssize_t r = ::read(m_socketFd, chunk, sizeof(chunk));
            if (r > 0) {
                m_recvBuffer.append(chunk, static_cast<int>(r));
                continue;
            }
            if (r == 0) {
                qInfo() << "[Helper] daemon closed the channel";
                QCoreApplication::exit(0);
                return;
            }
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            qCritical() << "[Helper] read error:" << strerror(errno);
            QCoreApplication::exit(InternalError);
            return;
        }

        while (m_recvBuffer.size() >= kHeaderSize) {
            // The frame header is written by the daemon with QDataStream
            // (big-endian), so read it the same way.
            quint32 len = 0;
            {
                QDataStream lenStream(m_recvBuffer);
                lenStream >> len;
            }
            if (len < sizeof(quint32) || len > kMaxFrameSize) {
                qCritical() << "[Helper] invalid frame length" << len;
                QCoreApplication::exit(InternalError);
                return;
            }
            if (m_recvBuffer.size() < static_cast<int>(len + kHeaderSize))
                break; // wait for the rest

            // len counts the op (4 bytes) + payload bytes that follow the
            // 4-byte length header.
            const QByteArray payload = m_recvBuffer.mid(kHeaderSize, len);
            m_recvBuffer.remove(0, static_cast<int>(len + kHeaderSize));

            QDataStream in(payload);
            quint32 op = 0;
            in >> op;
            switch (op) {
            case Authenticate:
                handleAuthenticate(in);
                break;
            case OpenSession:
                handleOpenSession(in);
                break;
            default:
                qCritical() << "[Helper] unknown opcode" << op;
                QCoreApplication::exit(InternalError);
                return;
            }
        }
    }

    void HelperApp::handleAuthenticate(QDataStream &in)
    {
        QString user, pamService;
        QByteArray secret;
        in >> user >> pamService >> secret;

        const bool ok = doAuthenticate(user, pamService, secret);
        if (!ok)
            utmpLogin(false);
        sendMsg(AuthResult, ok ? QByteArray("\x01", 1) : QByteArray("\x00", 1));
    }

    void HelperApp::handleOpenSession(QDataStream &in)
    {
        QStringList envList;
        QByteArray cookie;
        QString display;
        int tty = 0;
        int type = 0;
        QString command;
        in >> envList >> cookie >> display >> tty >> type >> command;

        QProcessEnvironment env;
        for (const QString &s : envList) {
            const int eq = s.indexOf('=');
            if (eq != -1)
                env.insert(s.left(eq), s.mid(eq + 1));
        }

        if (!m_pamHandle) {
            qCritical() << "[Helper] openSession requested but no authenticated handle";
            QByteArray payload;
            {
                QDataStream ds(&payload, QIODevice::WriteOnly);
                ds << static_cast<quint32>(SessionError);
            }
            sendMsg(SessionResult, payload);
            return;
        }

        // Insert user identity environment (HOME, USER, ...).
        struct passwd *pw = getpwnam(qPrintable(m_user));
        if (pw) {
            env.insert(QStringLiteral("HOME"), QString::fromLocal8Bit(pw->pw_dir));
            env.insert(QStringLiteral("PWD"), QString::fromLocal8Bit(pw->pw_dir));
            env.insert(QStringLiteral("SHELL"), QString::fromLocal8Bit(pw->pw_shell));
            env.insert(QStringLiteral("USER"), QString::fromLocal8Bit(pw->pw_name));
            env.insert(QStringLiteral("LOGNAME"), QString::fromLocal8Bit(pw->pw_name));
        }

        m_display = display;
        m_tty = tty;
        m_type = static_cast<Display::DisplayServerType>(type);
        m_command = command;
        m_cookie = cookie;

        QProcessEnvironment envOut;
        if (!doOpenSession(env, envOut)) {
            // doOpenSession() may fail after pam_setcred(PAM_ESTABLISH_CRED),
            // which leaves credentials established and the handle open. Clean
            // up here so the PAM teardown is not skipped (the helper keeps
            // running its event loop and would otherwise never reach it).
            closePamSession();
            QByteArray payload;
            {
                QDataStream ds(&payload, QIODevice::WriteOnly);
                ds << static_cast<quint32>(SessionError);
            }
            sendMsg(SessionResult, payload);
            return;
        }

        // Start the user's desktop session.
        // Validate the session id BEFORE starting the desktop process, so a
        // PAM stack that omits XDG_SESSION_ID cannot leave an orphaned desktop
        // process behind (the daemon rejects an empty id and deletes Auth).
        // Precedence: the original environment is the base; PAM-produced
        // variables (envOut) override same-named entries.
        QProcessEnvironment finalEnv = env;
        finalEnv.insert(envOut);
        const QString xdgSessionId = finalEnv.value(QStringLiteral("XDG_SESSION_ID"));
        if (xdgSessionId.isEmpty()) {
            qCritical() << "[Helper] PAM did not provide XDG_SESSION_ID";
            closePamSession();
            QByteArray payload;
            {
                QDataStream ds(&payload, QIODevice::WriteOnly);
                ds << static_cast<quint32>(SessionError);
            }
            sendMsg(SessionResult, payload);
            return;
        }

        m_session = new UserSession(this);
        m_session->setUser(m_user);
        m_session->setTty(m_tty);
        m_session->setProcessEnvironment(finalEnv);

        // Connect to UserSession's forwarded finished signal BEFORE starting
        // the process (the signal itself is wired from QProcess::finished in
        // the UserSession constructor, mirroring SDDM). A short-lived session
        // wrapper that exits between start() and waitForStarted() therefore
        // still delivers the signal.
        connect(m_session, &UserSession::finished, this, &HelperApp::onSessionFinished);

        m_session->start(m_command, m_type, m_cookie);

        if (!m_session->waitForStarted()) {
            qCritical() << "[Helper] failed to start session process";
            closePamSession();
            QByteArray payload;
            {
                QDataStream ds(&payload, QIODevice::WriteOnly);
                ds << static_cast<quint32>(SessionError);
            }
            sendMsg(SessionResult, payload);
            return;
        }

        const qint64 sessionPid = m_session->processId();
        m_sessionPid = sessionPid;
        m_sessionStarted = true;

        // Write the successful login record (utmp/wtmp), mirroring SDDM.
        utmpLogin(true);

        QByteArray payload;
        {
            QDataStream ds(&payload, QIODevice::WriteOnly);
            ds << static_cast<quint32>(Success) << xdgSessionId << sessionPid;
        }
        sendMsg(SessionResult, payload);
    }

    void HelperApp::closePamSession()
    {
        if (!m_pamHandle)
            return;

        if (m_sessionOpened) {
            pam_close_session(m_pamHandle, 0);
            m_sessionOpened = false;
        }
        pam_setcred(m_pamHandle, PAM_DELETE_CRED);
        pam_end(m_pamHandle, PAM_SUCCESS);
        m_pamHandle = nullptr;
        m_secret.clear();
        m_secretPtr = nullptr;
    }

    void HelperApp::onSessionFinished(int exitCode, QProcess::ExitStatus status)
    {
        qInfo() << "[Helper] session process finished, exitCode" << exitCode
                << "status" << status;

        closePamSession();

        QByteArray payload;
        {
            QDataStream ds(&payload, QIODevice::WriteOnly);
            quint32 code = static_cast<quint32>(exitCode);
            if (status == QProcess::CrashExit)
                code = static_cast<quint32>(SessionError);
            ds << code;
        }
        sendMsg(SessionFinished, payload);

        // The helper is one-shot per session: exit cleanly.
        QCoreApplication::exit(static_cast<int>(exitCode));
    }

    void HelperApp::utmpLogin(bool success)
    {
        struct utmpx entry { };
        struct timeval tv;

        entry.ut_type = USER_PROCESS;
        entry.ut_pid = m_sessionPid;

        // ut_line: vt
        if (m_tty > 0)
            strncpy(entry.ut_line, QStringLiteral("tty%1").arg(m_tty).toLocal8Bit().constData(), sizeof(entry.ut_line) - 1);

        // ut_host: displayName
        if (!m_display.isEmpty())
            strncpy(entry.ut_host, m_display.toLocal8Bit().constData(), sizeof(entry.ut_host) - 1);

        // ut_user: user
        strncpy(entry.ut_user, m_user.toLocal8Bit().constData(), sizeof(entry.ut_user) - 1);

        gettimeofday(&tv, NULL);
        entry.ut_tv.tv_sec = tv.tv_sec;
        entry.ut_tv.tv_usec = tv.tv_usec;

        // write to utmp
        setutxent();
        if (!pututxline(&entry))
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

    void HelperApp::utmpLogout()
    {
        // Only write a logout record if a login was written.
        if (!m_sessionStarted)
            return;

        struct utmpx entry { };
        struct timeval tv;

        entry.ut_type = DEAD_PROCESS;
        entry.ut_pid = m_sessionPid;

        // ut_line: vt
        if (m_tty > 0)
            strncpy(entry.ut_line, QStringLiteral("tty%1").arg(m_tty).toLocal8Bit().constData(), sizeof(entry.ut_line) - 1);

        // ut_host: displayName
        if (!m_display.isEmpty())
            strncpy(entry.ut_host, m_display.toLocal8Bit().constData(), sizeof(entry.ut_host) - 1);

        gettimeofday(&tv, NULL);
        entry.ut_tv.tv_sec = tv.tv_sec;
        entry.ut_tv.tv_usec = tv.tv_usec;

        // write to utmp
        setutxent();
        if (!pututxline(&entry))
            qWarning() << "Failed to write utmpx: " << strerror(errno);
        endutxent();

        // append to wtmp
        updwtmpx("/var/log/wtmp", &entry);
    }

    int HelperApp::converse(int num_msg,
                            const struct pam_message **msg,
                            struct pam_response **resp,
                            void *secret_ptr)
    {
        *resp = static_cast<struct pam_response *>(calloc(num_msg, sizeof(struct pam_response)));
        if (!*resp)
            return PAM_BUF_ERR;

        const char *secret = *static_cast<const char **>(secret_ptr);

        for (int i = 0; i < num_msg; ++i) {
            switch (msg[i]->msg_style) {
            case PAM_PROMPT_ECHO_OFF:
                resp[i]->resp = strdup(secret);
                resp[i]->resp_retcode = 0;
                break;
            case PAM_ERROR_MSG:
                qWarning() << "[Helper][Converse] Error message:" << msg[i]->msg;
                resp[i]->resp = nullptr;
                resp[i]->resp_retcode = 0;
                break;
            case PAM_TEXT_INFO:
                qInfo() << "[Helper][Converse] Info message:" << msg[i]->msg;
                resp[i]->resp = nullptr;
                resp[i]->resp_retcode = 0;
                break;
            default:
                qCritical("[Helper][Converse] Unsupported message style %d: %s", msg[i]->msg_style, msg[i]->msg);
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

    bool HelperApp::doAuthenticate(const QString &user, const QString &pamService, const QByteArray &secret)
    {
        m_user = user;
        m_secret = secret;

        // A stale handle should never survive here, but be safe.
        if (m_pamHandle) {
            pam_end(m_pamHandle, PAM_SUCCESS);
            m_pamHandle = nullptr;
        }

        const char *secretPtr = m_secret.constData();
        m_secretPtr = secretPtr;
        const pam_conv conv = { converse, const_cast<char **>(&m_secretPtr) };

        pam_handle_t *handle = nullptr;
        int ret = pam_start(pamService.toLocal8Bit().constData(),
                            user.toLocal8Bit().constData(),
                            &conv, &handle);
        if (ret != PAM_SUCCESS) {
            qWarning() << "[Helper] pam_start:" << pam_strerror(handle, ret);
            return false;
        }

        qInfo() << "[Helper] Authenticating user" << user;
        ret = pam_authenticate(handle, 0);
        if (ret != PAM_SUCCESS) {
            qWarning() << "[Helper] pam_authenticate:" << pam_strerror(handle, ret);
            pam_end(handle, ret);
            m_secret.fill(0);
            m_secretPtr = nullptr;
            return false;
        }

        // The secret is no longer needed once authentication completed. Wipe it
        // immediately so it does not linger for the whole desktop session.
        // Keep m_secretPtr pointing at the (now zeroed) buffer: PAM may still
        // invoke converse() during pam_acct_mgmt()/pam_open_session(), and
        // nulling it would leave a dangling conversation appdata pointer.
        m_secret.fill(0);

        ret = pam_acct_mgmt(handle, 0);
        if (ret != PAM_SUCCESS) {
            qWarning() << "[Helper] pam_acct_mgmt:" << pam_strerror(handle, ret);
            pam_end(handle, ret);
            m_secretPtr = nullptr;
            return false;
        }

        m_pamHandle = handle;
        return true;
    }

    bool HelperApp::doOpenSession(const QProcessEnvironment &env, QProcessEnvironment &envOut)
    {
        pam_handle_t *handle = m_pamHandle;
        if (!handle)
            return false;

        int ret = pam_setcred(handle, PAM_ESTABLISH_CRED);
        if (ret != PAM_SUCCESS) {
            qWarning() << "[Helper] pam_setcred:" << pam_strerror(handle, ret);
            return false;
        }

        const QString vtPath = TtyUtils::path(m_tty);
        ret = pam_set_item(handle, PAM_TTY, qPrintable(vtPath));
        if (ret != PAM_SUCCESS) {
            qWarning() << "[Helper] pam_set_item(PAM_TTY):" << pam_strerror(handle, ret);
            return false;
        }

        if (!m_display.isEmpty()) {
            ret = pam_set_item(handle, PAM_XDISPLAY, qPrintable(m_display));
            if (ret != PAM_SUCCESS) {
                qWarning() << "[Helper] pam_set_item(PAM_XDISPLAY):" << pam_strerror(handle, ret);
                return false;
            }
        }

        const QStringList envStrs = env.toStringList();
        for (const QString &s : envStrs) {
            ret = pam_putenv(handle, qPrintable(s));
            if (ret != PAM_SUCCESS) {
                qWarning() << "[Helper] pam_putenv:" << pam_strerror(handle, ret);
                return false;
            }
        }

        qInfo() << "[Helper] Opening session for user" << m_user;
        ret = pam_open_session(handle, 0);
        if (ret != PAM_SUCCESS) {
            qWarning() << "[Helper] pam_open_session:" << pam_strerror(handle, ret);
            return false;
        }
        m_sessionOpened = true;

        char **envlist = pam_getenvlist(handle);
        if (envlist) {
            for (int i = 0; envlist[i] != nullptr; ++i) {
                const QString str = QString::fromLocal8Bit(envlist[i]);
                const int eq = str.indexOf('=');
                if (eq != -1)
                    envOut.insert(str.left(eq), str.mid(eq + 1));
                free(envlist[i]);
            }
            free(envlist);
        }
        return true;
    }
} // namespace DDM

int main(int argc, char **argv)
{
    DDM::HelperApp app(argc, argv);
    return app.exec();
}
