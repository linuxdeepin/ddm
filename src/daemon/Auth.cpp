// Copyright (C) 2026 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#include "Auth.h"

#include "Constants.h"
#include "DaemonApp.h"
#include "DdeSeatdControl.h"

#include <pwd.h>
#include <signal.h>
#include <unistd.h>

#include <fcntl.h>
#include <sys/socket.h>

#include <QDataStream>
#include <QDebug>
#include <QProcess>

namespace DDM {

    namespace {
        constexpr int kHeaderSize = sizeof(quint32);
        constexpr quint32 kMaxFrameSize = 1 << 20;

        // Helper protocol opcodes. Keep in sync with HelperApp::Msg.
        constexpr quint32 kOpAuthenticate = 1;
        constexpr quint32 kOpOpenSession = 2;
        constexpr quint32 kOpAuthResult = 3;
        constexpr quint32 kOpSessionResult = 4;
        constexpr quint32 kOpSessionFinished = 5;

        bool writeAll(int fd, const void *buf, size_t len)
        {
            const char *p = static_cast<const char *>(buf);
            size_t off = 0;
            while (off < len) {
                // MSG_NOSIGNAL: the peer (helper) may already have exited,
                // so write() must return EPIPE instead of raising SIGPIPE
                // and killing the daemon.
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

    ///////////////////////////
    // utmp helper functions //
    ///////////////////////////

    /////////////////////////
    // Auth implementation //
    /////////////////////////

    class AuthPrivate : public QObject {
        Q_OBJECT
    public:
        AuthPrivate(Auth *parent)
            : QObject(parent)
        {
        }

        // socketpair for talking to the session helper.
        int socketFd { -1 };
        // Helper process.
        QProcess *helper { nullptr };
        // Buffer for streaming replies from the helper.
        QByteArray recvBuffer;
    };

    Auth::Auth(QObject *parent, QString user)
        : QObject(parent)
        , user(user)
        , d(new AuthPrivate(this)) {}

    Auth::~Auth() {
        if (sessionOpened) {
            if (sessionPid > 0)
                kill(sessionPid, SIGTERM);
            closeSession();
        }
        // closeSession() records logout while sessionOpened is still true,
        // but a session that was never opened (e.g. authenticate-only) needs
        // no utmp logout. The helper is always terminated as a fallback here.
        if (d->helper) {
            d->helper->terminate();
            if (!d->helper->waitForFinished(3000))
                d->helper->kill();
        }
        if (d->socketFd >= 0) {
            ::close(d->socketFd);
            d->socketFd = -1;
        }
        qInfo() << "[Auth] Auth for user" << user << "ended.";
    }

    bool Auth::ensureHelper()
    {
        if (d->helper)
            return true;

        int sv[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) == -1) {
            qWarning() << "[Auth] socketpair failed:" << strerror(errno);
            return false;
        }

        d->helper = new QProcess(this);

        // The helper is exec()'d from a fresh, single-threaded process. It
        // never opens a DBus connection, so gnome-keyring's fork()+exit()
        // inside pam_open_session() cannot deadlock on Qt atexit handlers.
        //
        // All of the daemon's sockets are FD_CLOEXEC, so exec() closes them
        // automatically (no inherited system-bus fd, no retained DBus names).
        // The only fd that must survive exec() is our socketpair write end,
        // whose number is passed through argv after clearing its CLOEXEC flag.
        d->helper->setChildProcessModifier([sv]() {
            ::close(sv[0]);
            ::fcntl(sv[1], F_SETFD, 0); // clear FD_CLOEXEC
        });

        d->helper->setProgram(QStringLiteral("%1/ddm-helper").arg(QStringLiteral(LIBEXEC_INSTALL_DIR)));
        d->helper->setArguments({ QString::number(sv[1]) });

        connect(d->helper, &QProcess::errorOccurred, this, [this](QProcess::ProcessError e) {
            qCritical() << "[Auth] helper error:" << e;
        });
        connect(d->helper, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                this, &Auth::onHelperFinished);

        d->helper->start();

        ::close(sv[1]);
        d->socketFd = sv[0];

        if (!d->helper->waitForStarted()) {
            qWarning() << "[Auth] failed to start helper";
            ::close(d->socketFd);
            d->socketFd = -1;
            d->helper->deleteLater();
            d->helper = nullptr;
            return false;
        }

        return true;
    }

    void Auth::onHelperFinished(int exitCode, QProcess::ExitStatus status)
    {
        qInfo() << "[Auth] session helper finished, exitCode" << exitCode
                << "status" << status;
        // Whether it exited cleanly or crashed, the user session is over.
        // Do NOT clear sessionOpened here: the destructor (invoked by Display
        // from this signal) uses that flag to record the utmp/wtmp logout.
        Q_EMIT sessionFinished();
    }

    bool Auth::sendRequest(quint32 op, const QByteArray &payload, QByteArray &reply)
    {
        if (!ensureHelper())
            return false;

        QByteArray frame;
        {
            QDataStream ds(&frame, QIODevice::WriteOnly);
            ds << static_cast<quint32>(payload.size() + sizeof(quint32));
            ds << op;
            if (!payload.isEmpty())
                ds.writeRawData(payload.constData(), payload.size());
        }

        if (!writeAll(d->socketFd, frame.constData(), frame.size())) {
            qWarning() << "[Auth] failed to write request";
            return false;
        }

        // Read one complete framed reply.
        for (;;) {
            if (d->recvBuffer.size() >= kHeaderSize) {
                // The helper writes the frame header with QDataStream
                // (big-endian); read it the same way.
                quint32 len = 0;
                {
                    QDataStream lenStream(d->recvBuffer);
                    lenStream >> len;
                }
                if (len < sizeof(quint32) || len > kMaxFrameSize) {
                    qWarning() << "[Auth] invalid reply length" << len;
                    return false;
                }
                if (d->recvBuffer.size() >= static_cast<int>(len + kHeaderSize)) {
                    // len counts the op (4 bytes) + payload bytes that follow
                    // the 4-byte length header.
                    reply = d->recvBuffer.mid(kHeaderSize, len);
                    d->recvBuffer.remove(0, static_cast<int>(len + kHeaderSize));
                    return true;
                }
            }
            char chunk[4096];
            const ssize_t r = ::read(d->socketFd, chunk, sizeof(chunk));
            if (r <= 0) {
                if (r < 0 && errno == EINTR)
                    continue;
                qWarning() << "[Auth] helper closed channel unexpectedly";
                return false;
            }
            d->recvBuffer.append(chunk, static_cast<int>(r));
        }
    }

    bool Auth::authenticate(const QByteArray &secret) {
        Q_ASSERT(!user.isEmpty());

        qInfo() << "[Auth] Starting...";

        if (!ensureHelper()) {
            return false;
        }

        QByteArray payload;
        {
            QDataStream ds(&payload, QIODevice::WriteOnly);
            ds << user << pamService << secret;
        }

        QByteArray reply;
        if (!sendRequest(kOpAuthenticate, payload, reply)) {
            return false;
        }

        // Reply payload: [quint32 op(AuthResult)][bool ok]
        QDataStream in(reply);
        quint32 op = 0;
        in >> op;
        bool ok = false;
        if (op == kOpAuthResult) {
            in >> ok;
        }

        if (!ok) {
            qWarning() << "[Auth] Authentication failed for user" << user;
            return false;
        }

        authenticated = true;
        return true;
    }

    QString Auth::openSession(const QString &command,
                              QProcessEnvironment env,
                              const QByteArray &cookie) {
        Q_ASSERT(authenticated);

        if (!ensureHelper()) {
            return {};
        }

        // Here is most safe place to request the VT switch before opening the session.
        if (!daemonApp->seatdControl()->requestSwitchVt(tty)) {
            qWarning() << "[Auth] Failed to switch to VT" << tty << ":" << strerror(errno);
            return {};
        }

        QByteArray payload;
        {
            QDataStream ds(&payload, QIODevice::WriteOnly);
            ds << env.toStringList()
               << cookie
               << display
               << tty
               << static_cast<int>(type)
               << command;
        }

        QByteArray reply;
        if (!sendRequest(kOpOpenSession, payload, reply)) {
            return {};
        }

        QDataStream in(reply);
        quint32 op = 0;
        in >> op;
        if (op != kOpSessionResult) {
            qWarning() << "[Auth] unexpected reply op" << op;
            return {};
        }

        quint32 status = 0;
        in >> status;
        if (status != 0 /* Success */) {
            qWarning() << "[Auth] openSession failed with status" << status;
            return {};
        }

        QString xdgId;
        qint64 pid = 0;
        in >> xdgId >> pid;

        if (xdgId.isEmpty()) {
            qCritical() << "[Auth] empty XDG_SESSION_ID from helper";
            return {};
        }
        if (pid <= 0) {
            qCritical() << "[Auth] invalid session PID from helper" << pid;
            return {};
        }

        xdgSessionId = xdgId;
        sessionPid = pid;
        sessionOpened = true;

        return xdgSessionId;
    }

    bool Auth::closeSession() {
        if (!sessionOpened) {
            qWarning() << "[Auth] closeSession: Session was not opened.";
            return true;
        }
        qWarning() << "[Auth] Closing session for user" << user;

        // The helper runs the PAM teardown (pam_close_session /
        // PAM_DELETE_CRED / pam_end) in ~HelperApp(). SIGTERM makes it exit
        // its event loop gracefully so that destructor runs; kill() is only a
        // timeout fallback.
        if (d->helper && d->helper->state() != QProcess::NotRunning) {
            d->helper->terminate();
            if (!d->helper->waitForFinished(5000))
                d->helper->kill();
        }

        sessionOpened = false;
        qInfo() << "[Auth] Session closed.";
        return true;
    }
} // namespace DDM

#include "Auth.moc"
