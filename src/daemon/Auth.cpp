/*
 * Qt Authentication Library
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

#include "Auth.h"

#include "Pam.h"
#include "UserSession.h"

#include <pwd.h>
#include <unistd.h>
#include <utmp.h>
#include <utmpx.h>

namespace DDM {

    //////////////////////
    // Helper functions //
    //////////////////////

    /**
     * Write utmp/wtmp/btmp records when a user logs in
     *
     * @param vt  Virtual terminal (tty7, tty8,...)
     * @param displayName  Display (:0, :1,...)
     * @param user  User logging in
     * @param pid  User process ID (e.g. PID of startkde)
     * @param authSuccessful  Was authentication successful
     */
    static void utmpLogin(const QString &vt, const QString &displayName, const QString &user, qint64 pid, bool authSuccessful) {
        struct utmpx entry { };
        struct timeval tv;

        entry.ut_type = USER_PROCESS;
        entry.ut_pid = pid;

        // ut_line: vt
        if (!vt.isEmpty()) {
            QString tty = QStringLiteral("tty");
            tty.append(vt);
            QByteArray ttyBa = tty.toLocal8Bit();
            const char* ttyChar = ttyBa.constData();
            strncpy(entry.ut_line, ttyChar, sizeof(entry.ut_line) - 1);
        }

        // ut_host: displayName
        QByteArray displayBa = displayName.toLocal8Bit();
        const char* displayChar = displayBa.constData();
        strncpy(entry.ut_host, displayChar, sizeof(entry.ut_host) - 1);

        // ut_user: user
        QByteArray userBa = user.toLocal8Bit();
        const char* userChar = userBa.constData();
        strncpy(entry.ut_user, userChar, sizeof(entry.ut_user) -1);

        gettimeofday(&tv, NULL);
        entry.ut_tv.tv_sec = tv.tv_sec;
        entry.ut_tv.tv_usec = tv.tv_usec;

        // write to utmp
        setutxent();
        if (!pututxline (&entry))
            qWarning() << "Failed to write utmpx: " << strerror(errno);
        endutxent();

        // append to failed login database btmp
        if (!authSuccessful) {
            updwtmpx("/var/log/btmp", &entry);
        } else {
            // append to wtmp
            updwtmpx("/var/log/wtmp", &entry);
        }
    }

    /**
     * Write utmp/wtmp records when a user logs out
     *
     * @param vt  Virtual terminal (tty7, tty8,...)
     * @param displayName  Display (:0, :1,...)
     * @param pid  User process ID (e.g. PID of startkde)
     */
    static void utmpLogout(const QString &vt, const QString &displayName, qint64 pid) {
        struct utmpx entry { };
        struct timeval tv;

        entry.ut_type = DEAD_PROCESS;
        entry.ut_pid = pid;

        // ut_line: vt
        if (!vt.isEmpty()) {
            QString tty = QStringLiteral("tty");
            tty.append(vt);
            QByteArray ttyBa = tty.toLocal8Bit();
            const char* ttyChar = ttyBa.constData();
            strncpy(entry.ut_line, ttyChar, sizeof(entry.ut_line) - 1);
        }

        // ut_host: displayName
        QByteArray displayBa = displayName.toLocal8Bit();
        const char* displayChar = displayBa.constData();
        strncpy(entry.ut_host, displayChar, sizeof(entry.ut_host) - 1);

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

    /////////////////////////
    // Auth implementation //
    /////////////////////////

    Auth::Auth(QObject *parent, QString user)
        : QObject(parent)
        , user(user)
        , m_pam(new Pam(this))
        , m_session(new UserSession(this)) {
        connect(m_session,
                QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                this,
                &Auth::userProcessFinished);
    }

    Auth::~Auth() {
        stop();
    }

    bool Auth::authenticate(const QByteArray &secret) {
        m_pam->user = user;
        if (!m_pam->start()) {
            utmpLogin(std::to_string(tty).c_str(), display, user, 0, false);
            return false;
        }
        if (!m_pam->authenticate(secret)) {
            utmpLogin(std::to_string(tty).c_str(), display, user, 0, false);
            return false;
        }
        active = true;
        return true;
    }

    int Auth::openSession(const QProcessEnvironment &env) {
        Q_ASSERT(active);
        auto ret = m_pam->openSession(env);
        if (!ret.has_value())
            return -1;
        m_env = *ret;
        xdgSessionId = m_env.value(QStringLiteral("XDG_SESSION_ID")).toInt();
        return xdgSessionId;
    }

    void Auth::startUserProcess(const QString &command, const QByteArray &cookie) {
        Q_ASSERT(!m_env.isEmpty());
        QProcessEnvironment env = m_env;
        struct passwd *pw = getpwnam(qPrintable(user));
        if (pw) {
            env.insert(QStringLiteral("HOME"), QString::fromLocal8Bit(pw->pw_dir));
            env.insert(QStringLiteral("PWD"), QString::fromLocal8Bit(pw->pw_dir));
            env.insert(QStringLiteral("SHELL"), QString::fromLocal8Bit(pw->pw_shell));
            env.insert(QStringLiteral("USER"), QString::fromLocal8Bit(pw->pw_name));
            env.insert(QStringLiteral("LOGNAME"), QString::fromLocal8Bit(pw->pw_name));
        }
        m_session->setProcessEnvironment(env);
        m_session->start(command, type, cookie);

        // write successful login to utmp/wtmp
        const QString displayId = env.value(QStringLiteral("DISPLAY"));
        const QString vt = env.value(QStringLiteral("XDG_VTNR"));
        // cache pid for session end
        utmpLogin(vt, displayId, user, m_session->processId(), true);
    }

    void Auth::stop() {
        if (!active)
            return;
        active = false;
        qint64 pid = m_session->processId();
        QString vt = m_env.value(QStringLiteral("XDG_VTNR"));
        QString displayId = m_env.value(QStringLiteral("DISPLAY"));
        if (m_session->state() != QProcess::NotRunning)
            m_session->stop();
        if (m_pam->sessionOpened)
            m_pam->closeSession();

        // write logout to utmp/wtmp
        if (pid > 0) {
            utmpLogout(vt, displayId, pid);
        }
    }
} // namespace DDM
