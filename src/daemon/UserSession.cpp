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

#include <QCoreApplication>
#include <QSocketNotifier>

#include "Auth.h"
#include "Configuration.h"
#include "TreelandConnector.h"
#include "UserSession.h"
#include "VirtualTerminal.h"
#include "XAuth.h"

#include <linux/kd.h>
#include <functional>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <termios.h>

namespace DDM {
    UserSession::UserSession(Auth *parent)
        : QProcess(parent) {
        setChildProcessModifier(std::bind(&UserSession::childModifier, this));
    }

    void UserSession::start(const QString &command,
                            Display::DisplayServerType type,
                            const QByteArray &cookie) {
        QProcessEnvironment env = processEnvironment();

        switch (type) {
        case Display::Treeland: {
            setProgram(mainConfig.Single.SessionCommand.get());
            setArguments(QStringList{ command });
            qInfo() << "Starting Treeland session:" << program() << command;
            QProcess::start();
            closeWriteChannel();
            closeReadChannel(QProcess::StandardOutput);
            return;
        }
        case Display::X11: {
            if (cookie.isEmpty()) {
                qCritical() << "Can't start X11 session with empty auth cookie";
                return;
            }
            // Create the Xauthority file
            // Place it into /tmp, which is guaranteed to be read/writeable by
            // everyone while having the sticky bit set to avoid messing with
            // other's files.
            m_xauthFile.setFileTemplate(QStringLiteral("/tmp/xauth_XXXXXX"));

            if (!m_xauthFile.open()) {
                qCritical() << "Could not create the Xauthority file";
                return;
            }

            QString display = env.value(QStringLiteral("DISPLAY"));

            if (!XAuth::writeCookieToFile(display, m_xauthFile.fileName(), cookie)) {
                qCritical() << "Failed to write the Xauthority file";
                m_xauthFile.close();
                return;
            }

            env.insert(QStringLiteral("XAUTHORITY"), m_xauthFile.fileName());
            setProcessEnvironment(env);

            qInfo() << "Starting X11 user session:" << command;
            setProgram(mainConfig.X11.SessionCommand.get());
            setArguments(QStringList{ command });
            QProcess::start();
            return;
        }
        case Display::Wayland: {
            setProgram(mainConfig.Wayland.SessionCommand.get());
            setArguments(QStringList{ command });
            qInfo() << "Starting Wayland user session:" << program() << command;
            QProcess::start();
            closeWriteChannel();
            closeReadChannel(QProcess::StandardOutput);
            return;
        }
        default: {
            qCritical() << "Unable to run user session: unknown session type";
        }
        }
    }

    void UserSession::stop()
    {
        if (state() != QProcess::NotRunning) {
            terminate();
            if (!waitForFinished(60000)) {
                kill();
                if (!waitForFinished(5000)) {
                    qWarning() << "Could not fully finish the process" << program();
                }
            }
        } else {
            Q_EMIT finished(1);
        }
    }

    void UserSession::childModifier() {
        Auth *auth = qobject_cast<Auth *>(parent());

        // When the display server is part of the session, we leak the VT into
        // the session as stdin so that it stays open without races
        if (auth->type != Display::X11) {
            // open VT and get the fd
            QString ttyString = VirtualTerminal::path(auth->tty);
            int vtFd = ::open(qPrintable(ttyString), O_RDWR | O_NOCTTY);

            // when this is true we'll take control of the tty
            bool takeControl = false;

            if (vtFd > 0) {
                dup2(vtFd, STDIN_FILENO);
                ::close(vtFd);
                takeControl = true;
            } else {
                int stdinFd = ::open("/dev/null", O_RDWR);
                dup2(stdinFd, STDIN_FILENO);
                ::close(stdinFd);
            }

            // set this process as session leader
            if (setsid() < 0) {
                qCritical("Failed to set pid %lld as leader of the new session and process group: %s",
                          QCoreApplication::applicationPid(), strerror(errno));
                _exit(1);
            }

            // take control of the tty
            if (takeControl) {
                if (ioctl(STDIN_FILENO, TIOCSCTTY, 1) < 0) {
                    const auto error = strerror(errno);
                    qCritical().nospace() << "Failed to take control of " << ttyString << " (" << QFileInfo(ttyString).owner() << "): " << error;
                    _exit(1);
                }
                if (ioctl(STDIN_FILENO, KDSKBMODE, K_OFF) == -1) {
                    qCritical().nospace() << "Failed to set keyboard mode to K_OFF";
                    _exit(1);
                }
            }
        }

        // enter Linux namespaces
        for (const QString &ns: mainConfig.Namespaces.get()) {
            qInfo() << "Entering namespace" << ns;
            int fd = ::open(qPrintable(ns), O_RDONLY);
            if (fd < 0) {
                qCritical("open(%s) failed: %s", qPrintable(ns), strerror(errno));
                exit(1);
            }
            if (setns(fd, 0) != 0) {
                qCritical("setns(open(%s), 0) failed: %s", qPrintable(ns), strerror(errno));
                exit(1);
            }
            ::close(fd);
        }

        // switch user
        const QByteArray username = auth->user.toLocal8Bit();
        struct passwd pw;
        struct passwd *rpw;
        long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
        if (bufsize == -1)
            bufsize = 16384;
        QScopedPointer<char, QScopedPointerPodDeleter> buffer(static_cast<char*>(malloc(bufsize)));
        if (buffer.isNull()) {
            qCritical() << "Could not allocate buffer of size" << bufsize;
            exit(1);
        }
        int err = getpwnam_r(username.constData(), &pw, buffer.data(), bufsize, &rpw);
        if (rpw == NULL) {
            if (err == 0)
                qCritical() << "getpwnam_r(" << username << ") username not found!";
            else
                qCritical() << "getpwnam_r(" << username << ") failed with error: " << strerror(err);
            exit(1);
        }

        const int xauthHandle = m_xauthFile.handle();
        if (xauthHandle != -1 && fchown(xauthHandle, pw.pw_uid, pw.pw_gid) != 0) {
            qCritical() << "fchown failed for" << m_xauthFile.fileName();
            exit(1);
        }

        if (setgid(pw.pw_gid) != 0) {
            qCritical() << "setgid(" << pw.pw_gid << ") failed for user: " << username;
            exit(1);
        }

        // fetch ambient groups from PAM's environment;
        // these are set by modules such as pam_groups.so
        int n_pam_groups = getgroups(0, NULL);
        gid_t *pam_groups = NULL;
        if (n_pam_groups > 0) {
            pam_groups = new gid_t[n_pam_groups];
            if ((n_pam_groups = getgroups(n_pam_groups, pam_groups)) == -1) {
                qCritical() << "getgroups() failed to fetch supplemental"
                            << "PAM groups for user:" << username;
                exit(1);
            }
        } else {
            n_pam_groups = 0;
        }

        // fetch session's user's groups
        int n_user_groups = 0;
        gid_t *user_groups = NULL;
        if (-1 == getgrouplist(pw.pw_name, pw.pw_gid,
                               NULL, &n_user_groups)) {
            user_groups = new gid_t[n_user_groups];
            if ((n_user_groups = getgrouplist(pw.pw_name,
                                              pw.pw_gid, user_groups,
                                              &n_user_groups)) == -1 ) {
                qCritical() << "getgrouplist(" << pw.pw_name << ", " << pw.pw_gid
                            << ") failed";
                exit(1);
            }
        }

        // set groups to concatenation of PAM's ambient
        // groups and the session's user's groups
        int n_groups = n_pam_groups + n_user_groups;
        if (n_groups > 0) {
            gid_t *groups = new gid_t[n_groups];
            memcpy(groups, pam_groups, (n_pam_groups * sizeof(gid_t)));
            memcpy((groups + n_pam_groups), user_groups,
                   (n_user_groups * sizeof(gid_t)));

            // setgroups(2) handles duplicate groups
            if (setgroups(n_groups, groups) != 0) {
                qCritical() << "setgroups() failed for user: " << username;
                exit (1);
            }
            delete[] groups;
        }
        delete[] pam_groups;
        delete[] user_groups;

        if (setuid(pw.pw_uid) != 0) {
            qCritical() << "setuid(" << pw.pw_uid << ") failed for user: " << username;
            exit(1);
        }

        if (chdir(pw.pw_dir) != 0) {
            qCritical() << "chdir(" << pw.pw_dir << ") failed for user: " << username;
            qCritical() << "verify directory exist and has sufficient permissions";
            exit(1);
        }

        //we cannot use setStandardError file as this code is run in the child process
        //we want to redirect after we setuid so that the log file is owned by the user

        // determine stderr log file based on session type
        QString sessionLog = QStringLiteral("%1/%2")
            .arg(QString::fromLocal8Bit(pw.pw_dir))
            .arg(auth->type == Display::X11
                 ? mainConfig.X11.SessionLogFile.get()
                 : mainConfig.Wayland.SessionLogFile.get());

        // create the path
        QFileInfo finfo(sessionLog);
        QDir().mkpath(finfo.absolutePath());

        //swap the stderr pipe of this subprcess into a file
        int fd = ::open(qPrintable(sessionLog), O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0)
            {
                dup2 (fd, STDERR_FILENO);
                ::close(fd);
            } else {
            qWarning() << "Could not open stderr to" << sessionLog;
        }

        //redirect any stdout to /dev/null
        fd = ::open("/dev/null", O_WRONLY);
        if (fd >= 0)
            {
                dup2 (fd, STDOUT_FILENO);
                ::close(fd);
            } else {
            qWarning() << "Could not redirect stdout";
        }
    }
}
