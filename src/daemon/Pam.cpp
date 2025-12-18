// Copyright (C) 2025 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#include "Pam.h"

#include "VirtualTerminal.h"

#include <QDebug>

#include <security/pam_appl.h>

namespace DDM {
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
                resp[i]->resp = strdup(*static_cast<char **>(secret_ptr));
                resp[i]->resp_retcode = 0;
                break;
            case PAM_ERROR_MSG:
                qWarning() << "[PAM] Error message:" << msg[i]->msg;
                resp[i]->resp = nullptr;
                resp[i]->resp_retcode = 0;
                break;
            case PAM_TEXT_INFO:
                qInfo() << "[PAM] Info message:" << msg[i]->msg;
                resp[i]->resp = nullptr;
                resp[i]->resp_retcode = 0;
                break;
            default:
                qCritical("[PAM] Unsupported message style %d: %s", msg[i]->msg_style, msg[i]->msg);
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

    class PamPrivate : public QObject {
        Q_OBJECT
    public:
        PamPrivate(Pam *parent)
            : QObject(parent)
            , secretPtr(new const char *)
            , conv({ converse, static_cast<void *>(secretPtr) }) {
            *secretPtr = nullptr;
        }

        ~PamPrivate() {
            delete secretPtr;
        }

        pam_handle_t *handle{ nullptr };
        const char **secretPtr{};
        pam_conv conv{};
        int ret{};
    };

    Pam::Pam(QObject *parent, QString user)
        : QObject(parent)
        , user(user)
        , d(new PamPrivate(this)) { }

    Pam::~Pam() {
        if (!d->handle)
            return;
        if (sessionOpened)
            closeSession();
        d->ret = pam_end(d->handle, d->ret);
        if (d->ret != PAM_SUCCESS)
            qWarning() << "[PAM] end:" << pam_strerror(d->handle, d->ret);
        else
            qDebug() << "[PAM] Ended.";
    }

    bool Pam::start() {
        d->ret = pam_start("ddm", user.toLocal8Bit().constData(), &d->conv, &d->handle);
        if (d->ret != PAM_SUCCESS) {
            qWarning() << "[PAM] start" << pam_strerror(d->handle, d->ret);
            return false;
        }
        qDebug() << "[PAM] Starting...";
        return true;
    }

    bool Pam::authenticate(const QByteArray &secret) {
        qDebug() << "[PAM] Authenticating user" << user;

        // Set the secret, authenticate, then clear the secret
        // immediately to avoid leak
        *d->secretPtr = secret.constData();
        d->ret = pam_authenticate(d->handle, 0);
        *d->secretPtr = nullptr;

        if (d->ret != PAM_SUCCESS) {
            qWarning() << "[PAM] authenticate:" << pam_strerror(d->handle, d->ret);
            return false;
        }
        qDebug() << "[PAM] Authenticated.";

        d->ret = pam_acct_mgmt(d->handle, 0);
        if (d->ret != PAM_SUCCESS) {
            qWarning() << "[PAM] acct_mgmt:" << pam_strerror(d->handle, d->ret);
            return false;
        }
        return true;
    }

#define CHECK_RET_OPEN                                                         \
    if (d->ret != PAM_SUCCESS) {                                               \
        qWarning() << "[PAM] openSession:" << pam_strerror(d->handle, d->ret); \
        return std::nullopt;                                                   \
    }
    std::optional<QProcessEnvironment> Pam::openSession(QProcessEnvironment sessionEnv) {
        qDebug() << "[PAM] Opening session for user" << user;

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
        for (const QString &s : sessionEnv.toStringList()) {
            d->ret = pam_putenv(d->handle, qPrintable(s));
            CHECK_RET_OPEN
        }

        // OPEN!!!
        d->ret = pam_open_session(d->handle, 0);
        CHECK_RET_OPEN

        qDebug() << "[PAM] Session opened.";
        sessionOpened = true;

        // Retrieve env vars in new session, which contain XDG_SESSION_ID we need.
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

#define CHECK_RET_CLOSE                                                         \
    if (d->ret != PAM_SUCCESS) {                                                \
        qWarning() << "[PAM] closeSession:" << pam_strerror(d->handle, d->ret); \
        return false;                                                           \
    }
    bool Pam::closeSession() {
        qDebug() << "[PAM] Closing session for user" << user;

        d->ret = pam_close_session(d->handle, 0);
        CHECK_RET_CLOSE

        sessionOpened = false;
        d->ret = pam_setcred(d->handle, PAM_DELETE_CRED);
        CHECK_RET_CLOSE

        qDebug() << "[PAM] Session closed.";
        return true;
    }

} // namespace DDM

#include "Pam.moc"
