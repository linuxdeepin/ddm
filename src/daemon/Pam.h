// Copyright (C) 2025 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef Pam_H
#define Pam_H

#include <QObject>
#include <QProcessEnvironment>

#include <optional>

namespace DDM {
    class PamPrivate;

    /**
     * PAM authenticate module.
     *
     * The `user' property must be set before calling start().
     * To validate user's secret, call start() then authenticate().
     * To open a session, call openSession() after authenticate().
     * Existing opened session will be closed automatically on destruction,
     * but you can also close it manually with closeSession().
     */
    class Pam : public QObject {
        Q_OBJECT
    public:
        Pam(QObject *parent = nullptr, QString user = QString());
        ~Pam();

        /**
         * Start PAM transaction
         * @return true on success, false on failure
         */
        bool start();
        /**
         * Authenticate user with given secret (e.g. password)
         * @return true on success, false on failure
         */
        bool authenticate(const QByteArray &secret);
        /**
         * Open PAM session with given environment variables
         * @return Environment variables set by PAM modules on success, std::nullopt on failure
         */
        std::optional<QProcessEnvironment> openSession(const QProcessEnvironment &sessionEnv);
        /**
         * Close PAM session
         * @return true on success, false on failure
         */
        bool closeSession();

        /** Username. Must be set before calling start() */
        QString user{};
        /** A boolean value indicating whether a session is opened with this PAM handle */
        bool sessionOpened{ false };

    private:
        PamPrivate *d{ nullptr };
    };
} // namespace DDM

#endif // Pam_H
