// Copyright (C) 2025-2026 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <QObject>

#include <memory>

class QRemoteObjectNode;
class DDMTreelandRemoteReplica;

namespace DDM {
    class TreelandConnector : public QObject {
        Q_OBJECT
    public:
        explicit TreelandConnector(QObject *parent = nullptr);
        ~TreelandConnector();
        bool isConnected();
        int treelandMainPid() const;
        bool connect();
        void disconnect();

        void switchToUser(const QString &username);
        void lock();

    Q_SIGNALS:
        void lockStateChanged(bool locked);

    private:
        bool ensureRemote();

        std::unique_ptr<QRemoteObjectNode> m_remoteNode;
        std::unique_ptr<DDMTreelandRemoteReplica> m_remoteReplica;
    };
} // namespace DDM
