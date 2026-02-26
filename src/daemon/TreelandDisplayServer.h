// Copyright (C) 2023-2026 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#include <QMap>
#include <QDBusVariant>

class QLocalSocket;
class QLocalServer;

namespace DDM {
    class Display;
    class SocketServer;

    class TreelandDisplayServer : public QObject {
        Q_OBJECT
        Q_DISABLE_COPY(TreelandDisplayServer)
        public:
        explicit TreelandDisplayServer(DDM::SocketServer *socketServer, Display *parent);
        ~TreelandDisplayServer();

    public Q_SLOTS:
        bool start();
        void stop();
        void activateUser(const QString &user, int xdgSessionId);
        void onLoginFailed(const QString &user);

    private:
        SocketServer *m_socketServer;
        QList<QLocalSocket *> m_greeterSockets;
        bool m_started{ false };
    };
}
