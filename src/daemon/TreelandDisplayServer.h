// Copyright (C) 2023 Dingyuan Zhang <lxz@mkacg.com>.
// SPDX-License-Identifier: GPL-2.0-or-later

#include <QObject>

namespace DDM {
    class Display;

    class TreelandDisplayServer : public QObject {
        Q_OBJECT
        Q_DISABLE_COPY(TreelandDisplayServer)
        public:
        explicit TreelandDisplayServer(Display *parent);
        ~TreelandDisplayServer();

    public Q_SLOTS:
        bool start();
        void stop();

    private:
        bool m_started{ false };
    };
}
