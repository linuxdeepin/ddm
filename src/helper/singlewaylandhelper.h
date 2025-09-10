// Copyright (C) 2023 Dingyuan Zhang <lxz@mkacg.com>.
// SPDX-License-Identifier: GPL-2.0-or-later

#include <QObject>

class QProcess;

class SingleWaylandHelper : public QObject {
    Q_OBJECT
public:
    explicit SingleWaylandHelper(QObject *parent = nullptr);

    bool start(const QString& compositor, const QString& args);

private:
    QProcess *m_process;
};
