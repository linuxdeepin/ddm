// Copyright (C) 2026 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef DDM_DDESEATDCONTROL_H
#define DDM_DDESEATDCONTROL_H

#include <QByteArray>
#include <QLocalSocket>
#include <QObject>
#include <QString>

namespace DDM {
class DdeSeatdControl : public QObject {
    Q_OBJECT
public:
    explicit DdeSeatdControl(QObject *parent = nullptr);
    ~DdeSeatdControl();

    bool connectEventSocket();
    void disconnectEventSocket();

    int activeVt();
    int findAvailableVt();
    bool requestSwitchVt(int vt);

    int createGroupVt(int ownerPid, const QString &user, const QString &sessionId);
    void destroyGroupVt(int vt);

Q_SIGNALS:
    void vtChanged(int oldVt, int newVt);

private:
    void handleEventSocket();
    void handleEventSocketError(QLocalSocket::LocalSocketError error);
    int queryActiveVt();
    bool sendDestroyGroupVt(int vt);

    QLocalSocket *m_eventSocket { nullptr };
    QByteArray m_eventBuffer;
    int m_activeVt { -1 };
    int m_pendingVt { -1 };
};
}

#endif
