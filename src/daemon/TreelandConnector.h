// Copyright (C) 2025-2026 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#include <QObject>
#include <QLocalSocket>
#include <QSocketNotifier>
#include <QByteArray>

struct wl_display;
struct treeland_ddm_v1;

namespace DDM {
class TreelandConnector : public QObject {
    Q_OBJECT
public:
    TreelandConnector();
    ~TreelandConnector();
    bool isConnected();
    void setPrivateObject(struct treeland_ddm_v1 *ddm);
    void setSignalHandler();
    void connect(const QString socketPath);
    void disconnect();
    int createGroupVtForTreeland(const QString &user, const QString &sessionId);
    void destroyGroupVt(int vt);

    void switchToGreeter();
    void switchToUser(const QString username);
private:
    bool connectControlSocket();
    void disconnectControlSocket();
    void handleControlSocket();
    int treelandMainPid() const;
    bool sendDestroyGroupVt(int vt);

    struct wl_display *m_display { nullptr };
    QSocketNotifier *m_notifier { nullptr };
    QLocalSocket *m_controlSocket { nullptr };
    struct treeland_ddm_v1 *m_ddm { nullptr };
    QByteArray m_controlBuffer;
};
}
