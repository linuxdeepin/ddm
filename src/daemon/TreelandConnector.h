// Copyright (C) 2025-2026 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#include <QObject>
#include <QSocketNotifier>

struct wl_display;
struct wl_callback;
struct treeland_ddm_v1;

namespace DDM {
class TreelandConnector : QObject {
    Q_OBJECT
public:
    TreelandConnector();
    ~TreelandConnector();
    bool isConnected();
    void setPrivateObject(struct treeland_ddm_v1 *ddm);
    void setSignalHandler();
    void connect(const QString socketPath);
    void disconnect();

    void switchToGreeter();
    void switchToUser(const QString username);
    void ackVtSwitch(const int vtnr);
    void activateSession();
    void deactivateSession();
    void enableRender();
    struct wl_callback *disableRender();
private:
    struct wl_display *m_display { nullptr };
    QSocketNotifier *m_notifier { nullptr };
    struct treeland_ddm_v1 *m_ddm { nullptr };
};
}
