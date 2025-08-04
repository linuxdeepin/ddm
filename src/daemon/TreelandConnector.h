// Copyright (C) 2025 April Lu <apr3vau@outlook.com>.
// SPDX-License-Identifier: Apache-2.0 OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only

#include <QObject>
#include <QSocketNotifier>

struct wl_display;
struct treeland_ddm;

namespace DDM {
class TreelandConnector : QObject {
    Q_OBJECT
public:
    TreelandConnector();
    ~TreelandConnector();
    bool isConnected();
    void setPrivateObject(struct treeland_ddm *ddm);
    void connect(const QString socketPath);

    void switchToGreeter();
    void switchToUser(const QString username);
    void activateSession();
    void deactivateSession();
private:
    struct wl_display *m_display { nullptr };
    QSocketNotifier *m_notifier { nullptr };
    struct treeland_ddm *m_ddm { nullptr };
};
}
