// Copyright (C) 2025-2026 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#include <QObject>
#include <QSocketNotifier>
#include <QString>

struct wl_display;
struct treeland_ddm_v1;

namespace DDM {
class TreelandConnector : public QObject {
    Q_OBJECT
public:
    explicit TreelandConnector(QObject *parent = nullptr);
    ~TreelandConnector();
    bool isConnected();
    int mainPid();
    void setPrivateObject(struct treeland_ddm_v1 *ddm);
    void connect(const QString &socketPath);
    void disconnect();
    void switchToGreeter();
    void switchToUser(const QString &username);

private:
    struct wl_display *m_display { nullptr };
    QSocketNotifier *m_notifier { nullptr };
    struct treeland_ddm_v1 *m_ddm { nullptr };
};
}
