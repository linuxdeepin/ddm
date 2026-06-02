// Copyright (C) 2023-2026 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#include "TreelandDisplayServer.h"
#include "SocketServer.h"
#include "Display.h"
#include "DaemonApp.h"
#include "TreelandConnector.h"

#include <QDBusInterface>
#include <QDBusConnection>
#include <QStandardPaths>
#include <QChar>
#include <QTimer>
#include <QProcessEnvironment>

#include <fcntl.h>
#include <sys/socket.h>

using namespace DDM;

TreelandDisplayServer::TreelandDisplayServer(SocketServer *socketServer, Display *parent)
    : QObject(parent)
    , m_socketServer(socketServer) {
}

TreelandDisplayServer::~TreelandDisplayServer() {
    stop();
}

bool TreelandDisplayServer::start() {
    // Check flag
    if (m_started)
        return false;

    // Start treeland service
    QDBusInterface systemd("org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", QDBusConnection::systemBus());
    const QDBusMessage reply = systemd.call("StartUnit", "treeland.service", "replace");
    if (reply.type() == QDBusMessage::ErrorMessage) {
        qCritical() << "Failed to start treeland.service:" << reply.errorMessage();
        return false;
    }

    // TODO: check treeland service

    // Set flag
    m_started = true;

    return true;
}

void TreelandDisplayServer::stop() {
    // Check flag
    if (!m_started)
        return;

    // Stop treeland service
    QDBusInterface systemd("org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", QDBusConnection::systemBus());
    systemd.call("StopUnit", "treeland.service", "replace");

    // Reset flag
    m_started = false;
}

void TreelandDisplayServer::activateUser(const QString &user, int xdgSessionId) {
    qDebug("Send greeter activation: user=%s xdgSessionId=%d",
           qPrintable(user), xdgSessionId);
    if (user == "dde")
        daemonApp->treelandConnector()->lock();
    else
        daemonApp->treelandConnector()->switchToUser(user);
}

void TreelandDisplayServer::onLoginFailed(const QString &user) {
    m_socketServer->loginFailed(user);
}
