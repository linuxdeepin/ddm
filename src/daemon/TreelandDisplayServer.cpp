// Copyright (C) 2023 Dingyuan Zhang <lxz@mkacg.com>.
// SPDX-License-Identifier: GPL-2.0-or-later

#include "TreelandDisplayServer.h"
#include "Messages.h"
#include "SocketServer.h"
#include "SocketWriter.h"
#include "Display.h"

#include <QDBusInterface>
#include <QDBusConnection>
#include <QStandardPaths>
#include <QChar>
#include <QLocalSocket>
#include <QLocalServer>
#include <QDataStream>
#include <QTimer>
#include <QProcessEnvironment>

#include <fcntl.h>
#include <sys/socket.h>

using namespace DDM;

TreelandDisplayServer::TreelandDisplayServer(SocketServer *socketServer, Display *parent)
    : QObject(parent)
    , m_socketServer(socketServer) {
    connect(m_socketServer, &SocketServer::connected, this, [this, parent](QLocalSocket *socket) {
        m_greeterSockets << socket;
    });
    connect(m_socketServer, &SocketServer::disconnected, this, [this](QLocalSocket *socket) {
        m_greeterSockets.removeOne(socket);
    });
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
    systemd.call("StartUnit", "treeland.service", "replace");

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
    for (auto greeter : m_greeterSockets) {
        if (user == "dde") {
            SocketWriter(greeter) << quint32(DaemonMessages::SwitchToGreeter);
        }

        SocketWriter(greeter) << quint32(DaemonMessages::UserActivateMessage) << user << xdgSessionId;
    }
}

void TreelandDisplayServer::onLoginFailed(const QString &user) {
    for (auto greeter : m_greeterSockets) {
        SocketWriter(greeter) << quint32(DaemonMessages::LoginFailed) << user;
    }
}
