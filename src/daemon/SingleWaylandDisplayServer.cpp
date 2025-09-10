// Copyright (C) 2023 Dingyuan Zhang <lxz@mkacg.com>.
// SPDX-License-Identifier: GPL-2.0-or-later

#include "SingleWaylandDisplayServer.h"
#include "DaemonApp.h"
#include "DisplayManager.h"
#include "Messages.h"
#include "SocketServer.h"
#include "Constants.h"
#include "SocketWriter.h"
#include "Utils.h"
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

SingleWaylandDisplayServer::SingleWaylandDisplayServer(SocketServer *socketServer, Display *parent)
    : DDM::DisplayServer(parent)
    , m_socketServer(socketServer)
{
    connect(m_socketServer, &SocketServer::connected, this, [this, parent](QLocalSocket *socket) {
        m_greeterSockets << socket;
    });
    connect(m_socketServer, &SocketServer::disconnected, this, [this](QLocalSocket *socket) {
        m_greeterSockets.removeOne(socket);
    });

    // TODO: use PAM auth again
    connect(m_socketServer, &SocketServer::requestActivateUser, this, [this]([[maybe_unused]] QLocalSocket *socket, const QString &user){
        activateUser(user);
    });
}

SingleWaylandDisplayServer::~SingleWaylandDisplayServer() {
    stop();
}

QString SingleWaylandDisplayServer::sessionType() const
{
    return QStringLiteral("wayland");
}

void SingleWaylandDisplayServer::setDisplayName(const QString &displayName)
{
    m_display = displayName;
}

bool SingleWaylandDisplayServer::start()
{
    // Check flag
    if (m_started)
        return false;

    // Start treeland service
    QDBusInterface systemd("org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", QDBusConnection::systemBus());
    systemd.call("StartUnit", "treeland.service", "replace");

    // TODO: check treeland service

    // Set flag
    m_started = true;
    emit started();

    return true;
}

void SingleWaylandDisplayServer::stop()
{
    // Check flag
    if (!m_started)
        return;

    // Stop treeland service
    QDBusInterface systemd("org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", QDBusConnection::systemBus());
    systemd.call("StopUnit", "treeland.service", "replace");

    // Reset flag
    m_started = false;
    emit stopped();
}

void SingleWaylandDisplayServer::finished()
{
}

void SingleWaylandDisplayServer::setupDisplay()
{
}

void SingleWaylandDisplayServer::activateUser(const QString &user) {
    for (auto greeter : m_greeterSockets) {
        if (user == "dde") {
            SocketWriter(greeter) << quint32(DaemonMessages::SwitchToGreeter);
        }

        SocketWriter(greeter) << quint32(DaemonMessages::UserActivateMessage) << user;
    }
}

QString SingleWaylandDisplayServer::getUserWaylandSocket(const QString &user) const {
    return m_waylandSockets.value(user);
}

void SingleWaylandDisplayServer::onLoginFailed(const QString &user) {
    for (auto greeter : m_greeterSockets) {
        SocketWriter(greeter) << quint32(DaemonMessages::LoginFailed) << user;
    }
}

void SingleWaylandDisplayServer::onLoginSucceeded(const QString &user) {
    for (auto greeter : m_greeterSockets) {
        SocketWriter(greeter) << quint32(DaemonMessages::LoginSucceeded) << user;
    }
}
