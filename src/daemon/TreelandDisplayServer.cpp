// Copyright (C) 2023 Dingyuan Zhang <lxz@mkacg.com>.
// SPDX-License-Identifier: GPL-2.0-or-later

#include "TreelandDisplayServer.h"
#include "Display.h"

#include <QDBusInterface>
#include <QDBusConnection>

using namespace DDM;

TreelandDisplayServer::TreelandDisplayServer(Display *parent)
    : QObject(parent) { }

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
