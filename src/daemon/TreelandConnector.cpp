// Copyright (C) 2025-2026 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#include "TreelandConnector.h"

#include "rep_treelandremote_replica.h"

#include <QDBusInterface>
#include <QDBusObjectPath>
#include <QDBusReply>
#include <QDBusVariant>
#include <QDebug>
#include <QRemoteObjectNode>
#include <QRemoteObjectPendingCallWatcher>
#include <QUrl>

#include <limits>

namespace DDM {

    static constexpr auto systemdService = "org.freedesktop.systemd1";
    static constexpr auto systemdPath = "/org/freedesktop/systemd1";
    static constexpr auto systemdManagerInterface = "org.freedesktop.systemd1.Manager";
    static constexpr auto systemdPropertiesInterface = "org.freedesktop.DBus.Properties";
    static constexpr auto systemdServiceInterface = "org.freedesktop.systemd1.Service";
    static constexpr auto treelandUnit = "treeland.service";
    static constexpr auto treelandRemoteUrl = "local:org.deepin.dde.treeland.qro";

    // TreelandConnector

    TreelandConnector::TreelandConnector(QObject *parent)
        : QObject(parent) { }

    TreelandConnector::~TreelandConnector() {
        disconnect();
    }

    bool TreelandConnector::isConnected() {
        return m_remoteReplica && m_remoteReplica->state() == QRemoteObjectReplica::Valid;
    }

    bool TreelandConnector::connect() {
        return ensureRemote();
    }

    void TreelandConnector::disconnect() {
        m_remoteReplica.reset();
        m_remoteNode.reset();
    }

    bool TreelandConnector::ensureRemote() {
        if (isConnected())
            return true;

        if (!m_remoteNode) {
            m_remoteNode.reset(new QRemoteObjectNode);
            if (!m_remoteNode->connectToNode(QUrl(QString::fromLatin1(treelandRemoteUrl)))) {
                qWarning() << "Failed to connect Treeland remote node:" << treelandRemoteUrl;
                m_remoteNode.reset();
                return false;
            }
        }

        if (!m_remoteReplica) {
            m_remoteReplica.reset(m_remoteNode->acquire<DDMTreelandRemoteReplica>());
            QObject::connect(
                m_remoteReplica.get(),
                &QRemoteObjectReplica::stateChanged,
                this,
                [this](QRemoteObjectReplica::State state, QRemoteObjectReplica::State oldState) {
                    qInfo() << "Treeland remote replica state changed from" << oldState << "to"
                            << state;
                });
            QObject::connect(m_remoteReplica.get(),
                             &DDMTreelandRemoteReplica::lockChanged,
                             this,
                             [this](bool locked) {
                                 qDebug() << "Treeland lock state changed:" << locked;
                                 Q_EMIT lockStateChanged(locked);
                             });
            if (!m_remoteReplica->waitForSource(3000)) {
                qWarning() << "Timed out waiting for Treeland remote source";
                disconnect();
                return false;
            }
            auto *lockStateWatcher =
                new QRemoteObjectPendingCallWatcher(m_remoteReplica->lockState(), this);
            QObject::connect(lockStateWatcher,
                             &QRemoteObjectPendingCallWatcher::finished,
                             this,
                             [this](QRemoteObjectPendingCallWatcher *watcher) {
                                 if (watcher->error() == QRemoteObjectPendingCall::NoError) {
                                     const QVariant value = watcher->returnValue();
                                     if (value.canConvert<bool>()) {
                                         const bool locked = value.toBool();
                                         qDebug() << "Treeland initial lock state:" << locked;
                                         Q_EMIT lockStateChanged(locked);
                                     } else {
                                         qWarning() << "Treeland lockState returned invalid value:"
                                                    << value;
                                     }
                                 } else {
                                     qWarning() << "Failed to query Treeland lock state:"
                                                << watcher->error();
                                 }
                                 watcher->deleteLater();
                             });
        }

        return isConnected();
    }

    int TreelandConnector::treelandMainPid() const {
        QDBusInterface systemd(systemdService,
                               systemdPath,
                               systemdManagerInterface,
                               QDBusConnection::systemBus());
        const auto unitReply =
            systemd.call(QStringLiteral("GetUnit"), QString::fromLatin1(treelandUnit));
        if (unitReply.type() == QDBusMessage::ErrorMessage) {
            qWarning() << "Failed to get" << treelandUnit << "unit:" << unitReply.errorMessage();
            return -1;
        }

        const auto unitPath = qvariant_cast<QDBusObjectPath>(unitReply.arguments().value(0)).path();
        QDBusInterface properties(systemdService,
                                  unitPath,
                                  systemdPropertiesInterface,
                                  QDBusConnection::systemBus());
        const auto reply = properties.call(QStringLiteral("Get"),
                                           QString::fromLatin1(systemdServiceInterface),
                                           QStringLiteral("MainPID"));
        if (reply.type() == QDBusMessage::ErrorMessage) {
            qWarning() << "Failed to get Treeland MainPID:" << reply.errorMessage();
            return -1;
        }

        const auto variant = qvariant_cast<QDBusVariant>(reply.arguments().value(0)).variant();
        bool ok = false;
        const auto pid = variant.toULongLong(&ok);
        if (!ok || pid == 0 || pid > static_cast<qulonglong>(std::numeric_limits<pid_t>::max())) {
            qWarning() << "Invalid Treeland MainPID from systemd:" << variant;
            return -1;
        }
        return static_cast<int>(pid);
    }

    // Request wrapper

    void TreelandConnector::switchToUser(const QString &username) {
        if (!ensureRemote()) {
            qWarning("Treeland is not connected when trying to call switchToUser");
            return;
        }

        qDebug("Calling treeland switchToUser: user=%s", qPrintable(username));
        m_remoteReplica->switchToUser(username);
    }

    void TreelandConnector::lock() {
        if (!ensureRemote()) {
            qWarning("Treeland is not connected when trying to call lock");
            return;
        }

        qDebug("Calling treeland lock");
        m_remoteReplica->lock();
    }

} // namespace DDM
