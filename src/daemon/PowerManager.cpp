/***************************************************************************
 * Copyright (C) 2025-2026 UnionTech Software Technology Co., Ltd.
 * Copyright (c) 2013 Abdurrahman AVCI <abdurrahmanavci@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the
 * Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 ***************************************************************************/

#include "PowerManager.h"

#include "Configuration.h"
#include "DaemonApp.h"
#include "Messages.h"

#include <QDBusConnectionInterface>
#include <QDBusInterface>
#include <QDBusReply>
#include <QProcess>

namespace DDM {
    /************************************************/
    /* POWER MANAGER BACKEND                        */
    /************************************************/
    class PowerManagerBackend {
    public:
        PowerManagerBackend() {
        }

        virtual ~PowerManagerBackend() {
        }

        Capabilities capabilities() const {
            Capabilities caps = Capability::None;

            if (canPowerOff())
                caps |= Capability::PowerOff;
            if (canReboot())
                caps |= Capability::Reboot;
            if (canSuspend())
                caps |= Capability::Suspend;
            if (canHibernate())
                caps |= Capability::Hibernate;
            if (canHybridSleep())
                caps |= Capability::HybridSleep;

            return caps;
        }

        virtual bool canPowerOff() const = 0;
        virtual bool canReboot() const = 0;
        virtual bool canSuspend() const = 0;
        virtual bool canHibernate() const = 0;
        virtual bool canHybridSleep() const = 0;

        virtual void powerOff() const = 0;
        virtual void reboot() const = 0;
        virtual void suspend() const = 0;
        virtual void hibernate() const = 0;
        virtual void hybridSleep() const = 0;
    };

    /**********************************************/
    /* UPOWER BACKEND                             */
    /**********************************************/

const QString UPOWER_PATH = QStringLiteral("/org/freedesktop/UPower");
const QString UPOWER_SERVICE = QStringLiteral("org.freedesktop.UPower");
const QString UPOWER_OBJECT = QStringLiteral("org.freedesktop.UPower");

    class UPowerBackend : public PowerManagerBackend {
    public:
        UPowerBackend(const QString & service, const QString & path, const QString & interface) {
            m_interface = new QDBusInterface(service, path, interface, QDBusConnection::systemBus());
        }

        ~UPowerBackend() {
            delete m_interface;
        }

        bool canPowerOff() const {
            return true;
        }

        bool canReboot() const {
            return true;
        }

        bool canSuspend() const {
            const QDBusReply<bool> reply = m_interface->call(QStringLiteral("SuspendAllowed"));
            return reply.isValid() && reply.value();
        }

        bool canHibernate() const {
            const QDBusReply<bool> reply = m_interface->call(QStringLiteral("HibernateAllowed"));
            return reply.isValid() && reply.value();
        }

        bool canHybridSleep() const {
            return false;
        }

        void powerOff() const {
            auto command = QProcess::splitCommand(mainConfig.HaltCommand.get());
            const QString program = command.takeFirst();
            QProcess::execute(program, command);
        }

        void reboot() const {
            auto command = QProcess::splitCommand(mainConfig.RebootCommand.get());
            const QString program = command.takeFirst();
            QProcess::execute(program, command);
        }

        void suspend() const {
            m_interface->call(QStringLiteral("Suspend"));
        }

        void hibernate() const {
            m_interface->call(QStringLiteral("Hibernate"));
        }

        void hybridSleep() const {
        }

    private:
        QDBusInterface *m_interface { nullptr };
    };

    /**********************************************/
    /* LOGIN1 && ConsoleKit2 BACKEND              */
    /**********************************************/

const QString LOGIN1_SERVICE = QStringLiteral("org.freedesktop.login1");
const QString LOGIN1_PATH = QStringLiteral("/org/freedesktop/login1");
const QString LOGIN1_OBJECT = QStringLiteral("org.freedesktop.login1.Manager");

const QString CK2_SERVICE = QStringLiteral("org.freedesktop.ConsoleKit");
const QString CK2_PATH = QStringLiteral("/org/freedesktop/ConsoleKit/Manager");
const QString CK2_OBJECT = QStringLiteral("org.freedesktop.ConsoleKit.Manager");

    class SeatManagerBackend : public PowerManagerBackend {
    public:
        SeatManagerBackend(const QString & service, const QString & path, const QString & interface) {
            m_interface = new QDBusInterface(service, path, interface, QDBusConnection::systemBus());
        }

        ~SeatManagerBackend() {
            delete m_interface;
        }

        bool canPowerOff() const {
            return can(QStringLiteral("CanPowerOff"));
        }

        bool canReboot() const {
            return can(QStringLiteral("CanReboot"));
        }

        bool canSuspend() const {
            return can(QStringLiteral("CanSuspend"));
        }

        bool canHibernate() const {
            return can(QStringLiteral("CanHibernate"));
        }

        bool canHybridSleep() const {
            return can(QStringLiteral("CanHybridSleep"));
        }

        void powerOff() const {
            m_interface->call(QStringLiteral("PowerOff"), true);
        }

        void reboot() const {
            m_interface->call(QStringLiteral("Reboot"), true);
        }

        void suspend() const {
            m_interface->call(QStringLiteral("Suspend"), true);
        }

        void hibernate() const {
            m_interface->call(QStringLiteral("Hibernate"), true);
        }

        void hybridSleep() const {
            m_interface->call(QStringLiteral("HybridSleep"), true);
        }


        bool can(const QString &method) const {
            const QDBusReply<QString> reply = m_interface->call(method);
            return reply.isValid() && reply.value() == QLatin1String("yes");
        }
    private:
        QDBusInterface *m_interface { nullptr };
    };

    /**********************************************/
    /* POWER MANAGER                              */
    /**********************************************/
    PowerManager::PowerManager(QObject *parent) : QObject(parent) {
        QDBusConnectionInterface *interface = QDBusConnection::systemBus().interface();

        // check if login1 interface exists
        if (interface->isServiceRegistered(LOGIN1_SERVICE))
            m_backends << new SeatManagerBackend(LOGIN1_SERVICE, LOGIN1_PATH, LOGIN1_OBJECT);

        // check if ConsoleKit2 interface exists
        if (interface->isServiceRegistered(CK2_SERVICE))
            m_backends << new SeatManagerBackend(CK2_SERVICE, CK2_PATH, CK2_OBJECT);

        // check if upower interface exists
        if (interface->isServiceRegistered(UPOWER_SERVICE))
            m_backends << new UPowerBackend(UPOWER_SERVICE, UPOWER_PATH, UPOWER_OBJECT);
    }

    PowerManager::~PowerManager() {
        while (!m_backends.empty())
            delete m_backends.takeFirst();
    }

    Capabilities PowerManager::capabilities() const {
        Capabilities caps = Capability::None;

        for (PowerManagerBackend *backend: m_backends)
            caps |= backend->capabilities();

        return caps;
    }

    bool PowerManager::canPowerOff() const {
        for (PowerManagerBackend *backend: m_backends) {
            if (backend->canPowerOff())
                return true;
        }

        return false;
    }

    bool PowerManager::canReboot() const {
        for (PowerManagerBackend *backend: m_backends) {
            if (backend->canReboot())
                return true;
        }

        return false;
    }

    bool PowerManager::canSuspend() const {
        for (PowerManagerBackend *backend: m_backends) {
            if (backend->canSuspend())
                return true;
        }

        return false;
    }

    bool PowerManager::canHibernate() const {
        for (PowerManagerBackend *backend: m_backends) {
            if (backend->canHibernate())
                return true;
        }

        return false;
    }

    bool PowerManager::canHybridSleep() const {
        for (PowerManagerBackend *backend: m_backends) {
            if (backend->canHybridSleep())
                return true;
        }

        return false;
    }

    void PowerManager::powerOff() const {
        for (PowerManagerBackend *backend: m_backends) {
            if (backend->canPowerOff()) {
                backend->powerOff();
                break;
            }
        }
    }

    void PowerManager::reboot() const {
        for (PowerManagerBackend *backend: m_backends) {
            if (backend->canReboot()) {
                backend->reboot();
                break;
            }
        }
    }

    void PowerManager::suspend() const {
        for (PowerManagerBackend *backend: m_backends) {
            if (backend->canSuspend()) {
                backend->suspend();
                break;
            }
        }
    }

    void PowerManager::hibernate() const {
        for (PowerManagerBackend *backend: m_backends) {
            if (backend->canHibernate()) {
                backend->hibernate();
                break;
            }
        }
    }

    void PowerManager::hybridSleep() const {
        for (PowerManagerBackend *backend: m_backends) {
            if (backend->canHybridSleep()) {
                backend->hybridSleep();
                break;
            }
        }
    }
}
