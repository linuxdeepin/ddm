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

#include "SeatManager.h"

#include "Configuration.h"
#include "DaemonApp.h"
#include "Display.h"

#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusPendingReply>
#include <QDBusContext>
#include <QTimer>

#include "LogindDBusTypes.h"
#include <Login1Manager.h>

namespace DDM {

    class LogindSeat : public QObject {
    Q_OBJECT
    public:
        LogindSeat(const QString &name, const QDBusObjectPath &objectPath);
        QString name() const;
        bool canGraphical() const;
    Q_SIGNALS:
        void canGraphicalChanged(bool);
    private Q_SLOTS:
        void propertiesChanged(const QString &interface, const QVariantMap &changedProperties , const QStringList &invalidatedProperties);
    private:
        QString m_name;
        bool m_canGraphical;
    };

    LogindSeat::LogindSeat(const QString& name, const QDBusObjectPath& objectPath):
        m_name(name),
        m_canGraphical(false)
    {
        QDBusConnection::systemBus().connect(Logind::serviceName(), objectPath.path(), QStringLiteral("org.freedesktop.DBus.Properties"), QStringLiteral("PropertiesChanged"), this, SLOT(propertiesChanged(QString,QVariantMap,QStringList)));

        auto canGraphicalMsg = QDBusMessage::createMethodCall(Logind::serviceName(), objectPath.path(), QStringLiteral("org.freedesktop.DBus.Properties"), QStringLiteral("Get"));
        canGraphicalMsg << Logind::seatIfaceName() << QStringLiteral("CanGraphical");

        QDBusPendingReply<QVariant> reply = QDBusConnection::systemBus().asyncCall(canGraphicalMsg);
        QDBusPendingCallWatcher *watcher = new QDBusPendingCallWatcher(reply);
        connect(watcher, &QDBusPendingCallWatcher::finished, this, [watcher, reply, this]() {
            watcher->deleteLater();
            if (!reply.isValid())
                return;

            bool value = reply.value().toBool();
            if (value != m_canGraphical) {
                m_canGraphical = value;
                emit canGraphicalChanged(m_canGraphical);
            }
        });
    }

    bool LogindSeat::canGraphical() const
    {
        return m_canGraphical;
    }

    QString LogindSeat::name() const
    {
        return m_name;
    }

    void LogindSeat::propertiesChanged(const QString& interface, const QVariantMap& changedProperties, const QStringList& invalidatedProperties)
    {
        Q_UNUSED(invalidatedProperties);
        if (interface != Logind::seatIfaceName()) {
            return;
        }

        if (changedProperties.contains(QStringLiteral("CanGraphical"))) {
            m_canGraphical = changedProperties[QStringLiteral("CanGraphical")].toBool();
            emit canGraphicalChanged(m_canGraphical);
        }
    }

    void SeatManager::initialize() {
        if (!Logind::isAvailable()) {
            //if we don't have logind/CK2, just create a single seat immediately and don't do any other connections
            createSeat(QStringLiteral("seat0"));
            return;
        }

        //fetch seats
        auto listSeatsMsg = QDBusMessage::createMethodCall(Logind::serviceName(), Logind::managerPath(), Logind::managerIfaceName(), QStringLiteral("ListSeats"));
        QDBusPendingReply<NamedSeatPathList> reply = QDBusConnection::systemBus().asyncCall(listSeatsMsg);

        QDBusPendingCallWatcher *watcher = new QDBusPendingCallWatcher(reply);
        connect(watcher, &QDBusPendingCallWatcher::finished, this, [watcher, reply, this]() {
            watcher->deleteLater();
            const auto seats = reply.value();
            for (const NamedSeatPath &seat : seats) {
                logindSeatAdded(seat.name, seat.path);
            }
        });

        QDBusConnection::systemBus().connect(Logind::serviceName(), Logind::managerPath(), Logind::managerIfaceName(), QStringLiteral("SeatNew"), this, SLOT(logindSeatAdded(QString,QDBusObjectPath)));
        QDBusConnection::systemBus().connect(Logind::serviceName(), Logind::managerPath(), Logind::managerIfaceName(), QStringLiteral("SeatRemoved"), this, SLOT(logindSeatRemoved(QString,QDBusObjectPath)));
    }

    void SeatManager::createSeat(const QString &name) {
        //reload config if needed
        mainConfig.load();

        // create a new display
        qDebug() << "Adding new display...";
        Display *display = new Display(this, name);

        // restart display on stop
        connect(display, &Display::stopped, this, &SeatManager::displayStopped);

        // start the display
        startDisplay(display);

        // add to the list
        displays.append(display);

        // emit signal
        emit seatCreated(name);
    }

    void SeatManager::removeSeat(const QString &name) {
        for (auto display : std::as_const(displays)) {
            if (display->name == name) {
                // remove from the list
                displays.removeAll(display);
                // stop the display
                display->blockSignals(true);
                display->stop();
                display->blockSignals(false);
                // delete display
                display->deleteLater();
                // emit signal
                emit seatRemoved(name);
                return;
            }
        }
    }

    void SeatManager::switchToGreeter(const QString &name) {
        for (auto display : std::as_const(displays)) {
            if (display->name == name) {
                // switch to greeter
                display->activateSession("dde", 0);
                return;
            }
        }
    }

    void SeatManager::startDisplay(Display *display, int tryNr) {
        if (display->start())
            return;

        // It's possible that the system isn't ready yet (driver not loaded,
        // device not enumerated, ...). It's not possible to tell when that changes,
        // so try a few times with a delay in between.
        qWarning() << "Attempt" << tryNr << "starting the Display server on vt" << display->terminalId << "failed";

        if(tryNr >= 3) {
            qCritical() << "Could not start Display server on vt" << display->terminalId;
            return;
        }

        QTimer::singleShot(2000, display, [this, display, tryNr] { startDisplay(display, tryNr + 1); });
    }

    void SeatManager::displayStopped() {
        Display *display = qobject_cast<Display *>(sender());
        QString name = display->name;
        // re-create display
        removeSeat(name);
        createSeat(name);
    }

    void SeatManager::logindSeatAdded(const QString& name, const QDBusObjectPath& objectPath)
    {
        auto logindSeat = new LogindSeat(name, objectPath);
        connect(logindSeat, &LogindSeat::canGraphicalChanged, this, [this, logindSeat]() {
            if (logindSeat->canGraphical()) {
                createSeat(logindSeat->name());
            } else {
                removeSeat(logindSeat->name());
            }
        });

        systemSeats.insert(name, logindSeat);
    }

    void SeatManager::logindSeatRemoved(const QString& name, const QDBusObjectPath& objectPath)
    {
        Q_UNUSED(objectPath);
        auto logindSeat = systemSeats.take(name);
        delete logindSeat;
        removeSeat(name);
    }
}

#include "SeatManager.moc"
