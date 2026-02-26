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

#ifndef DDM_SEATMANAGER_H
#define DDM_SEATMANAGER_H

#include <QObject>
#include <QHash>
#include <QDBusObjectPath>
#include "Display.h"

namespace DDM {
    class LogindSeat;

    class SeatManager : public QObject {
        Q_OBJECT
    public:
        explicit SeatManager(QObject *parent = 0) : QObject(parent) {}

        void initialize();
        void createSeat(const QString &name);
        void removeSeat(const QString &name);
        void switchToGreeter(const QString &seat);

        QList<Display *> displays; //these will exist only for graphical seats
        QHash<QString, LogindSeat*> systemSeats; //these will exist for all seats

    Q_SIGNALS:
        void seatCreated(const QString &name);
        void seatRemoved(const QString &name);

    private Q_SLOTS:
        void logindSeatAdded(const QString &name, const QDBusObjectPath &objectPath);
        void logindSeatRemoved(const QString &name, const QDBusObjectPath &objectPath);
        void displayStopped();

    private:
        void startDisplay(Display *display, int tryNr = 1);
    };
}

#endif // DDM_SEATMANAGER_H
