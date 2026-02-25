/***************************************************************************
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

#ifndef DDM_DAEMONAPP_H
#define DDM_DAEMONAPP_H

#include <QCoreApplication>

#define daemonApp DaemonApp::instance()

namespace DDM {
    class Configuration;
    class DisplayManager;
    class PowerManager;
    class SeatManager;
    class SignalHandler;

    class DaemonApp : public QCoreApplication {
        Q_OBJECT
        Q_DISABLE_COPY(DaemonApp)
    public:
        explicit DaemonApp(int &argc, char **argv);

        static inline DaemonApp *instance() { return self; }

        QString hostName() const;
        inline DisplayManager *displayManager() const { return m_displayManager; };
        inline PowerManager *powerManager() const { return m_powerManager; };
        inline SeatManager *seatManager() const { return m_seatManager; };
        inline SignalHandler *signalHandler() const { return m_signalHandler; };

        void backToNormal();

    public slots:
        int newSessionId();

    private:
        static DaemonApp *self;

        int m_lastSessionId { 0 };

        DisplayManager *m_displayManager { nullptr };
        PowerManager *m_powerManager { nullptr };
        SeatManager *m_seatManager { nullptr };
        SignalHandler *m_signalHandler { nullptr };
    };
}

#endif // DDM_DAEMONAPP_H
