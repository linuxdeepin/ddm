/***************************************************************************
* Copyright (c) 2015 Pier Luigi Fiorini <pierluigi.fiorini@gmail.com>
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

#ifndef DDM_VIRTUALTERMINAL_H
#define DDM_VIRTUALTERMINAL_H

#include <QString>

namespace DDM {
    namespace VirtualTerminal {
        QString path(int vt);
        int getVtActive(int fd);
        bool handleVtSwitches(int fd);
        int currentVt();
        int setUpNewVt();
        void jumpToVt(int vt, bool vt_auto);
        void setVtSignalHandler(std::function<void()> onAcquireDisplay, std::function<void()> onReleaseDisplay);
    }
}

#endif // DDM_VIRTUALTERMINAL_H
