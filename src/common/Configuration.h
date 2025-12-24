/*
 * DDM configuration
 * Copyright (C) 2014 Martin Bříza <mbriza@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#ifndef DDM_CONFIGURATION_H
#define DDM_CONFIGURATION_H

#include <QtCore/QString>
#include <QtCore/QTextStream>
#include <QtCore/QStringList>
#include <QtCore/QDir>
#include <pwd.h>

#include "Constants.h"

#include "ConfigReader.h"

namespace DDM {
    //     Name        File         Sections and/or Entries (but anything else too, it's a class) - Entries in a Config are assumed to be in the General section
    Config(MainConfig, QStringLiteral(CONFIG_FILE), QStringLiteral(CONFIG_DIR), QStringLiteral(SYSTEM_CONFIG_DIR),

        //  Name                   Type         Default value                                   Description
        Entry(HaltCommand,         QString,     _S(HALT_COMMAND),                               _S("Halt command"));
        Entry(RebootCommand,       QString,     _S(REBOOT_COMMAND),                             _S("Reboot command"));
        Entry(Namespaces,          QStringList, QStringList(),                                  _S("Comma-separated list of Linux namespaces for user session to enter"));
        //  Name   Entries (but it's a regular class again)
        Section(Theme,
            Entry(CursorTheme,         QString,     QString(),                                  _S("Cursor theme used in the greeter"));
            Entry(CursorSize,          QString,     QString(),                                  _S("Cursor size used in the greeter"));
        );

        // TODO: Not absolutely sure if everything belongs here. Xsessions, VT and probably some more seem universal
        Section(X11,
            Entry(ServerPath,          QString,     _S("/usr/bin/X"),                           _S("Path to X server binary"));
            Entry(ServerArguments,     QString,     _S("-nolisten tcp"),                        _S("Arguments passed to the X server invocation"));
            Entry(SessionDir,          QStringList, {_S("/usr/local/share/xsessions"),
                                                     _S("/usr/share/xsessions")},               _S("Comma-separated list of directories containing available X sessions"));
            Entry(SessionCommand,      QString,     _S(SESSION_COMMAND),                        _S("Path to a script to execute when starting the desktop session"));
            Entry(SessionLogFile,      QString,     _S(".local/share/ddm/xorg-session.log"),   _S("Path to the user session log file"));
            Entry(DisplayCommand,      QString,     _S(DATA_INSTALL_DIR "/scripts/Xsetup"),     _S("Path to a script to execute when starting the display server"));
            Entry(DisplayStopCommand,  QString,     _S(DATA_INSTALL_DIR "/scripts/Xstop"),      _S("Path to a script to execute when stopping the display server"));
        );

        Section(Wayland,
            Entry(SessionDir,          QStringList, {_S("/usr/local/share/wayland-sessions"),
                                                     _S("/usr/share/wayland-sessions")},        _S("Comma-separated list of directories containing available Wayland sessions"));
            Entry(SessionCommand,      QString,     _S(WAYLAND_SESSION_COMMAND),                _S("Path to a script to execute when starting the desktop session"));
            Entry(SessionLogFile,      QString,     _S(".local/share/ddm/wayland-session.log"),_S("Path to the user session log file"));
        );

        Section(Single,
            Entry(SessionCommand,      QString,     _S(WAYLAND_SESSION_COMMAND),                _S("Path to a script to execute when starting the desktop session"));
        );

        Section(Users,
            Entry(DefaultPath,         QString,     _S("/usr/local/bin:/usr/bin:/bin"),         _S("Default $PATH for logged in users"));
            Entry(RememberLastUser,    bool,        true,                                       _S("Remember the last successfully logged in user"));
            Entry(RememberLastSession, bool,        true,                                       _S("Remember the session of the last successfully logged in user"));
        );
    );

    Config(StateConfig, []()->QString{auto tmp = getpwnam("ddm"); return tmp ? QString::fromLocal8Bit(tmp->pw_dir) : QStringLiteral(STATE_DIR);}().append(QStringLiteral("/state.conf")), QString(), QString(),
        Section(Last,
            Entry(Session,         QString,     QString(),                                      _S("Name of the session for the last logged-in user.\n"
                                                                                                   "This session will be preselected when the login screen appears."));
            Entry(User,            QString,     QString(),                                      _S("Name of the last logged-in user.\n"
                                                                                                   "This user will be preselected when the login screen appears"));
        );
    );

    extern MainConfig mainConfig;
    extern StateConfig stateConfig;
}

#endif // DDM_CONFIGURATION_H
