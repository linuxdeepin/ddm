// Copyright (C) 2026 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <QFile>
#include <QMap>
#include <QObject>
#include <QPair>
#include <QVariant>

#include "Constants.h"

namespace DDM {
    class Config : public QObject {
        Q_OBJECT
    public:
        /**
         * Constructor.
         *
         * @param configPath Path to the configuration file.
         * @param defaults Default configuration values and descriptions.
         * @param parent Parent QObject.
         */
        Config(const QString &configPath,
               //   section       entry          default   description
               QMap<QString, QMap<QString, QPair<QVariant, QString>>> defaults = {},
               QObject *parent = nullptr)
            : QObject(parent)
            , m_configPath(configPath)
            , m_defaults(defaults) { }

        /**
         * Get a configuration entry value.
         * If the entry is not found in the loaded configuration, the default value is returned.
         * If no default value is set, an exception is thrown.
         *
         * @param section The configuration section name.
         * @param entry The configuration entry name.
         * @return The value of the configuration entry.
         */
        template<typename T>
        inline T get(const QString &section, const QString &entry) const {
            if (m_data.contains(section) && m_data[section].contains(entry))
                return m_data[section][entry].value<T>();
            else if (m_defaults.contains(section) && m_defaults[section].contains(entry))
                return m_defaults[section][entry].first.value<T>();
            else
                throw std::runtime_error(QStringLiteral("Config entry '%1/%2' not found")
                                             .arg(section, entry)
                                             .toStdString());
        }

        /**
         * Get a configuration entry value inside the default section.
         * If the entry is not found in the loaded configuration, the default value is returned.
         * If no default value is set, an exception is thrown.
         *
         * @param entry The configuration entry name.
         * @return The value of the configuration entry.
         */
        template<typename T>
        inline T get(const QString &entry) const {
            return get<T>({}, entry);
        }

        /**
         * Set a configuration entry value.
         *
         * @param section The configuration section name.
         * @param entry The configuration entry name.
         * @param value The value to set.
         */
        template<typename T>
        inline void set(const QString &section, const QString &entry, const T &value) {
            m_data[section][entry] = QVariant::fromValue(value);
        }

        /**
         * Set a configuration entry value inside the default section.
         *
         * @param entry The configuration entry name.
         * @param value The value to set.
         */
        template<typename T>
        inline void set(const QString &entry, const T &value) {
            m_data[{}][entry] = QVariant::fromValue(value);
        }

        /**
         * Reset a configuration entry to its default value.
         *
         * @param section The configuration section name.
         * @param entry The configuration entry name.
         * @return True if the entry was reset, false if it was not found or already default.
         */
        inline bool setDefault(const QString &section, const QString &entry) {
            if (m_data.contains(section) && m_data[section].contains(entry)) {
                m_data[section].remove(entry);
                return true;
            }
            return false;
        }

        /**
         * Reset a configuration entry to its default value inside the default section.
         *
         * @param entry The configuration entry name.
         * @return True if the entry was reset, false if it was not found or already default.
         */
        inline bool setDefault(const QString &entry) {
            return setDefault({}, entry);
        }

        /**
         * Load the configuration from the file.
         *
         * @return True if the configuration was loaded successfully, false otherwise.
         */
        bool load() {
            QFile file(m_configPath);
            if (!file.open(QIODevice::ReadOnly)) {
                return false;
            }
            QString currentSection{};
            while (!file.atEnd()) {
                QString line = QString::fromLocal8Bit(file.readLine()).trimmed();
                if (line.isEmpty() || line.startsWith('#'))
                    continue;
                if (line.startsWith('[') && line.endsWith(']')) {
                    currentSection = line.mid(1, line.length() - 2).trimmed();
                } else {
                    int separatorPosition = line.indexOf('=');
                    if (separatorPosition >= 0) {
                        if (!m_data.contains(currentSection))
                            m_data[currentSection] = {};
                        QString name = line.left(separatorPosition).trimmed();
                        QString value = line.mid(separatorPosition + 1).trimmed();
                        if (value.isEmpty()) {
                            m_data[currentSection][name] = QVariant();
                        } else if (value.indexOf(',') >= 0) {
                            QStringList list = value.split(',', Qt::SkipEmptyParts);
                            for (QString &item : list)
                                item = item.trimmed();
                            m_data[currentSection][name] = QVariant(list);
                        } else
                            m_data[currentSection][name] = QVariant(value);
                    }
                }
            }
            return true;
        }

        /**
         * Save the configuration to the file.
         *
         * @return True if the configuration was saved successfully, false otherwise.
         */
        bool save() const {
            QFile file(m_configPath);
            if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                return false;
            }
            QTextStream out(&file);
            for (auto section = m_data.cbegin(); section != m_data.cend(); ++section) {
                const QString &sectionName = section.key();
                if (!sectionName.isEmpty())
                    out << "[" << sectionName << "]\n";
                const auto &entries = section.value();
                for (auto entry = entries.constBegin(); entry != entries.constEnd(); ++entry) {
                    if (entry.value().userType() == QMetaType::QStringList)
                        out << entry.key() << "=" << entry.value().toStringList().join(", ") << "\n";
                    else
                        out << entry.key() << "=" << entry.value().toString() << "\n";
                }
                out << "\n";
            }
            return true;
        }

        /**
         * Serialize the default configuration to the format of the
         * configuration file, as a string.
         *
         * @return The default configuration as a string.
         */
        QString defaultConfig() const {
            QString str;
            QTextStream out(&str);
            for (auto section = m_defaults.cbegin(); section != m_defaults.cend(); ++section) {
                const QString &sectionName = section.key();
                if (!sectionName.isEmpty())
                    out << "[" << sectionName << "]\n\n";
                const auto &entries = section.value();
                for (auto entry = entries.constBegin(); entry != entries.constEnd(); ++entry) {
                    const QString &description = entry.value().second;
                    if (!description.isEmpty())
                        for (const QString &line : description.split('\n'))
                            out << "# " << line << "\n";
                    if (entry.value().first.userType() == QMetaType::QStringList)
                        out << entry.key() << "=" << entry.value().first.toStringList().join(", ") << "\n\n";
                    else
                        out << entry.key() << "=" << entry.value().first.toString() << "\n\n";
                }
            }
            return str;
        }

        /**
         * Wipe all loaded configuration data, reset all entries to default.
         */
        inline void wipe() {
            m_data.clear();
        }

    private:
        /** Path to the configuration file. */
        QString m_configPath{};
        //   section       entry    value
        QMap<QString, QMap<QString, QVariant>> m_data;
        //   section       entry          default   description
        QMap<QString, QMap<QString, QPair<QVariant, QString>>> m_defaults;
    };

    /** Main configuration instance. */
    inline Config mainConfig(
        CONFIG_FILE,
        { { {},
            { { "HaltCommand", { HALT_COMMAND, "Halt command" } },
              { "RebootCommand", { REBOOT_COMMAND, "Reboot command" } },
              { "Namespaces",
                { QStringList(),
                  "List of Linux namespaces for user session to enter" } } } },
          { "Theme",
            { { "CursorTheme", { QString(), "Cursor theme used in the greeter" } },
              { "CursorSize", { QString(), "Cursor size used in the greeter" } } } },
          { "X11",
            { { "ServerPath", { "/usr/bin/X", "Path to X server binary" } },
              { "ServerArguments",
                { "-nolisten tcp", "Arguments passed to the X server invocation" } },
              { "SessionDir",
                { QStringList{ "/usr/local/share/xsessions", "/usr/share/xsessions" },
                  "Comma-separated list of directories containing available X sessions" } },
              { "SessionCommand",
                { SESSION_COMMAND,
                  "Path to a script to execute when starting the desktop session" } },
              { "SessionLogFile",
                { ".local/share/ddm/xorg-session.log", "Path to the user session log file" } },
              { "DisplayCommand",
                { QStringLiteral(DATA_INSTALL_DIR "/scripts/Xsetup"),
                  "Path to a script to execute when starting the display server" } },
              { "DisplayStopCommand",
                { QStringLiteral(DATA_INSTALL_DIR "/scripts/Xstop"),
                  "Path to a script to execute when stopping the display server" } } } },
          { "Wayland",
            { { "SessionDir",
                { QStringList{ "/usr/local/share/wayland-sessions", "/usr/share/wayland-sessions" },
                  "Comma-separated list of directories containing available Wayland sessions" } },
              { "SessionCommand",
                { WAYLAND_SESSION_COMMAND,
                  "Path to a script to execute when starting the desktop session" } },
              { "SessionLogFile",
                { ".local/share/ddm/wayland-session.log",
                  "Path to the user session log file" } } } },
          { "Single",
            { { "SessionCommand",
                { WAYLAND_SESSION_COMMAND,
                  "Path to a script to execute when starting the desktop session" } } } },
          { "Users",
            { { "DefaultPath",
                { "/usr/local/bin:/usr/bin:/bin", "Default $PATH for logged in users" } },
              { "RememberLastUser", { true, "Remember the last successfully logged in user" } },
              { "RememberLastSession",
                { true, "Remember the session of the last successfully logged in user" } } } } });

    /** State configuration instance. */
    inline Config stateConfig(
        QStringLiteral(STATE_DIR "/state.conf"),
        { { "Last",
            { { "User", { QString(), "The last successfully logged in user" } },
              { "Session",
                { QString(), "The session of the last successfully logged in user" } } } } });
} // namespace DDM
