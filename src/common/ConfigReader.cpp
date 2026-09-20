/*
 * INI Configuration parser classes (DConfig backed)
 * Copyright (C) 2014 Martin Bříza <mbriza@redhat.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 *
 */

#include "ConfigReader.h"

#include <DConfig>

#include <QtCore/QCoreApplication>
#include <QtCore/QDebug>
#include <QtCore/QFile>
#include <QtCore/QHash>
#include <QtCore/QMap>
#include <QtCore/QMetaType>
#include <QtCore/QStringView>
#include <QtCore/QtGlobal>

QTextStream &operator>>(QTextStream &str, QStringList &list)  {
    list.clear();

    QString line = str.readLine();
    const auto strings = QStringView{line}.split(u',');
    for (const QStringView &s : strings) {
        QStringView trimmed = s.trimmed();
        if (!trimmed.isEmpty())
            list.append(trimmed.toString());
    }
    return str;
}

QTextStream &operator<<(QTextStream &str, const QStringList &list) {
    str << list.join(QLatin1Char(','));
    return str;
}

QTextStream &operator>>(QTextStream &str, bool &val) {
    QString line = str.readLine();
    val = (0 == QStringView(line).trimmed().compare(QLatin1String("true"), Qt::CaseInsensitive));
    return str;
}

QTextStream &operator<<(QTextStream &str, const bool &val) {
    if (val)
        str << "true";
    else
        str << "false";
    return str;
}

namespace DDM {
    namespace {
        QString dconfigKey(const QString &section, const QString &entry) {
            static const QHash<QString, QString> s_overrides = {
                { QStringLiteral("Theme.CursorTheme"), QStringLiteral("cursorTheme") },
                { QStringLiteral("Theme.CursorSize"), QStringLiteral("cursorSize") },
                { QStringLiteral("Users.RememberLastUser"), QStringLiteral("rememberLastUser") },
                { QStringLiteral("Users.RememberLastSession"),
                  QStringLiteral("rememberLastSession") },
            };

            const QString fullName = section + QLatin1Char('.') + entry;
            auto it = s_overrides.constFind(fullName);
            if (it != s_overrides.constEnd())
                return it.value();

            QString key;
            if (section != QStringLiteral(IMPLICIT_SECTION))
                key = section + entry;
            else
                key = entry;
            if (!key.isEmpty())
                key[0] = key[0].toLower();
            return key;
        }

        DTK_CORE_NAMESPACE::DConfig *dconfigFor(const QString &appId, const QString &name) {
            static QHash<QString, DTK_CORE_NAMESPACE::DConfig *> s_configs;
            const QString cacheKey = appId + QLatin1Char('/') + name;
            auto it = s_configs.constFind(cacheKey);
            if (it != s_configs.constEnd())
                return it.value();
            auto *config = DTK_CORE_NAMESPACE::DConfig::create(appId, name, QString(), nullptr);
            s_configs.insert(cacheKey, config);
            return config;
        }

        QString variantToString(const QVariant &value) {
            if (value.typeId() == QMetaType::QStringList)
                return value.toStringList().join(QLatin1Char(','));
            if (value.typeId() == QMetaType::QVariantList) {
                QStringList stringList;
                const auto list = value.toList();
                for (const QVariant &item : list)
                    stringList << item.toString();
                return stringList.join(QLatin1Char(','));
            }
            return value.toString();
        }

        QVariant stringToVariant(DTK_CORE_NAMESPACE::DConfig *config,
                                 const QString &key,
                                 const QString &str) {
            switch (config->value(key).typeId()) {
            case QMetaType::Bool:
                return QVariant(str.compare(QLatin1String("true"), Qt::CaseInsensitive) == 0);
            case QMetaType::QStringList:
            case QMetaType::QVariantList: {
                QStringList list;
                const auto parts = QStringView{ str }.split(u',');
                for (const QStringView &part : parts) {
                    const QStringView trimmed = part.trimmed();
                    if (!trimmed.isEmpty())
                        list.append(trimmed.toString());
                }
                return QVariant(list);
            }
            default:
                return QVariant(str);
            }
        }
    } // namespace

    template <> void ConfigEntry<QString>::setValue(const QString &str) {
        m_value = str.trimmed();
    }

    ConfigSection::ConfigSection(ConfigBase *parent, const QString &name) : m_parent(parent),
        m_name(name) {
        m_parent->m_sections.insert(name, this);
    }

    ConfigEntryBase *ConfigSection::entry(const QString &name) {
        auto it = m_entries.find(name);
        if (it != m_entries.end())
            return it.value();
        return nullptr;
    }

    const ConfigEntryBase *ConfigSection::entry(const QString &name) const {
        auto it = m_entries.find(name);
        if (it != m_entries.end())
            return it.value();
        return nullptr;
    }

    const QMap<QString, ConfigEntryBase*> &ConfigSection::entries() const {
        return m_entries;
    }


    const QString &ConfigSection::name() const {
        return m_name;
    }

    void ConfigSection::save(ConfigEntryBase *entry) {
        m_parent->save(this, entry);
    }

    void ConfigSection::clear() {
        for (auto it : m_entries) {
            it->setDefault();
        }
    }

    QString ConfigSection::toConfigFull() const {
        QString final = QStringLiteral("[%1]\n").arg(m_name);
        for (const ConfigEntryBase *entry : m_entries)
            final.append(entry->toConfigFull());
        return final;
    }

    QString ConfigSection::toConfigShort() const {
        return QStringLiteral("[%1]").arg(name());
    }

    ConfigBase::ConfigBase(const QString &configPath, const QString &configDir, const QString &sysConfigDir) :
        m_path(configPath),
        m_configDir(configDir),
        m_sysConfigDir(sysConfigDir)
    {
    }

    bool ConfigBase::hasUnused() const {
        return m_unusedSections || m_unusedVariables;
    }

    QString ConfigBase::toConfigFull() const {
        QString ret;
        for (ConfigSection *s : m_sections) {
            ret.append(s->toConfigFull());
            ret.append(QLatin1Char('\n'));
        }
        return ret;
    }

    void ConfigBase::load()
    {
        // The Config macro constructs and loads the config objects during
        // static initialization, before a QCoreApplication exists. DConfig
        // cannot be used then, so defer the actual load to runtime.
        if (!QCoreApplication::instance())
            return;

        auto *config = dconfigFor(m_configDir, m_path);
        if (!config || !config->isValid())
            return;

        for (ConfigSection *section : m_sections) {
            const auto &entries = section->entries();
            for (auto it = entries.constBegin(); it != entries.constEnd(); ++it) {
                const QVariant value = config->value(dconfigKey(section->name(), it.key()));
                if (!value.isValid())
                    continue;
                it.value()->setValue(variantToString(value));
            }
        }
    }

    void ConfigBase::save(const ConfigSection *section, const ConfigEntryBase *entry) {
        auto *config = dconfigFor(m_configDir, m_path);
        if (!config)
            return;

        auto saveEntry = [&config](const ConfigSection *s, const ConfigEntryBase *e) {
            const QString key = dconfigKey(s->name(), e->name());
            if (e->matchesDefault())
                config->reset(key);
            else
                config->setValue(key, stringToVariant(config, key, e->value()));
        };

        if (section) {
            if (entry)
                saveEntry(section, entry);
            else
                for (const ConfigEntryBase *e : section->entries())
                    saveEntry(section, e);
        } else {
            for (const ConfigSection *s : m_sections)
                for (const ConfigEntryBase *e : s->entries())
                    saveEntry(s, e);
        }
    }

    void ConfigBase::wipe() {
        for (auto it : m_sections) {
            it->clear();
        }
    }
}
