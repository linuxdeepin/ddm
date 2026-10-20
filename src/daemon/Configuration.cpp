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

#include "Configuration.h"

#include "Constants.h"
#include "DdmConfig.hpp"

#include <QtCore/QDebug>

namespace DDM {
    namespace {
        DdmConfig *s_mainConfig{ nullptr };
    }

    DdmConfig *mainConfig() {
        return s_mainConfig;
    }

    Configurations::Configurations(QObject *parent)
        : QObject(parent) {
        s_mainConfig = DdmConfig::create(QStringLiteral(DDM_DCONFIG_APP_ID), QString(), this);

        connect(s_mainConfig, &DdmConfig::configInitializeSucceed, this, [this]() {
            setReady();
        });
        connect(s_mainConfig, &DdmConfig::configInitializeFailed, this, [this]() {
            qCritical() << "Failed to initialize the DDM configuration";
            setReady();
        });
    }

    void Configurations::setReady() {
        if (m_ready)
            return;

        m_ready = true;
        Q_EMIT readyChanged();
    }
}
