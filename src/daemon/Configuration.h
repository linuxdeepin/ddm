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

#include <QtCore/QObject>

// The configuration class is generated from the DConfig schema
#include "DdmConfig.hpp"

namespace DDM {
    DdmConfig *mainConfig();

    // Creates the configuration object and reports when the DConfig backend has
    // provided its values. Values must not be read before that: the generated
    // class is initialized asynchronously.
    class Configurations : public QObject {
        Q_OBJECT
    public:
        explicit Configurations(QObject *parent = nullptr);

        bool ready() const {
            return m_ready;
        }

    Q_SIGNALS:
        void readyChanged();

    private:
        void setReady();

        bool m_ready{ false };
    };
}

#endif // DDM_CONFIGURATION_H
