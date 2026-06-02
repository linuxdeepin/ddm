// Copyright (C) 2026 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef DDM_TTYUTILS_H
#define DDM_TTYUTILS_H

#include <QString>

namespace DDM::TtyUtils {
    inline QString path(int tty) {
#ifdef __FreeBSD__
        const char c = tty <= 10 ? static_cast<char>('0' + (tty - 1))
                                 : static_cast<char>('a' + (tty - 11));
        return QStringLiteral("/dev/ttyv%1").arg(c);
#else
        return QStringLiteral("/dev/tty%1").arg(tty);
#endif
    }
}

#endif
