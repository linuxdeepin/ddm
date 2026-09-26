// Copyright (C) 2026 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef DDM_FORKEXITGUARD_H
#define DDM_FORKEXITGUARD_H

#include <cstdlib>
#include <sys/types.h>
#include <unistd.h>

namespace DDM::ForkExitGuard {
    /** PID of the process which installed the exit bypass. Forked children
     *  inherit this value unchanged, so inside a child it still refers to
     *  the original (daemon) process. -1 means "not installed". */
    inline pid_t s_ownerPid{ -1 };

    /**
     * atexit(3) handler terminating every process except the one which
     * installed it (i.e. every fork()ed descendant) immediately with
     * _exit(0), so that exit() in a forked child skips all the other
     * exit handlers.
     *
     * Exit handlers registered via atexit()/__cxa_atexit() (such as Qt's
     * static cleanup, e.g. libQt6DBus joining its dispatcher thread) are
     * inherited across fork(), but the threads and other resources they
     * operate on are not: running them in a forked child can deadlock
     * forever. Exit handlers run in LIFO order, so this handler bypasses
     * every handler registered before the last install() call.
     */
    inline void bypassInheritedCleanup() {
        if (::getpid() != s_ownerPid)
            ::_exit(0);
    }

    /**
     * Installs (or refreshes) the exit bypass for forked children.
     *
     * Must be called from the original daemon process before fork(),
     * where all libc locks are in a consistent state. It must never be
     * called from a pthread_atfork child handler or any other post-fork
     * child context: atexit() is not async-signal-safe and may block
     * forever acquiring libc internal locks which were inherited in a
     * locked state from another thread of the forking process.
     *
     * Calling this again before every fork() re-registers the handler at
     * the end of the exit handler list, so that it also runs before any
     * handler registered since the previous install(). The duplicate
     * registrations are harmless in the owner process, where the handler
     * is a no-op and the regular cleanup runs unchanged.
     *
     * @return true on success, false if the handler could not be registered
     */
    inline bool install() {
        if (::atexit(bypassInheritedCleanup) != 0)
            return false;
        s_ownerPid = ::getpid();
        return true;
    }

    /** Whether the exit bypass has been installed in this process image. */
    inline bool isInstalled() {
        return s_ownerPid != -1;
    }

    /** PID of the process which installed the bypass, -1 if not installed. */
    inline pid_t ownerPid() {
        return s_ownerPid;
    }
}

#endif // DDM_FORKEXITGUARD_H
