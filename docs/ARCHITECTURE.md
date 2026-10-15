## Introduction

DDM (Deepin Display Manager) is the display and login manager for the
[Treeland](https://github.com/linuxdeepin/treeland) Wayland compositor. It
authenticates users with PAM, starts their desktop sessions and keeps the login
screen running on the initial virtual terminal.

DDM does not draw the login screen. The greeter is part of Treeland, which DDM
starts as the `treeland.service` systemd unit and which runs as the `dde` user.
DDM only manages the lifecycle of the compositor, the seats and the user
sessions.

## Components

| Component | Description |
| --- | --- |
| `ddm` | The daemon, started by `ddm.service` as root. |
| `ddm-helper` | Session helper, spawned by the daemon for every authentication. |
| `libddm-common` | Shared library with configuration, session and X authorization helpers. |
| `treeland.service` | The compositor providing the greeter, run as the `dde` user. |
| `dde-seatd.service` | Seat and virtual terminal management. |

### Daemon

The daemon (`src/daemon`) is a `QCoreApplication` that owns:

- **Seat management** (`SeatManager`): enumerates logind seats and creates one
  `Display` per graphical seat.
- **Display management** (`TreelandDisplayServer`, `XorgDisplayServer`): starts
  and stops the Treeland compositor, or an X server for X11 sessions.
- **Authentication** (`Auth`): runs the PAM transaction through `ddm-helper` and
  opens the logind session.
- **Application lifecycle** (`Display`): turns greeter requests into logins,
  logouts, locks and unlocks.
- **Power management** (`PowerManager`): power off, reboot, suspend, hibernate
  and hybrid sleep through logind, ConsoleKit2 or UPower, whichever is
  available.
- **Virtual terminals** (`DdeSeatdControl`): asks `dde-seatd` to allocate
  grouped VTs and reports VT changes.

### Session helper

`ddm-helper` (`src/helper`) is a standalone, single-threaded
`QCoreApplication`. The daemon spawns it with `fork()`/`exec()` and talks to it
over an inherited socketpair. It runs the full PAM transaction
(`pam_authenticate()` and `pam_open_session()`) and starts the user's session
process.

Running PAM in a separate process keeps DDM safe from PAM modules that fork
inside `pam_open_session()` (for example gnome-keyring): forking a
multi-threaded Qt process and letting the child call `exit()` can deadlock on
Qt's inherited `atexit` handlers.

### Treeland

Treeland is the compositor and the greeter. It is started by DDM as
`treeland.service` with the `--lockscreen` option, running as the `dde` user.
Its greeter implementation lives in `src/greeter` and the `LockScreen` QML
plugin, and exposes `GreeterProxy`, `SessionModel` and `UserModel` to the login
screen.

For sessions whose desktop file sets `X-DDE-SINGLE-WAYLAND=true`, the user
session runs inside the already running Treeland instance instead of starting
its own compositor. Otherwise DDM stops Treeland and starts the session's own
display server.

### dde-seatd

`dde-seatd` is a fork of `seatd`. DDM talks to its control socket
(`/run/dde-seatd-control.sock`) to allocate and destroy grouped VTs and to be
notified about VT changes. Treeland uses the regular libseat seatd backend
against `/run/dde-seatd.sock`.

## Login flow

1. `ddm.service` starts the daemon. `SeatManager` enumerates logind seats and
   creates a `Display` for every graphical seat.
2. The `Display` picks a virtual terminal, starts `treeland.service`, starts a
   local socket server and publishes the socket path over D-Bus as
   `org.deepin.DisplayManager.AuthInfo`.
3. The Treeland greeter connects to that socket and sends `Connect` with the
   path of its Wayland socket. The daemon connects to it and binds the private
   `treeland_ddm_v1` protocol. It then sends the host name, the power
   capabilities and `ShowGreeter`.
4. When the greeter sends `Login`, the daemon authenticates the user with
   `ddm-helper`. On success it saves the last user and session in
   `state.conf` and starts the session.
5. The session type decides what happens next:
   - **Single-mode Treeland** (`X-DDE-SINGLE-WAYLAND=true`): the daemon asks
     `dde-seatd` for a grouped VT, opens the logind session and asks Treeland to
     switch to the user.
   - **Wayland**: the daemon stops Treeland and runs the session's compositor
     through the `Wayland.SessionCommand` script.
   - **X11**: the daemon stops Treeland, starts the X server with an
     authorization file in `RUNTIME_DIR` (`/run/ddm/xauth_XXXXXX`), writes the
     user session's authorization cookie to `/tmp/xauth_XXXXXX` and runs the
     session through the `X11.SessionCommand` script.
6. `Logout`, `Lock` and `Unlock` messages are forwarded to systemd-logind
   (`TerminateSession()`, `LockSession()`, `UnlockSession()`). Unlocking also
   activates the session again, either through Treeland or by switching to the
   session's VT.
7. When the session process exits, the daemon removes the session and frees
   its grouped VT. For X11 sessions the stopped X server also tears the
   display down, which makes the seat recreate itself and start Treeland
   again for the login screen.

VT switches are driven by `dde-seatd`: on every VT change the daemon tells
Treeland to switch to the greeter or to the user owning the new VT.

## Communication

### Greeter socket

The greeter talks to the daemon over a local socket named
`ddm-treeland-XXXXXX`. Messages are framed with a `quint32` opcode:

- greeter to daemon: `Connect`, `Login`, `Logout`, `Lock`, `Unlock`,
  `PowerOff`, `Reboot`, `Suspend`, `Hibernate`, `HybridSleep`, `BackToNormal`.
- daemon to greeter: `HostName`, `Capabilities`, `LoginFailed`,
  `InformationMessage`, `UserActivateMessage`, `SwitchToGreeter`,
  `UserLoggedIn`, `ShowGreeter`.

The opcodes are defined in `src/common/Messages.h`.

### Wayland protocol

The daemon binds the private `treeland_ddm_v1` global of the Treeland
compositor (see the treeland-protocols repository) and uses it to switch
between the greeter and a user. The deprecated `switch_to_vt` and `acquire_vt`
events are ignored, as VT switching is handled by `dde-seatd` and
wlroots/libseat.

### D-Bus

The daemon registers `org.freedesktop.DisplayManager` at
`/org/freedesktop/DisplayManager` (seats, sessions, `LastSession`) and the
deepin-specific `org.deepin.DisplayManager` at `/org/deepin/DisplayManager`
(`AuthInfo`, `LastActivatedUser`). The greeter uses the latter to find the
daemon socket and to know which user was activated last.

## Configuration

Configuration is loaded, from lowest to highest precedence, from the system
configuration directory (`${CMAKE_INSTALL_PREFIX}/lib/ddm/ddm.conf.d`, which
defaults to `/usr/local/lib/ddm/ddm.conf.d`), `/etc/ddm.conf.d` and
`/etc/ddm.conf`. The last user and session are stored in `state.conf` in the
`dde` user's home directory. See **ddm.conf**(5) and **ddm-state.conf**(5).
