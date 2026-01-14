# GitHub Copilot Repository Instructions for ddm

## Big Picture
`ddm` is a Linux display manager that use Treeland as its greeter, originally forked from SDDM. Treeland is a Wayland compositor built on `wlroots` + Qt6/QtQuick

## Where to Look
- `src/common` includes utilities and is exposed outside independently, like configuration definitions, socket messaging protocols and VT management functions.
- `src/daemon` includes source of the main app
  - DaemonApp defines the application. It starts SeatManager, PowerManager, DisplayManager, SignalHandler and TreelandConnector.
    - PowerManager provides functionality of poweroff, reboot, etc.
    - DisplayManager provides org.freedesktop.DisplayManager D-Bus service.
    - SignalHandler handle signals send to the DaemonApp.
    - TreelandConnector is a wayland client that connects to Treeland.
    - SeatManager manage seats & displays. It will create one Display for each seat.
      - The Display starts up Treeland as greeter and use SocketServer to communicate with it.
      - For each time user login / unlock, an Auth is created and managed by Display.
        - When user login, Auth will startup UserSession, which will call PAM to open session, as well as starting up desktop environment.

## Build & Test
```bash
cmake -B build -G Ninja \
      -DCMAKE_INSTALL_PREFIX=/usr \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_CXX_FLAGS="${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror"
cmake --build build
```

## Project Rules (must-follow)
- Use C++20; Qt6 only (do not introduce Qt5 APIs/modules).
- Keep diffs minimal: touch only task-related files/symbols; avoid broad refactors/renames and avoid reformatting unrelated code.
- New files must include an SPDX line consistent with this repo (typically `SPDX-License-Identifier: GPL-2.0-or-later`).
- For English reviews, append a Chinese translation after the English content.
- Terminal commands in fenced `bash` blocks; paths/symbols in backticks.
