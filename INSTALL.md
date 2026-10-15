## Installation instructions

DDM uses CMake to configure and build the project.

  1. From the project root, configure the build directory:
     `cmake -B build`
  2. To build, run `cmake --build build`.
  3. To install, run `cmake --install build`.

CMake accepts a number of standard and extra arguments:

  - `BUILD_MAN_PAGES`, pass `-DBUILD_MAN_PAGES=ON` to build man pages. This
    requires `rst2man` from the python `docutils` package.
  - `WERROR`, pass `-DWERROR=ON` to build with `-Werror`.
  - `LOGIN_DEFS_PATH`, path of `login.defs` used to autodetect `UID_MIN` and
    `UID_MAX`. Defaults to `/etc/login.defs`.
  - `DDM_INITIAL_VT`, the virtual terminal ddm starts on. Defaults to `1`.
  - Install locations such as `CONFIG_FILE`, `CONFIG_DIR`, `SYSTEM_CONFIG_DIR`,
    `STATE_DIR`, `RUNTIME_DIR`, `DATA_INSTALL_DIR`, `DBUS_CONFIG_DIR` and
    `LOG_FILE` can be overridden in the same way.

By default, a `Release` build is created. To build a debug build, use
`cmake -DCMAKE_BUILD_TYPE=Debug -B build`.

To see all the possible arguments, run `cmake -L -B build`.
For documentation on standard CMake variables, see:
  https://cmake.org/cmake/help/latest/manual/cmake-variables.7.html

### Post-installation steps

DDM runs its greeter as its own user, named **dde**. The user, its group and
its home directory (`/var/lib/ddm` by default) are created by
`systemd-sysusers` from the installed `dde.conf`; the runtime and state
directories are created by `systemd-tmpfiles`. Both are installed by the
package, so on a systemd distribution no manual step is required.

DDM is started by `ddm.service`. It starts `treeland.service` for the login
screen and requires `dde-seatd.service`. Make sure all three units and the PAM
services (`ddm` and `ddm-autologin` in `/etc/pam.d`) are installed.

### Dependencies

DDM depends on PAM for authorization and on systemd-logind for opening user
sessions, and uses libxau to write X authorization files. Apart from other
things, it also depends on Qt 6 for its event loop and D-Bus communication.
It uses wayland-client and the `treeland_ddm_v1` protocol from
treeland-protocols to talk to the Treeland compositor, and dde-seatd to manage
virtual terminals.

X11 sessions additionally require an X server at runtime; the path is
configured with the `X11.ServerPath` option.

DDM makes use of C++20 features, therefore it needs a recent version of GCC to
compile.
