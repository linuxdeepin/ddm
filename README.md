# DDM

`ddm` (Deepin Display Manager) is the display and login manager for the
[Treeland](https://github.com/linuxdeepin/treeland) Wayland compositor. It is based on [SDDM](https://github.com/sddm/sddm), but the
QtQuick greeter it inherited is gone: the login screen is drawn by Treeland
itself, and `ddm` only manages the compositor, authenticates users and starts
their desktop sessions.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how the pieces fit together.

## Dependencies

Check `debian/control` for build-time and runtime dependencies, or use `cmake`
to check the missing required dependencies.

Core build dependencies:

- Qt 6 (Core, DBus, Network), version 6.6 or newer
- [treeland-protocols](https://github.com/linuxdeepin/treeland-protocols)
- PAM, libsystemd, libxau and wayland-client
- ECM (extra-cmake-modules) 1.4 or newer

Runtime dependencies:

- [treeland](https://github.com/linuxdeepin/treeland) — the greeter and, for
  single-mode sessions, the compositor the user session runs in
- [dde-seatd](https://github.com/linuxdeepin/dde-seatd) — seat and virtual
  terminal management
- systemd-logind, used to open user sessions

## Building

Regular CMake building steps apply, in short:

```shell
$ cmake -Bbuild
$ cmake --build build
$ cmake --install build # only do this if you know what you are doing
```

The man pages are only built with `-DBUILD_MAN_PAGES=ON`, and require `rst2man`
from the python `docutils` package.

A `debian` folder is provided to build the package under the *deepin* linux desktop distribution. To build the package, use the following command:

```shell
$ sudo apt build-dep . # install build dependencies
$ dpkg-buildpackage -uc -us -nc -b # build binary package(s)
```

## Running

`ddm` is meant to be started by its systemd unit as the display manager:

```shell
$ systemctl start ddm.service
```

It starts `treeland.service` for the login screen and requires
`dde-seatd.service`. Both units, the PAM services and the `dde` greeter user
are installed by the package.

## Getting Involved

- [Code contribution via GitHub](https://github.com/linuxdeepin/ddm/)
- [Submit bug or suggestions to GitHub Issues or GitHub Discussions](https://github.com/linuxdeepin/developer-center/issues/new/choose)

## License

**ddm** is licensed under GPL-2.0+. See REUSE file for detailed information.
