## Themes

DDM does not implement a greeter and therefore ships no theming API of its own.
The login screen is drawn by
[Treeland](https://github.com/linuxdeepin/treeland), which runs the greeter as
the `LockScreen` QML plugin.

The QtQuick greeter that DDM inherited from SDDM — the `ddm` context object,
`ddm-greeter`, and the `screenModel`, `sessionModel` and `userModel` models —
no longer exists in this repository. Their equivalents are provided by
Treeland's greeter:

- `GreeterProxy` (QML singleton in the `Treeland` module) holds the host name,
  the power capabilities and the lock state, and forwards login, logout, lock
  and unlock requests to DDM over the greeter socket.
- `SessionModel` and `UserModel` (QML singletons in the `Treeland` module)
  list the available desktop sessions and users.

The login screen itself is the `Greeter`/`LoginView` QML in Treeland's
lockscreen plugin. Customizing the login screen therefore means changing that
QML in the Treeland repository, not adding a theme to DDM.

## Testing

DDM no longer ships a `ddm-greeter` test binary. To test the login screen,
start `treeland.service` directly; the greeter connects to DDM through the
socket published on the `org.deepin.DisplayManager.AuthInfo` D-Bus property.
