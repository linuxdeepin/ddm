# DDM

`ddm`（Deepin Display Manager）是
[Treeland](https://github.com/linuxdeepin/treeland) Wayland 合成器的显示与登录
管理器。它基于 [SDDM](https://github.com/sddm/sddm)，但不再使用从
SDDM 继承的 QtQuick greeter：登录界面由 Treeland 自己绘制，`ddm` 只负责管理
合成器、认证用户并启动用户桌面会话。

各组件之间的关系参见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 依赖

查看 `debian/control` 了解构建时和运行时依赖，或者使用 `cmake` 检查缺失的
必要组件。

核心构建依赖：

- Qt 6（Core、DBus、Network），版本 6.6 或更高
- [treeland-protocols](https://github.com/linuxdeepin/treeland-protocols)
- PAM、libsystemd、libxau 和 wayland-client
- ECM（extra-cmake-modules）1.4 或更高

运行时依赖：

- [treeland](https://github.com/linuxdeepin/treeland) —— 提供登录界面，并在
  single 模式下作为用户会话所在的合成器
- [dde-seatd](https://github.com/linuxdeepin/dde-seatd) —— seat 与虚拟终端管理
- systemd-logind —— 用于打开用户会话

## 构建

常规的 CMake 构建步骤即可，简要如下：

```shell
$ cmake -Bbuild
$ cmake --build build
$ cmake --install build # 只有明确知道后果时才执行安装
```

只有传入 `-DBUILD_MAN_PAGES=ON` 才会构建 man 手册，且需要 python `docutils`
提供的 `rst2man`。

仓库提供了 `debian` 目录用于在 *deepin* Linux 发行版下打包。构建软件包使用
以下命令：

```shell
$ sudo apt build-dep . # 安装构建依赖
$ dpkg-buildpackage -uc -us -nc -b # 构建二进制软件包
```

## 运行

`ddm` 由自身的 systemd 服务作为显示管理器启动：

```shell
$ systemctl start ddm.service
```

它会启动 `treeland.service` 以提供登录界面，并依赖 `dde-seatd.service`。
这些服务、PAM 配置以及 `dde` greeter 用户均由软件包安装。

## 参与贡献

- [通过 GitHub 贡献代码](https://github.com/linuxdeepin/ddm/)
- [在 GitHub Issues 或 GitHub Discussions 提交问题或建议](https://github.com/linuxdeepin/developer-center/issues/new/choose)

## 许可证

**ddm** 使用 GPL-2.0+ 许可证。详细信息参见 REUSE 文件。
