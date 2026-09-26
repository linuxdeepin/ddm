# DDM

`ddm` 项目是基于 `SDDM` 的显示管理器分支。

## 依赖项

检查 `debian/control` 中的构建时和运行时依赖项，或者使用 `cmake` 来检查缺失的所需依赖项。
## Building

常规的 CMake 构建步骤适用，简而言之：

```shell
$ cmake -Bbuild
$ cmake --build build
$ cmake --install build # only do this if you know what you are doing
```

提供了一个 `debian` 文件夹，用于在 *deepin* Linux 桌面发行版下构建该软件包。 要构建该包，请使用以下命令：

```shell
$ sudo apt build-dep . # install build dependencies
$ dpkg-buildpackage -uc -us -nc -b # build binary package(s)
```

## 参与方式

- [通过 GitHub 提交代码](https://github.com/linuxdeepin/ddm/)
- [向 GitHub 问题或 GitHub 讨论中提交错误或建议](https://github.com/linuxdeepin/developer-center/issues/new/choose)

## 许可证

**ddm** 采用 GPL-2.0+ 许可证。有关详细信息，请参阅 REUSE 文件。