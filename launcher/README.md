# SnowEdge 桌面启动器

<p align="center"><img src="../app/static/brand/snowedge-app.png" width="96" alt="SnowEdge"></p>

正式入口 `SnowEdge.exe` 由 `launcher/Desktop.cs` 编译，使用原生 Windows 窗口与 WebView2。运行 `launcher/build-desktop.ps1` 可重新构建。程序自动准备运行环境、启动本地服务，并管理自己启动的后台进程。

`main.go` 是旧版监督器启动方案的历史源码。旧二进制文件保存在 `tools/dev/legacy`，不作为正式入口，也不进入发布包。
