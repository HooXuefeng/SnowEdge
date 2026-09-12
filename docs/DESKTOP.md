# Windows 桌面工作台

双击目录外层的“SnowEdge”快捷方式，或项目内的 `SnowEdge.exe`。

- 原生独立窗口，支持拖动、最大化、调整窗口大小，无需打开浏览器或终端。
- 顶部不再显示返回、首页、刷新功能条。网页页脚“显示大小”提供标准、稍大、大字三档，自动记住选择。默认正文 16px，辅助文字 14px。
- 自动启动本地服务和两个后台任务执行器。沿用项目目录中的 `.env`、数据库、附件和备份配置。
- 关闭窗口时先请求服务正常退出，等待后台任务清理；未完成任务沿用现有恢复机制。
- 如果启动前已经有工作台服务运行，窗口会复用该服务，关闭时不会停止它。已有服务的进程不会因关闭桌面窗口而终止。
- 桌面进程意外终止时，后台通过父进程句柄检测退出并清理；不会根据缓存 PID 杀死其他进程。
- 只绑定本机 `127.0.0.1:8000`。端口被其他服务占用会显示启动失败，不替换其他服务。

## 文件与环境

需要 Python 3.11+、Windows .NET Framework 4.8 和 Microsoft Edge WebView2 Runtime。干净发布包首次启动自动创建本机虚拟环境并联网安装依赖。三个 WebView2 DLL 与 EXE 必须放在同一目录，不要单独移动 EXE。

Microsoft.Web.WebView2 SDK：1.0.3650.58，来自微软 NuGet 包。授权文件保留在 `launcher/webview2/sdk/LICENSE.txt`（以包内实际文件为准）。WebView2 用户配置存在 `.runtime/desktop-profile`，显示偏好存在窗口的本地存储中，日志是 `.runtime/desktop.log`。

旧浏览器启动器继续保留。托盘和系统任务通知尚未添加。

## 构建与验证

`powershell -NoProfile -ExecutionPolicy Bypass -File launcher/build-desktop.ps1`

`python scripts/qa_desktop.py` 使用临时数据库、模拟 AI 和独立端口，检查原生页面加载、字号切换、正常关闭、复用服务和父进程退出清理。测试不会读取正式数据库或启动外部扫描。
