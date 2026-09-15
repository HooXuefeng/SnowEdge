# SnowEdge 第三方组件声明

SnowEdge 项目自身代码采用 [GPL-3.0-or-later](LICENSE)。下列第三方组件不因包含在源码、构建流程或发布包中而改用 SnowEdge 的许可证。

| 类别 | 组件 | 使用方式 | 许可证依据 |
| --- | --- | --- | --- |
| 桌面运行时 | Microsoft Edge WebView2 Runtime / SDK | Windows 独立窗口与随包运行库 | 发布包同时保留 `licenses/Microsoft.WebView2.LICENSE.txt` 和 `licenses/Microsoft.WebView2.NOTICE.txt` |
| Python 依赖 | FastAPI、Starlette、Uvicorn、SQLAlchemy、Pydantic、Jinja2、httpx、Cryptography、Alembic、python-docx、Pillow 等 | 首次启动时由包管理器安装 | 以安装版本的包元数据、上游仓库及许可证文件为准 |
| 浏览器组件 | Playwright、Chromium/WebView2 | 浏览器观察、PDF 预览与桌面承载 | 以对应上游发行包所附许可证为准 |
| Burp 联动 | Burp Suite Extender API | 用户自行安装 Burp 后加载 SnowEdge 扩展 | Burp Suite 与 API 由 PortSwigger 按其条款提供 |
| 外部安全工具 | Nmap、Subfinder、Naabu、httpx、Katana、Nuclei | 用户独立安装；SnowEdge 只调用可执行文件并解析结果 | 各工具保持各自上游许可证；SnowEdge 发布包不分发这些可执行文件 |

依赖名称不表示相关权利人对 SnowEdge 的认可。重新发布 SnowEdge 时，请同时保留项目 `LICENSE`、本文件以及发布包 `licenses/` 中随附的第三方许可和声明。
