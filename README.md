# SnowEdge

<p align="center"><img src="app/static/brand/snowedge-app.png" width="96" alt="SnowEdge"></p>

<p align="center"><strong>资产发现 · 请求测试 · Evidence · AI 研判 · 报告交付</strong></p>

面向个人授权安全评估的工作台，集中管理资产、请求测试、漏洞、证据与报告，并提供 AI 辅助研判。

**当前版本：1.7.2 · by SnowPeak**

## 数据分析与界面更新

新增 Hash 多候选识别、MD5/SHA/NTLM 本地字典匹配、可取消任务与自定义字典。编码递归遇 Hash 时停止；联网默认关闭。统一部分遗留黑色组件并修复窄屏导航。详见 [Hash 分析说明](docs/HASH_ANALYSIS.md)。

## 工作流程

```mermaid
flowchart LR
    A[创建项目与授权范围] --> B[导入或发现资产]
    B --> C[扫描与浏览器观察]
    C --> D[请求及权限测试]
    D --> E[Finding 与 Evidence]
    E --> F[AI 辅助研判]
    F --> G[复测与正式报告]
```

## 能力地图

```mermaid
mindmap
  root((SnowEdge))
    资产与扫描
      端口和服务
      HTTP 与指纹
      子域名和 API
    手工测试
      请求重放
      身份差异
      权限验证
    漏洞闭环
      Finding
      Evidence
      复测
    AI 辅助
      证据研判
      标题与风险建议
      报告草稿
    交付
      A4 预览
      PDF 和 DOCX
      JSON 和 CSV
```

## 主要功能

- 项目与授权范围管理、资产整理、全局和项目代理。
- 扫描中心：TCP 端口探测、服务识别、HTTP 探测、Web 指纹、目录与 JS/API 发现、子域名发现；持久化任务、暂停、恢复与重试。
- 请求工作台：请求编辑、重放、版本与草稿、Burp 导入、身份和权限测试。
- 漏洞工作流：手工新建、编辑、风险分类、证据关联与人工复测。
- AI 辅助：结合项目、请求、证据和漏洞进行研判，提供引用及后续工具入口。
- 报告：正式 A4 分页预览、PDF/HTML/JSON/CSV/DOCX 导出，完整 Finding 与 Evidence 编排、AI 草稿、复测和固定交付版本；保留旧版 Markdown / txb02。详见 [报告交付说明](docs/REPORT_DELIVERY.md)。
- 实用工具：网络诊断、编码识别及多层解码、JSON、JWT 等。
- Windows 独立窗口：自动管理本地服务，支持字号和窗口缩放。

## 能力边界

内置引擎用于资产探测和安全评估，不承诺替代 Nmap、Nuclei 或 Burp。
Nuclei 兼容范围为部分 HTTP 模板；凭据检查主要为单组 HTTP Basic 验证；OOB 为自托管 HTTP 回连。
测绘服务需要自行配置账户和密钥。AI 默认使用演示模式，真实研判需要配置服务；结论应人工验证。
详见 [扫描中心](docs/SCAN_CENTER.md)。

## 从源码运行

需要 Python 3.11+。以下命令在仓库根目录执行。

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python scripts/db-upgrade.py
python run.py
```

打开 http://127.0.0.1:8000 。Linux/macOS 激活环境时使用 `source .venv/bin/activate`。
需要持久化队列后台处理时，在第二个已激活环境的终端运行 `python worker.py`。
浏览器观察能力还需要执行 `python -m playwright install chromium`。

可复制 `.env.example` 为本地 `.env`，按需配置 AI 等服务。首次启动自动生成并保存独立密钥；请妥善备份 `.runtime/app-secret`。
已有用户保留原 `.env`、密钥、数据库和附件；不要用示例配置覆盖现有配置。

## Windows 桌面构建

源码不包含 EXE、DLL 或 WebView2 SDK。准备 Windows x64、.NET Framework 编译器和 WebView2 Runtime。
将 Microsoft.Web.WebView2 NuGet 包解压至 `launcher/webview2/sdk`，确认存在 `lib/net462` 与 `runtimes/win-x64/native`，然后运行：

```powershell
.\launcher\build-desktop.ps1
```

生成后双击根目录 `SnowEdge.exe`。桌面使用与进程管理见 [桌面说明](docs/DESKTOP.md)。

## Burp 扩展与发布包

扩展源码位于 `integrations/burp-extension`，使用 JDK 与 Gradle 构建：

```powershell
cd integrations/burp-extension
gradle jar
```

构建产物位于 `build/libs`。发布构建及扩展打包测试使用 `integrations/burp-extension/dist/SnowEdge-Burp-1.0.0.jar`，请将生成的 JAR 复制到该位置。
在完成桌面和扩展构建后，从仓库根目录执行 `python scripts/build-release.py` 生成干净的 Windows 发布 ZIP。

## 开发与反馈

```powershell
python -m pytest -q
```

测试使用临时数据库。桌面及浏览器端到端验证需要额外运行环境；未构建桌面 EXE 或 Burp JAR 时跳过对应二进制检查。
请参阅 [参与开发](CONTRIBUTING.md)、[安全反馈](SECURITY.md) 和 [版本记录](CHANGELOG.md)。
Docker 部署见 [部署说明](docs/DEPLOY_WEB_WORKER_POSTGRES.md)。

## 版权与依赖

Copyright © 2026 SnowPeak。当前尚未指定开源许可证；公开源码不等于授予开源许可。
第三方依赖与引用资料遵循各自许可证。仅在获得授权的范围内使用本项目。
