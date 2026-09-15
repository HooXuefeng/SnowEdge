# Changelog

<p align="center"><img src="app/static/brand/snowedge-app.png" width="96" alt="SnowEdge"></p>

## V1.8.1 — 工具链流程编排

- 正式采用 GPL-3.0-or-later 开源许可证，补充第三方组件与外部工具授权说明。
- 一键流程改为持久化 ToolchainRun / ToolchainStep，步骤按依赖顺序执行。
- Subfinder 资产、Naabu 端口、httpx 与 Katana URL 会自动传递给下一步适配器。
- 流程页面展示整链状态、当前步骤、分步统计和失败原因，并支持失败步骤重试。
- 每一步最多接收 100 个去重目标，传递 URL 会移除查询参数与片段，避免敏感值进入任务载荷。
- “工具链”收入口径并入“扫描与工具链”，减少一级导航概念重叠。
- 被动导入支持 SnowLens 联动包，将前端暴露信号映射为候选 Finding 与脱敏 Evidence。
## V1.8.0 — 统一工具链基础

- 新增项目级工具链页面，检测 Nmap、Subfinder、Naabu、httpx、Katana 和 Nuclei 的安装路径与版本。
- 支持保存各工具的自定义可执行文件路径，不在 SnowEdge 包内重复分发第三方二进制。
- 新增受控外部工具 Job 类型，复用持久化队列、并发资源门、超时、取消、失败重试和 Scope 快照。
- 工具执行只接受目标和端口，参数由适配器白名单生成，不开放任意命令行输入。
- 增加 Nmap XML 与 ProjectDiscovery JSONL 解析，将结果写入现有 Asset、Service、Endpoint、Finding 和 Evidence 链路。
- 工具标准输出限制为 8 MB，并对 Evidence 进行凭据脱敏和完整性哈希。
- 提供基础设施识别、Web 深度评估、外部资产发现和单目标综合评估四种一键流程；缺失工具会明确跳过。

## 报告交付升级 - 2026-09-13

- 扩展现有 Finding、Evidence 与固定交付快照，加入完整漏洞章节、HTTP 关联、证据编排、AI 引用草稿和复测时间线。
- 报告中心改为正式交付入口，支持五种模板、漏洞排序、A4 浅色分页预览、缩放与页码跳转。
- 真实导出 PDF、HTML、JSON、CSV 和 DOCX；加入中文排版、风险图表、目录、页眉页脚和截图图注。
- 请求回放保存当次 HTTP 展示记录；历史缺失信息明确标记，脱敏与原数据保护保持生效。
- 保留历史分析报告、旧快照、Markdown 与 txb02 Word 兼容入口。新增 pypdfium2 预览依赖。
- 操作方式、证据边界、导出依赖与验收说明见 docs/REPORT_DELIVERY.md。

## Workspace update - 2026-09-12

- Added a scan center sharing the persistent job queue, with pause/resume, retries, TCP/HTTP discovery, fingerprint-driven checks and linked evidence/findings.
- Added scoped directory, JavaScript/API and DNS prefix discovery with soft-error-page and wildcard-DNS handling.
- Added a validated Nuclei HTTP subset, declarative custom rules, self-hosted HTTP OOB callbacks, and supplied HTTPS Basic credential checks.
- Added encrypted FOFA/Hunter/Quake/Shodan configuration and query adapters; real-account integration remains unverified.
- Added global proxy inheritance and HTTP CONNECT/SOCKS5 scan transport, without silent direct fallback.
- Added a separate automatic decoder and scan-evidence citations in the AI assistant.
- Documented supported protocols, limits and configuration in `docs/SCAN_CENTER.md`.

## 1.6.3 - 2026-09-09

- Reorganized the left navigation into Chinese workflow groups and added persistent collapse state.
- Added project-home “继续测试” cards for Request drafts, Candidate Findings, retest-ready Findings, authorization gaps and active jobs.
- Added a unified right-side Inspector for Endpoint and Finding context actions.
- Upgraded Data Grid with quick-filter chips, keyboard navigation, column visibility, CSV export and saved views.
- Made Coverage 2.0 directly actionable by linking each workflow gap to the corresponding workspace.
- Upgraded Ctrl+K from search-only to a Chinese command palette with workspace navigation/actions.
- Added Request Workspace keyboard navigation: Ctrl+Enter, Ctrl+S and Alt+1..4.
- Localized high-frequency Dashboard, Browser, Identity, Skills, Jobs, Reports, Remediation and Asset Intelligence UI copy.
- Added Chinese V1.6.3 UI regression suite: **8 passed**.
- Fixed Chinese project-name ZIP/DOCX downloads using an ASCII fallback plus UTF-8 `filename*` Content-Disposition.
- V1.6.3 clean release smoke: **PASS**.
- Full grouped historical regression: **134 passed**.
- Chromium UI QA: nine representative pages at 1440x1000, plus 1920x1080 and Windows 125%-style logical widths, with no horizontal overflow.
- No database migration was required; Alembic remains `v1_6_2_assetux` and sanitized export schema remains `ai-pentest-workspace-project/1.6.2`.

## 1.6.2 - 2026-09-09

- Added Asset Intelligence workspace inspired by TscanPlus-style result-to-next-step UX while preserving Workspace safety boundaries.
- Added deterministic Fingerprint Engine 2.0 for Web server, framework, runtime, frontend, CMS, middleware, WAF and security-edge metadata.
- Added constrained custom fingerprint rules using case-insensitive substring matching only.
- Added confidence/evidence/first-seen/last-seen metadata and safe WAF-aware recommendations.
- Added Endpoint Context Actions for Request Workspace, Browser Observe, redacted URL copy and fingerprint review.
- Added Unified Data Grid behavior: filter, sort, multi-select, CSV export and Saved View.
- Added Scan Profiles that capture/apply existing built-in ProjectSkill selections.
- Added Batch Assessment with per-target Scope validation, out-of-scope skip audit and serialized safe execution.
- Added Job Engine resource classes for scan/browser/AI/validation/local workload gating.
- Added Network Route Profiles for Direct, HTTP proxy, SOCKS5 and Burp.
- Route passwords are encrypted; UI and sanitized exports omit them.
- HTTP Probe, Web Discovery, Request Replay and Browser Workspace now consume the selected project route.
- Added real local HTTP-proxy replay regression to verify Network Route Profiles are consumed by Request Workspace runtime, not only rendered in configuration UI.
- Fingerprint evidence summaries now redact sensitive URL query values before persistence.
- Batch execution re-applies its bound Scan Profile at execution time so queued/recovered batches cannot silently inherit unrelated ProjectSkill changes.
- Port reconnaissance safely skips when a non-Direct route is selected instead of silently falling back to direct TCP/Nmap.
- Added V1.6.2 Alembic migration `v1_6_2_assetux`.
- Sanitized project export schema advanced to `ai-pentest-workspace-project/1.6.2`, retaining V1.2–V1.6 import compatibility.
- V1.6.2-specific regression tests: **9 passed**.
- Full historical regression suite: **126 passed**.

## 1.6.0 - 2026-09-09

- Added native Windows x64 GUI `SnowEdge.exe` built as a real PE32+ executable.
- Added hidden personal Supervisor for Web/Worker lifecycle, logs, status and stop signaling.
- Launcher/Supervisor performs pending restore before Alembic migration and service startup.
- Added AES-256-GCM + scrypt Encrypted Full Backup (`.aipwbak`) for the personal SQLite workspace.
- Full Backup includes consistent SQLite snapshot, Evidence artifacts, Browser artifacts and the APP_SECRET_KEY needed to decrypt restored Vault/Identity data.
- Backup password is never stored in BackupRecord; staged restore password is encrypted with the current APP_SECRET_KEY.
- Added cross-install artifact path rebasing for EvidenceAttachment and BrowserArtifact during full restore.
- Added pre-restore SQLite `.pre_restore` safety copy.
- Added Personal Secret Vault with project/global scope, expiry, last-used tracking, rotation, disable and logical purge.
- Added HTTP Identity Vault integration into Request Replay and Browser Workspace runtime identity material.
- Added encrypted Request Workspace drafts and automatic browser-independent autosave/recovery.
- Added Crash Recovery Center for persistent jobs, orphaned browser/task state and encrypted drafts.
- Added Ctrl+K global search across Project, Endpoint, Request, Revision, Finding, Evidence metadata, Identity, Browser and Task.
- Global search redacts sensitive query parameters and never returns Evidence content or Vault values.
- Added V1.6 Alembic migration `v1_6_reliability`.
- Sanitized project export schema advanced to `ai-pentest-workspace-project/1.6`, retaining V1.2–V1.5 import compatibility.
- V1.6-specific regression tests: **8 passed**.
- Full historical regression suite: **117 passed**.
- Real Supervisor Web + Worker start/stop E2E: **PASS**.
- Cross-install Encrypted Full Backup restore E2E: **PASS**.
- V1.6 Chromium visual QA: **7/7 pages with no horizontal overflow**.
- Windows Launcher runtime itself is not claimed as executed because the hosted release environment is Linux and has no Wine; PE32+ x64 compilation/structure checks passed.

## 1.5.0 - 2026-09-09

- Added Burp right-click integration source and prebuilt `SnowEdge-Burp-1.0.0.jar`.
- Burp ingestion requires encrypted local Integration Token and current Project Scope validation.
- Setup UI now exposes and persists the encrypted Burp Integration Token.
- Burp integration stores requests only; it never replays or launches scans.
- Added Request Workspace 2.0 with Raw, structured edit, Pretty JSON, response view and revision history.
- Added `StoredRequestRevision`; creation, editing and restore operations are auditable.
- State-changing methods remain STATE_CHANGE after editing unless the analyst explicitly uses the existing manual READ_ONLY override.
- Added Finding Quality Gate with 0–100 quality score and A/B/C/D grade.
- Added AI-only quality penalty when model output lacks deterministic evidence.
- Added Report Preflight for Candidate, low-quality, missing screenshot/request/response and Needs Review findings.
- Added Coverage 2.0 personal workflow dimensions for endpoint/request, parameters, identities, authorization, Browser, Evidence, screenshots, Proof and Retest.
- Added non-destructive screenshot annotation: box, arrow, redact, caption and ordering.
- Fixed signed left/up arrow annotation vectors and preserved V1.4 screenshot compatibility for Pillow-strict legacy PNGs.
- Original screenshot Evidence bytes remain unchanged; annotated images are rendered only for delivery output.
- txb02 Word export now applies screenshot annotations and explicit screenshot ordering.
- Added Browser Workspace 2.0 runtime model: route timeline, DOM SHA256/diff, WebSocket metadata, Storage keys, Cookie attributes and CSP observations.
- Browser Workspace 2.0 never persists Storage values, Cookie values or WebSocket payloads.
- Added V1.5 Alembic migration `v1_5_workflow2`.
- Sanitized project export schema advanced to `ai-pentest-workspace-project/1.5` with safe revision/annotation metadata.
- V1.5-specific regression suite: **10 passed**.
- Full regression suite after V1.5 integration: **109 passed**.
- Hosted Chromium real-navigation Browser 2.0 E2E is not claimed because the environment returns `ERR_BLOCKED_BY_ADMINISTRATOR`.

## 1.4.0 - 2026-09-09

- Repositioned the product around single-user pentest productivity instead of team/RBAC expansion.
- Added `START_PERSONAL.bat` one-click Windows launcher.
- Added first-run/personal settings wizard with encrypted AI API-key storage.
- Personal AI Provider/Base/Model/API Key and Browser/Nmap path overrides now affect actual runtime selection.
- Added five real ProjectSkill-backed personal project templates.
- Added global Quick Scan with exact-host Scope and the existing safe `project_scan` workflow.
- Added HAR, Postman Collection and OpenAPI/Swagger JSON/YAML passive import.
- Imported non-GET/HEAD requests remain `STATE_CHANGE` and are never automatically replayed.
- Added OpenAPI Path/Query/Header/Body parameter modeling and `required` preservation.
- Added deterministic “next best test” hints and one-click evidence-bound Copilot prioritization.
- Added Authorization Matrix 2.0 historical before/after comparison without new network requests.
- Added screenshot Evidence upload with MIME/magic validation, binary artifact storage and SHA256.
- txb02 Word now embeds Finding screenshots with figure captions and SHA256.
- Added automatic/manual sanitized project backups with SHA256 and per-project retention.
- Added local system diagnostics.
- Added user-visible URL secret redaction while retaining raw StoredRequest data only for explicit authorized replay.
- Sanitized project schema upgraded to `ai-pentest-workspace-project/1.4` with V1.2/V1.3 backward-compatible import.
- Added V1.4 Alembic migration and sparse-legacy migration hardening.
- V1.4-specific regression: **10 passed**; full regression: **99 passed**.
- Final Chromium QA: **9/9** representative pages at 1440×1000 with no page-level horizontal overflow.
- Final txb02 DOCX QA: **2 pages**, no clipping, overlap, missing glyphs or empty trailing page.
- Final clean-release smoke passed: setup/diagnostics/Quick Scan creation, OpenAPI import, redaction, screenshot Evidence, txb02 DOCX, project export, backup and dedicated Worker lifecycle.

## 1.3.0 - 2026-09-09

- Added dedicated `worker.py` runtime and Windows `start-worker.bat` / `start-all.bat`.
- Web startup no longer requires embedded workers; `JOB_EMBEDDED_WORKERS=0` is supported as the V1.3 separation mode.
- Added persistent `JobWorker` registry with hostname, PID, capabilities, active job and heartbeat state.
- Added job `worker_id`, lease token, heartbeat and lease-expiration metadata.
- Added lease-aware orphan recovery: only expired jobs are recovered; a Web restart does not steal an active worker lease.
- Added graceful SIGINT/SIGTERM worker shutdown and offline state update.
- Added atomic `queued → running` compare-and-swap claim for SQLite to prevent Web/Worker duplicate execution races.
- PostgreSQL claim path uses `FOR UPDATE SKIP LOCKED`.
- Added `Evidence.content_sha256`, `integrity_sha256`, capture metadata and `EvidenceProvenance`.
- Added automatic Job → Evidence provenance attachment for evidence created during a persistent job.
- Added persistence-time secret redaction for normal Finding / Task Evidence, including real and serialized HTTP newline forms.
- Added independent Finding confirmation, remediation and verification states plus reopened counter.
- Added txb02-oriented Chinese Word report export with Evidence SHA-256 references and secret redaction.
- Added passive Burp XML, Nmap XML and Nuclei JSONL import workspace.
- Passive imports execute no scanners or external commands and filter imported targets through current Project Scope.
- Added import audit models `ImportBatch` and `ImportRecord`.
- Added PostgreSQL driver dependency, Dockerfile and Docker Compose Web + Worker + PostgreSQL profile.
- Docker Compose now requires explicit `POSTGRES_PASSWORD`, `DATABASE_URL` and `APP_SECRET_KEY`; no default production credentials are embedded.
- Sanitized project export schema upgraded to `ai-pentest-workspace-project/1.3`.
- V1.3 import remains backward-compatible with V1.2 sanitized packages.
- Added V1.3 Worker, Evidence Chain, Finding state, passive import and txb02 report UI.
- V1.3 representative Chromium QA: 5 pages at 1440×1000, no page-level horizontal overflow.
- Dedicated Worker real-process E2E passed: queue claim → execute → done → graceful SIGTERM → worker offline.
- Word report rendered and visually inspected across all generated pages.
- V1.3-specific regression suite: **8 passed**.
- Full regression suite: **89 passed**.
- PostgreSQL/Docker profile is code/deployment-ready; live PostgreSQL service E2E was not claimed in the hosted QA environment.

## 1.2.1 - 2026-09-09

- Reworked global UI scale for readability at common Windows/Chromium 100% display scaling.
- Raised base UI text from the previous dense-console scale to 15px.
- Increased project navigation to 13px and data-table rows to 13px.
- Increased primary page titles to 28px and panel headings to 14px.
- Increased buttons, form controls, status chips, activity rows and evidence/code views.
- Increased Endpoint Parameter table content to 11.5px while preserving dense technical layout.
- Widened the workspace shell: navigation rail, project sidebar and main content spacing.
- Increased topbar height and search/control hit areas.
- Added clearer visual separation between sidebar navigation sections.
- Sidebar now scrolls independently on smaller-height displays instead of clipping lower navigation items.
- Increased panel spacing, metric-card height, table row height and card padding to reduce visual crowding.
- Added responsive layout adjustments for 1320px, 1080px and 820px breakpoints.
- Preserved horizontal fit at a 1440px QA viewport for Job Center, Endpoint Inventory, Findings and Project Settings.
- Representative Chromium QA computed:
  - body text: 15px
  - sidebar navigation: 13px
  - dense table rows: 13px
  - endpoint parameter rows: 11.5px
  - no horizontal page overflow at 1440px
- Full regression suite remains **81 passed**.

## 1.2.0 - 2026-09-08

- Added persistent database-backed Job Engine for project scans, Browser observation, Analyst Copilot, Specialist Agent Team, Proof Capsule retest, Authorization Matrix, endpoint sync and intelligence refresh.
- Added Job Center with queued/running/retry/cancel/done/error states, append-only events, priority, timeout, retry and manual retry.
- Added restart recovery for orphaned running jobs.
- Added immutable-at-creation Scope Snapshot JSON and SHA-256 Scope Hash for each persistent job.
- Current Scope is still revalidated before network-backed execution.
- Added reference-only persistent job payload contract that rejects obvious secret-bearing fields and request bodies.
- Added Alembic migration framework with V1.1 legacy baseline and V1.2 core migration.
- Added safe adoption of structurally-current databases when Alembic metadata is missing or stale.
- Added project engagement metadata: client, environment, engagement type, lifecycle status, dates, testers and authorization note.
- Added endpoint normalization and fingerprinting.
- Added `EndpointParameter` inventory for Query/Header/Body observations.
- Added nested JSON sensitive-field detection and redacted parameter examples.
- Added Authorization Matrix over explicitly selected identities and optional Anonymous comparison.
- Authorization Matrix is limited to READ_ONLY GET/HEAD, maximum six comparison identities and no automatic object-ID enumeration.
- Added Finding canonical fingerprinting and cross-source deduplication.
- Added `FindingOccurrence` so duplicate observations preserve provenance/evidence.
- Added Finding taxonomy fields for vulnerability type, parameter, CWE, OWASP and txb02 category.
- Added sanitized Project Export / Import ZIP workflow.
- Sanitized export excludes identity credentials, secret headers, request bodies, raw evidence, screenshots, remediation-note bodies and sensitive URL query values.
- Imported identities do not regain credentials; imported requests do not regain secret headers or bodies.
- Added Chinese core navigation and Chinese product views for Job Center, Authorization Matrix, Endpoint Parameter Inventory, Finding taxonomy and Project Settings.
- Core legacy regression suite remains passing.
- Added 7 V1.2-specific tests covering Job recovery/scope snapshots, nested parameter redaction, cross-source Finding dedupe, Authorization Matrix boundaries, sanitized portability, V1.1→V1.2 Alembic upgrade and Chinese core UI.
- Full suite: **81 passing tests**.

## 1.1.0 - 2026-09-08

- Added deterministic weighted Coverage Matrix across 15 assessment domains.
- Added persistent `CoverageSnapshot` history with score, covered/partial/gap/review counts and prioritized gaps.
- Added dedicated Coverage Matrix workspace and navigation.
- Added analysis-only Analyst Copilot over redacted Knowledge Graph, Assessment Memory and Coverage Matrix.
- Added persistent `CopilotQuery` history and background query execution.
- Added deterministic lexical retrieval before AI Copilot review.
- Added server-side citation allowlisting for `kg:*`, `mem:*` and `coverage:*` references.
- Added Copilot citation links back to project evidence views.
- Added Copilot intent-drift blocking for tool requests, commands, shell, payloads, invalid citations and invalid view links.
- Added persistent `FindingLifecycle` and `RemediationEvent` models.
- Added Remediation Board with open, triaged, remediation, retest-ready, resolved, accepted-risk and false-positive workflow states.
- Added Finding owner, priority, remediation note, Proof Capsule link and latest RetestRun tracking.
- Added background Proof Capsule retest queue from Remediation Board.
- `reproduced` retests return workflow to remediation.
- `resolved` retests close the workflow.
- unsupported deterministic verification remains `needs_review`; no automatic resolution is fabricated.
- Added `Finding → TRACKED_BY_WORKFLOW → FindingLifecycle` Knowledge Graph relation.
- Added latest Coverage Snapshot node to Knowledge Graph.
- Added remediation state to Assessment Memory.
- Raw remediation notes are excluded from canonical Knowledge Graph and Memory context.
- Coverage and remediation summaries added to Report Preview, Markdown and HTML exports.
- Finding Detail now links to the Remediation workflow and displays workflow status/owner.
- Project Overview now links Coverage, Copilot and Remediation into the operational workflow.
- Added 5 V1.1 regression tests covering coverage progression, Copilot secret isolation/drift, deterministic remediation retest, manual-review behavior and route/report integration.
- Full regression suite expanded to 74 passing tests.
- Replaced deprecated `datetime.utcnow()` usage with SQLite-compatible naive UTC timestamps derived from timezone-aware UTC values.
- Final full regression run completes with no project-owned deprecation warnings.

## 1.0.0 - 2026-09-08

- Added deterministic redacted Knowledge Graph.
- Added persistent `KnowledgeNode` and `KnowledgeEdge` models.
- Added graph relationships across assets, services, endpoints, web artifacts, routes, browser observations, stored requests, identities, authorization cases, findings, evidence, proof, plans and execution history.
- Added server-side Knowledge Graph relationship API and node neighborhood inspector.
- Added browser-safe SVG Knowledge Graph visualization without external graph dependencies.
- Knowledge Graph excludes Identity secrets, StoredRequest bodies and raw Evidence content.
- Added sensitive query-parameter redaction before URL-like values enter Knowledge Graph or Assessment Memory.
- Added persistent structured Assessment Memory with deterministic fingerprints.
- Added memory derivation from Authorization Cases, Proof Capsules, Browser Sessions, Response Diffs, Findings and repeatable coverage Tasks.
- Added repeat guidance states including `avoid_repeat`, `avoid_repeat_recent`, `confirm_or_retest`, `retest_after_fix` and `review`.
- Assessment Memory refresh is idempotent for derived memories.
- Added Memory-aware Skill Planner priority adjustment and visible memory notes.
- Added persistent `SpecialistAgentRun` and `AgentHandoff` models.
- Added six fixed analysis-only specialists: Planner, Recon Analyst, Web Analyst, Authorization Analyst, Evidence Reviewer and Reporter.
- Added per-role Intent Contracts with Scope, allowed Skills/capabilities, visible graph/memory types, allowed handoffs, risk ceiling and default deny.
- Added server-side Intent Drift Guard for unexpected tool requests, commands, payloads and invalid handoffs.
- Added background Specialist Team execution and status polling.
- Added Agent Team roster, specialist outputs, Intent Contracts, handoffs and drift visualization.
- Added automatic Knowledge Graph / Memory refresh after project assessment, Browser Session, Authorization Case, Response Diff and Proof Capsule retest.
- Fixed V0.9 project statistics omission for Browser Session/Event/Artifact counts.
- Added unified project statistics for Knowledge nodes/edges, memories, specialist runs and handoffs.
- Added Intelligence Layer strip to Project Overview and Agent Team link from Mission Control.
- Added Knowledge Graph / Memory / Specialist Agent sections to Report Preview, Markdown and HTML exports.
- Added explicit regression that Knowledge Graph and Memory never expose encrypted identity secrets, StoredRequest body content, raw Evidence content or sensitive query tokens.
- Added malicious-specialist regression proving arbitrary tool requests and invalid handoffs are discarded and counted as drift.
- Regression suite expanded to 69 passing tests before final release QA.

## 0.9.0 - 2026-09-08

- Added observe-only Playwright Browser Workspace.
- Added persistent `BrowserSession`, `BrowserEvent` and `BrowserArtifact` models.
- Added optional project Identity context for browser observation.
- Added strict Scope routing before every HTTP(S) browser request.
- Added automatic abort and audit event for out-of-scope page resources, redirects, CDN and analytics requests.
- Added Network request/response timeline.
- Added XHR / Fetch classification.
- Added console-message observation.
- Added DOM form, external script and link metadata extraction.
- Added bounded DOM snapshot artifact.
- Added full-page screenshot artifact and protected artifact-serving route.
- Added Browser Event inspector with protected header redaction.
- Added one-click Browser Event → Request Workspace handoff without replay.
- Preserved GET/HEAD as READ_ONLY and POST/other methods as STATE_CHANGE.
- Added Browser GET/HEAD → Authorization Lab handoff with request preselection.
- Added Browser Event → Evidence promotion.
- Added Browser Session status polling and responsive Browser Workspace UI.
- Added `browser_observe` and `browser_event_evidence` read-only policy actions.
- Added `Browser Observation Workspace` MANUAL_WORKSPACE Skill.
- Integrated Browser Skill into Skill Hub, AI Skill Planner and Execution Graph.
- Browser plan nodes remain `manual_ready` until an analyst explicitly starts a session.
- Added Playwright dependency plus optional Chromium install scripts.
- Added configurable browser headless mode, navigation timeout, post-load wait and artifact directory.
- Added browser artifact directory to `.gitignore`.
- Added regression coverage for Scope blocking, secret redaction, Request/Authz handoffs, method policy preservation, evidence promotion and manual Skill semantics.
- Regression suite expanded to 62 passing tests.
- Hosted real-browser smoke reached Chromium navigation but was blocked by the execution environment with `ERR_BLOCKED_BY_ADMINISTRATOR`; this is recorded as an environment limitation rather than a Browser PASS.

## 0.8.0 - 2026-09-08

- Added persistent Execution Graph nodes for every generated Skill Plan.
- Added deterministic Skill stage and dependency mapping.
- Added graph statuses: planned, approved, manual_ready, running, done, error, skipped and disabled.
- Approval now updates the exact graph node selection.
- Approved plan execution synchronizes graph nodes from actual `SkillRun` records.
- Added dedicated Execution Graph workspace and navigation.
- Added persistent `ProofCapsule` and `RetestRun` models.
- Added Finding Proof Capsule UI with verification contract, expected signal, latest observed signal and retest history.
- Added deterministic `http_header_absence` verifier.
- Added deterministic `http_header_presence` verifier.
- Added read-only `authorization_case_replay` verifier for Findings linked to existing Authorization Cases.
- Unsupported finding types use `evidence_snapshot` and remain `needs_review`; the system does not fabricate automatic proof.
- Every Proof Capsule network retest revalidates the current project Scope Engine.
- Every retest appends a linked `proof_capsule_retest` Evidence record.
- Added `reproduced`, `resolved`, `needs_review` and `error` verification states.
- Report Preview now includes Execution Graph and Finding Verification summaries.
- Markdown/HTML exports now include per-Finding verification state and graph status summary.
- Added post-execution graph synchronization regression coverage.
- Added real local HTTP fixture test proving `missing header → reproduced → fixed header → resolved`.
- Regression suite expanded to 51 passing tests.

## 0.7.0 - 2026-09-08

- Added evidence-aware AI Skill Planner.
- Added persistent `SkillPlan` model with draft / approved / queued / running / executed / error lifecycle.
- Added deterministic workspace evidence profiling for assets, services, endpoints, web artifacts, route candidates, requests, replays, identities, authorization cases, and findings.
- Added deterministic Skill shortlist generation before any AI recommendation.
- Added OpenAI-compatible Skill recommendation prompt that can select only from caller-supplied built-in Skill slugs.
- Added Mock provider Skill recommendation so the complete planner works without an API key.
- Added strict server-side filtering of model-returned Skill slugs against the built-in allowlisted catalog.
- Added AI priority and rationale merging with deterministic recommendations.
- Added dedicated AI Skill Planner UI.
- Added target-aware plan generation with Scope Engine validation.
- Added human checkbox review before approval.
- Approval now applies the exact selected built-in Skill profile.
- External imported Skills are never silently enabled by an AI plan.
- Added separate explicit execution step after approval.
- Approved plan execution revalidates scope and reapplies the exact approved Skill selection.
- Plan execution continues through the existing Task → Scope/Policy → SkillRun → Evidence → AgentRun pipeline.
- MANUAL_WORKSPACE Skills remain manual and are never silently executed by plan approval.
- Fixed `/skills/planner` static route collision with dynamic Skill detail routing.
- Expanded regression suite to 45 passing tests.
- Added local end-to-end validation that an approved Web-only plan executes HTTP/Web discovery while skipping disabled port reconnaissance.

## 0.6.0 - 2026-09-08

- Added project-scoped Skill Hub.
- Added `SkillDefinition`, `ProjectSkill`, and `SkillRun` persistence.
- Added 10 built-in AI pentest methodology Skills under `skills/builtin/*/SKILL.md`.
- Added selectable Skill execution modes:
  - DETERMINISTIC
  - AI_ANALYSIS
  - LOCAL_ANALYSIS
  - MANUAL_WORKSPACE
  - KNOWLEDGE_ONLY
- Added deterministic Skill → capability routing.
- Converted the main assessment workflow from a fixed pipeline to selected-Skill-driven execution.
- Disabled capability stages are now genuinely skipped instead of merely hidden in the UI.
- Added independent Skill Run audit history.
- Added `skill_start` / `skill_result` Agent Events.
- Added Skill execution trace to AI Mission Control.
- Added active Skill chips and dynamic capability pipeline to Project Overview.
- Added four Skill Packs:
  - Analysis Only
  - Passive Web / API
  - Web + Authorization
  - Full Safe Workspace
- Added safe external `SKILL.md` import.
- External Skills are always `KNOWLEDGE_ONLY`.
- External Skills always receive zero executable capabilities.
- Added restricted-content labeling for high-risk and prompt-injection markers.
- Added `http/https`-only provenance URL validation.
- Added explicit prompt-injection boundary for third-party Skill methodology sent to AI.
- Added selected Skill methodology context to bounded AI evidence review.
- Added Pentest Coverage Judge local-analysis Skill.
- Added Agent Tool Guardrails local-analysis Skill.
- Added enabled Skill profile to Markdown/HTML reports for reproducibility.
- Added Skill Hub GitHub reference panel for AboutSecurity, community Cybersecurity Skills, CAI, PentestGPT, and AI Pentest Agent Skill.
- Added Skill architecture documentation and source notes.
- Added Skill Pack, import safety, capability gating, report, UI, and end-to-end regression tests.
- Final regression suite: 40 passed.
- Added Chromium visual QA for Skill Hub, Project Overview, and Mission Control.


## 0.5.0 - 2026-09-08

- Added Authorization Lab.
- Added unauthenticated differential authorization testing.
- Added horizontal / object-level authorization comparison.
- Added vertical / role-level authorization comparison.
- Added explicit expected-resource-owner input for horizontal cases.
- Added `AuthorizationCase` persistence.
- Added deterministic authorization classifier.
- Added 401/403 positive-control recognition.
- Added status, length, similarity and JSON structural authorization signals.
- Added structural sensitive-looking JSON field-path detection without copying field values into Authorization Analysis evidence.
- Added strict GET/HEAD-only automation guard for Authorization Lab.
- Added automatic Response Diff generation for every authorization case.
- Added Authorization Analysis evidence records.
- Added Authorization Testing events to AI Mission Control.
- Added redacted AI second-opinion review.
- Added OpenAI-compatible authorization-review prompt and Mock provider support.
- Added configurable automatic candidate Finding creation.
- Added manual promotion of lower-confidence review cases into Findings.
- Added Authorization Lab case-detail UI.
- Added candidate confidence, identity comparison, sensitive path, rationale and AI review panels.
- Added `AUTHORIZATION_AUTO_CANDIDATE_FINDINGS`.
- Added `AUTHORIZATION_AUTO_CANDIDATE_MIN_CONFIDENCE`.
- Updated Request Workspace replay User-Agent to V0.5.
- Expanded regression suite to 28 tests.
- Added full horizontal-candidate + anonymous-control E2E validation.
- Added Chromium visual QA for Authorization Lab and Authorization Case pages.


## 0.4.0 - 2026-09-08

- Added Request Workspace with a dense three-column Repeater-style layout.
- Added persistent StoredRequest, ReplayResult, ResponseDiff and Identity models.
- Added Burp raw request parsing/import without automatic transmission.
- Added Endpoint → Request Workspace and Route Candidate → Request Workspace actions.
- Added manual Scope/Policy-gated request replay.
- GET/HEAD requests default to READ_ONLY; other methods default to STATE_CHANGE.
- Added explicit manual READ_ONLY override for verified non-mutating imported requests.
- Added Fernet encryption for identity headers/cookies and protected request headers.
- Added automatic first-run APP_SECRET_KEY generation in Windows/Linux start scripts.
- Added UI masking so identity secret values are never rendered back in plaintext.
- Added request-history redaction for Authorization, Cookie and API-key-style values.
- Added response Set-Cookie redaction from persisted response headers/evidence.
- Added identity-aware replay using Anonymous/User A/User B/Admin-style contexts.
- Added Response Diff: status, length, header diff, JSON path diff and text similarity.
- Added replay result evidence records and Agent Mission Control replay events.
- Added Request Workspace and Sessions navigation to the dense V0.3 workbench UI.
- Added request-validation metrics to Project Overview and Report Preview.
- Added V0.4 parser, encryption, replay, Scope-block, Diff and template tests.


## 0.3.0 - 2026-09-08

- Rebuilt the UI into a dense pentest workspace instead of a generic dashboard.
- Added narrow tool rail and high-density workspace navigation.
- Added Attack Surface tree: Host → Service → Web Resource → JavaScript → Route Candidate.
- Added a context inspector for attack-surface observations.
- Added safe in-scope HTML crawling.
- Added static JavaScript route/API extraction.
- Added `fetch` and common Axios method recognition.
- Added HTML form discovery without form submission.
- Added JavaScript source-map reference detection.
- Added basic technology fingerprint snapshots.
- Added persistent `WebArtifact` and `RouteCandidate` data models.
- Added `AgentRun` and `AgentEvent` audit models.
- Added AI Mission Control with stage and event stream views.
- Added Endpoints / Route Candidates workspace.
- Added Evidence workspace with raw evidence preview.
- Added Report Preview.
- Added Markdown and standalone HTML report exports.
- Kept the existing Scope Engine and default-deny Policy Engine.
- Added V0.3 discovery regression tests and full E2E validation.
- Added browser-rendered visual QA for Overview, Attack Surface and Mission Control.



## 0.2.0 - 2026-09-08

- Rebuilt the interface as a security operations workspace.
- Added global Dashboard with project, asset, finding and task metrics.
- Added project Overview, Assets, Findings, Tasks and Settings navigation.
- Added asynchronous background scan workflow so the UI returns immediately.
- Added live project/task polling.
- Added pre-scan Scope Check UI.
- Added structured asset inventory for hosts, services and endpoints.
- Added searchable Finding Library and evidence-chain detail view.
- Added AI provider / policy / scope status presentation.
- Added modern responsive dark security-platform styling.
- Migrated FastAPI startup to lifespan handlers.
- Added lightweight SQLite compatibility migration.
- Expanded regression suite for V0.2 routes and templates.


## 0.1.1 - 2026-09-08

- Fixed `Jinja2Templates.TemplateResponse` compatibility with newer Starlette releases.
- Replaced ambiguous positional template arguments with explicit `request=`, `name=` and `context=` arguments.
- Added regression tests that render the home, project and finding pages through FastAPI `TestClient`.
- Added an explicit Starlette compatibility range to `requirements.txt`.

## 0.1.0 - 2026-09-08

- Added FastAPI application and minimal web UI.
- Added project-scoped authorization allowlists.
- Added default-deny policy engine.
- Added HTTP, security-header, TLS and constrained port reconnaissance.
- Added Nmap integration with safe fallback TCP-connect probing.
- Added task, asset, endpoint, service, finding and evidence persistence.
- Added safe redirect handling that blocks out-of-scope destinations.
- Added backend-only AI provider configuration.
- Added mock AI provider and OpenAI-compatible provider adapter.
- Response bodies remain local by default and are not sent to external AI providers.
- Added unit tests and local end-to-end validation.
