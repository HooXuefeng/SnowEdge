from __future__ import annotations

import json
from dataclasses import dataclass
from sqlalchemy.orm import Session

from ..models import (
    AgentRun,
    AssessmentMemory,
    AuthorizationCase,
    BrowserSession,
    CoverageSnapshot,
    Endpoint,
    Evidence,
    EvidenceAttachment,
    EndpointParameter,
    Finding,
    FindingLifecycle,
    Identity,
    KnowledgeNode,
    Project,
    ProofCapsule,
    ResponseDiff,
    RouteCandidate,
    Service,
    SkillPlan,
    SpecialistAgentRun,
    StoredRequest,
    Task,
    WebArtifact,
)


WEIGHTS = {
    "scope_inventory": 8,
    "service_inventory": 7,
    "http_baseline": 8,
    "transport_headers": 8,
    "web_discovery": 10,
    "browser_observation": 8,
    "javascript_api_mapping": 8,
    "request_workspace": 7,
    "identity_context": 6,
    "response_differential": 6,
    "authorization_testing": 10,
    "finding_evidence": 6,
    "proof_verification": 5,
    "reporting_readiness": 5,
    "intelligence_review": 8,
}


def _count(db: Session, model, *filters) -> int:
    q = db.query(model)
    for f in filters:
        q = q.filter(f)
    return q.count()


def _task_count(db: Session, project_id: int, actions: set[str], status: str | None = None) -> int:
    q = db.query(Task).filter(Task.project_id == project_id, Task.action.in_(actions))
    if status:
        q = q.filter(Task.status == status)
    return q.count()


def _status(covered: bool, partial: bool = False, review: bool = False) -> str:
    if covered:
        return "covered"
    if review:
        return "needs_review"
    if partial:
        return "partial"
    return "gap"


def _item(
    key: str,
    label: str,
    category: str,
    status: str,
    evidence_count: int,
    rationale: str,
    next_step: str,
    refs: list[dict] | None = None,
) -> dict:
    return {
        "key": key,
        "label": label,
        "category": category,
        "status": status,
        "weight": WEIGHTS[key],
        "evidence_count": evidence_count,
        "rationale": rationale,
        "next_step": next_step,
        "refs": refs or [],
    }


def build_coverage_matrix(db: Session, project: Project) -> list[dict]:
    project_id = project.id

    # Project-scoped asset IDs keep coverage isolated to the current assessment.
    from ..models import Asset
    asset_ids = [a.id for a in db.query(Asset).filter(Asset.project_id == project_id).all()] or [-1]
    services = _count(db, Service, Service.asset_id.in_(asset_ids))
    endpoints = _count(db, Endpoint, Endpoint.asset_id.in_(asset_ids))
    routes = _count(db, RouteCandidate, RouteCandidate.asset_id.in_(asset_ids))
    web_artifacts = _count(db, WebArtifact, WebArtifact.asset_id.in_(asset_ids))

    completed_http = _task_count(db, project_id, {"http_probe"}, "done")
    completed_transport = _task_count(db, project_id, {"headers_check", "tls_check"}, "done")
    completed_web = _task_count(db, project_id, {"web_discovery"}, "done")
    browser_sessions = _count(db, BrowserSession, BrowserSession.project_id == project_id, BrowserSession.status == "done")
    stored_requests = _count(db, StoredRequest, StoredRequest.project_id == project_id)
    identities = _count(db, Identity, Identity.project_id == project_id)
    diffs = _count(db, ResponseDiff, ResponseDiff.project_id == project_id)
    auth_cases = _count(db, AuthorizationCase, AuthorizationCase.project_id == project_id)
    findings = _count(db, Finding, Finding.project_id == project_id)
    proof_capsules = _count(db, ProofCapsule, ProofCapsule.project_id == project_id)
    evidence = (
        db.query(Evidence)
        .filter(
            (Evidence.finding_id.in_([f.id for f in db.query(Finding).filter(Finding.project_id == project_id).all()] or [-1]))
            | (Evidence.task_id.in_([t.id for t in db.query(Task).filter(Task.project_id == project_id).all()] or [-1]))
        )
        .count()
    )
    specialist_runs = _count(db, SpecialistAgentRun, SpecialistAgentRun.project_id == project_id, SpecialistAgentRun.status == "done")
    knowledge_nodes = _count(db, KnowledgeNode, KnowledgeNode.project_id == project_id)
    memories = _count(db, AssessmentMemory, AssessmentMemory.project_id == project_id)
    plans = _count(db, SkillPlan, SkillPlan.project_id == project_id)
    report_ready = findings > 0 or evidence > 0 or auth_cases > 0

    items = [
        _item(
            "scope_inventory", "授权范围与资产清单", "基础",
            _status(bool(asset_ids != [-1])),
            0 if asset_ids == [-1] else len(asset_ids),
            "项目授权范围已建立，且已纳入发现资产。" if asset_ids != [-1] else "当前项目还没有关联已发现资产。",
            "执行一次授权范围内的基线评估，或添加已授权目标。",
        ),
        _item(
            "service_inventory", "服务清单", "基础",
            _status(services > 0, partial=(asset_ids != [-1] and services == 0)),
            services,
            f"当前项目资产已关联 {services} 条服务记录。",
            "检查当前已授权资产是否还需要补充服务识别。",
        ),
        _item(
            "http_baseline", "HTTP 基线", "Web",
            _status(completed_http > 0, partial=endpoints > 0),
            completed_http,
            f"已完成 {completed_http} 个 HTTP 基线任务；已知 {endpoints} 个接口。",
            "为尚未覆盖的 Web 目标补充 HTTP 基线证据，或复用已有证据。",
        ),
        _item(
            "transport_headers", "TLS 与安全响应头检查", "Web",
            _status(completed_transport >= 2, partial=completed_transport > 0),
            completed_transport,
            f"已完成 {completed_transport} 个 TLS / 响应头检查任务。",
            "检查授权范围内尚未覆盖的 HTTPS 表面、TLS 配置和安全响应头。",
        ),
        _item(
            "web_discovery", "Web 攻击面发现", "Web",
            _status(completed_web > 0 and (web_artifacts > 0 or routes > 0), partial=(completed_web > 0 or routes > 0)),
            completed_web + web_artifacts + routes,
            f"已完成 {completed_web} 次 Web 发现；记录 {web_artifacts} 个 Web Artifact、{routes} 个路由候选。",
            "对尚未覆盖的已授权 Web 根路径运行现有 Web 发现技能。",
        ),
        _item(
            "browser_observation", "真实浏览器观察", "Web",
            _status(browser_sessions > 0),
            browser_sessions,
            f"已完成 {browser_sessions} 个仅观察浏览器会话。",
            "静态发现遗漏 XHR/Fetch、DOM 表单或运行时行为时，使用浏览器工作台补充观察。",
        ),
        _item(
            "javascript_api_mapping", "JavaScript / API 映射", "Web",
            _status(routes > 0 and web_artifacts > 0, partial=(routes > 0 or web_artifacts > 0)),
            routes + web_artifacts,
            f"当前有 {routes} 个路由候选和 {web_artifacts} 个 Web Artifact 可供分析。",
            "重复采集前先检查 JavaScript / API 映射证据，确认是否仍有路由缺口。",
        ),
        _item(
            "request_workspace", "请求工作台覆盖", "验证",
            _status(stored_requests > 0),
            stored_requests,
            f"当前有 {stored_requests} 条已保存请求，可用于确定性重放和响应差异比较。",
            "把有价值的浏览器观察请求或人工请求保存到请求工作台。",
        ),
        _item(
            "identity_context", "授权身份上下文", "验证",
            _status(identities >= 2, partial=identities == 1),
            identities,
            f"当前配置了 {identities} 个已授权测试身份。",
            "只有在授权范围允许权限差异测试时，才配置至少两个已授权身份进行比较。",
        ),
        _item(
            "response_differential", "响应差异验证", "验证",
            _status(diffs > 0, partial=stored_requests > 0),
            diffs,
            f"当前保存了 {diffs} 组响应差异比较结果。",
            "仅在已有请求和授权身份足以支撑差异验证时，对只读重放结果进行比较。",
        ),
        _item(
            "authorization_testing", "权限差异验证", "验证",
            _status(auth_cases > 0, partial=(stored_requests > 0 and identities >= 2)),
            auth_cases,
            f"当前记录了 {auth_cases} 个权限验证案例。",
            "对尚未覆盖的身份 / 对象组合，使用仅 GET/HEAD 的权限验证案例。",
        ),
        _item(
            "finding_evidence", "漏洞与证据链", "证据",
            _status(findings > 0 and evidence > 0, partial=(findings > 0 or evidence > 0)),
            findings + evidence,
            f"当前记录了 {findings} 个漏洞和 {evidence} 条证据。",
            "只确认有证据支撑的候选问题；报告前补齐缺失证据。",
        ),
        _item(
            "proof_verification", "漏洞验证与复测", "证据",
            _status(proof_capsules > 0 and findings > 0, partial=findings > 0),
            proof_capsules,
            f"当前 {findings} 个漏洞中共有 {proof_capsules} 个 Proof Capsule。",
            "对需要可复现验证或明确人工复核状态的漏洞创建 Proof Capsule。",
        ),
        _item(
            "reporting_readiness", "报告交付准备度", "报告",
            _status(report_ready and evidence > 0, partial=report_ready),
            findings + auth_cases + proof_capsules,
            "当前已有证据支撑的项目结果，可以生成报告。" if report_ready else "当前还没有可交付的报告结果。",
            "导出前检查验证状态，只输出有证据支撑的结论。",
        ),
        _item(
            "intelligence_review", "知识 / 记忆 / 专家审阅", "智能分析",
            _status(knowledge_nodes > 0 and memories > 0 and specialist_runs >= 6, partial=(knowledge_nodes > 0 or memories > 0 or specialist_runs > 0)),
            knowledge_nodes + memories + specialist_runs,
            f"当前有 {knowledge_nodes} 个知识节点、{memories} 条测试记忆、{specialist_runs} 次已完成专家审阅。",
            "当证据集发生明显变化时，刷新知识图谱 / 测试记忆并重新运行专家审阅。",
        ),
    ]
    return items


def snapshot_coverage(db: Session, project: Project) -> CoverageSnapshot:
    items = build_coverage_matrix(db, project)
    total_weight = sum(i["weight"] for i in items)
    earned = 0.0
    status_factor = {"covered": 1.0, "partial": 0.5, "needs_review": 0.35, "gap": 0.0}
    for item in items:
        earned += item["weight"] * status_factor[item["status"]]
    score = round((earned / total_weight) * 100) if total_weight else 0

    gaps = [
        {
            "key": item["key"],
            "label": item["label"],
            "status": item["status"],
            "next_step": item["next_step"],
            "weight": item["weight"],
        }
        for item in items if item["status"] != "covered"
    ]
    gaps.sort(key=lambda x: (-x["weight"], x["label"]))

    counts = {s: sum(1 for i in items if i["status"] == s) for s in ["covered", "partial", "gap", "needs_review"]}
    row = CoverageSnapshot(
        project_id=project.id,
        score=score,
        covered_count=counts["covered"],
        partial_count=counts["partial"],
        gap_count=counts["gap"],
        needs_review_count=counts["needs_review"],
        matrix_json=json.dumps(items, ensure_ascii=False),
        gaps_json=json.dumps(gaps, ensure_ascii=False),
        summary=(
            f"覆盖度 {score}/100：{counts['covered']} 项已覆盖，"
            f"{counts['partial']} 项部分覆盖，{counts['gap']} 项缺口，{counts['needs_review']} 项待复核。"
        ),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def coverage_payload(snapshot: CoverageSnapshot) -> dict:
    def load(raw, default):
        try:
            return json.loads(raw or "")
        except Exception:
            return default
    return {
        "id": snapshot.id,
        "score": snapshot.score,
        "covered": snapshot.covered_count,
        "partial": snapshot.partial_count,
        "gap": snapshot.gap_count,
        "needs_review": snapshot.needs_review_count,
        "matrix": load(snapshot.matrix_json, []),
        "gaps": load(snapshot.gaps_json, []),
        "summary": snapshot.summary,
        "created_at": snapshot.created_at,
    }


def latest_coverage(db: Session, project: Project, *, refresh: bool = False) -> CoverageSnapshot:
    latest = (
        db.query(CoverageSnapshot)
        .filter(CoverageSnapshot.project_id == project.id)
        .order_by(CoverageSnapshot.id.desc())
        .first()
    )
    if refresh or latest is None:
        return snapshot_coverage(db, project)
    return latest


def coverage_dimensions(db: Session, project: Project) -> list[dict]:
    from ..models import Asset, RetestRun

    project_id = project.id
    assets = db.query(Asset).filter(Asset.project_id == project_id).all()
    asset_ids = [a.id for a in assets] or [-1]
    endpoints = db.query(Endpoint).filter(Endpoint.asset_id.in_(asset_ids)).all()
    endpoint_ids = [e.id for e in endpoints] or [-1]
    parameters = db.query(EndpointParameter).filter(EndpointParameter.endpoint_id.in_(endpoint_ids)).count()
    requests = db.query(StoredRequest).filter(StoredRequest.project_id == project_id).all()
    identities = db.query(Identity).filter(Identity.project_id == project_id).all()
    auth_cases = db.query(AuthorizationCase).filter(AuthorizationCase.project_id == project_id).all()
    browsers = db.query(BrowserSession).filter(BrowserSession.project_id == project_id, BrowserSession.status == "done").all()
    findings = db.query(Finding).filter(Finding.project_id == project_id, Finding.finding_state != "false_positive").all()
    finding_ids = [f.id for f in findings] or [-1]
    evidence_finding_ids = {
        x[0] for x in db.query(Evidence.finding_id)
        .filter(Evidence.finding_id.in_(finding_ids), Evidence.finding_id.is_not(None))
        .distinct().all()
    }
    screenshot_finding_ids = {
        x[0] for x in db.query(EvidenceAttachment.finding_id)
        .filter(EvidenceAttachment.finding_id.in_(finding_ids))
        .distinct().all()
    }
    proof_finding_ids = {
        x[0] for x in db.query(ProofCapsule.finding_id)
        .filter(ProofCapsule.finding_id.in_(finding_ids))
        .distinct().all()
    }
    retested_finding_ids = {
        x[0] for x in db.query(RetestRun.finding_id)
        .filter(RetestRun.finding_id.in_(finding_ids))
        .distinct().all()
    }

    read_only_requests = [r for r in requests if r.method in {"GET", "HEAD"}]
    auth_request_ids = {c.stored_request_id for c in auth_cases if c.stored_request_id}
    endpoint_request_ratio = min(1.0, len(requests) / max(1, len(endpoints)))
    parameter_ratio = min(1.0, parameters / max(1, len(endpoints)))
    identity_ratio = 1.0 if len(identities) >= 2 else 0.5 if len(identities) == 1 else 0.0
    auth_ratio = min(1.0, len(auth_request_ids) / max(1, len(read_only_requests))) if read_only_requests else 0.0
    browser_ratio = min(1.0, len(browsers) / max(1, len(assets))) if assets else 0.0
    evidence_ratio = len(evidence_finding_ids) / max(1, len(findings)) if findings else 0.0
    screenshot_ratio = len(screenshot_finding_ids) / max(1, len(findings)) if findings else 0.0
    retest_ratio = len(retested_finding_ids | {f.id for f in findings if f.verification_state == "resolved"}) / max(1, len(findings)) if findings else 0.0
    proof_ratio = len(proof_finding_ids) / max(1, len(findings)) if findings else 0.0

    raw = [
        ("endpoint", "Endpoint → Request", len(requests), len(endpoints), endpoint_request_ratio, "把高价值 Endpoint 转成可复用 Stored Request。"),
        ("parameter", "参数建模", parameters, len(endpoints), parameter_ratio, "通过 OpenAPI/HAR/Postman/Browser 补齐参数结构。"),
        ("identity", "身份上下文", len(identities), 2, identity_ratio, "权限测试通常至少需要两个明确授权身份。"),
        ("authorization", "只读权限覆盖", len(auth_request_ids), len(read_only_requests), auth_ratio, "优先覆盖尚未做差异验证的 GET/HEAD 请求。"),
        ("browser", "Browser 运行时覆盖", len(browsers), len(assets), browser_ratio, "对动态 Web/SPA 资产补一次 observe-only Browser Session。"),
        ("finding_evidence", "Finding Evidence", len(evidence_finding_ids), len(findings), evidence_ratio, "每个报告 Finding 至少应有一条可追溯 Evidence。"),
        ("screenshot", "验证截图", len(screenshot_finding_ids), len(findings), screenshot_ratio, "为需要交付的 Finding 补验证截图。"),
        ("proof", "Proof Capsule", len(proof_finding_ids), len(findings), proof_ratio, "对需要可重复验证的 Finding 建立 Proof Capsule。"),
        ("retest", "复测覆盖", len(retested_finding_ids), len(findings), retest_ratio, "优先处理 retest_ready 或已整改漏洞。"),
    ]
    return [
        {
            "key": key,
            "label": label,
            "numerator": numerator,
            "denominator": denominator,
            "score": round(ratio * 100),
            "status": "covered" if ratio >= 0.9 else "partial" if ratio > 0 else "gap",
            "next_step": next_step,
        }
        for key, label, numerator, denominator, ratio, next_step in raw
    ]


def coverage_dimension_summary(db: Session, project: Project) -> dict:
    rows = coverage_dimensions(db, project)
    return {
        "rows": rows,
        "average": round(sum(x["score"] for x in rows) / len(rows)) if rows else 0,
        "gaps": sorted([x for x in rows if x["score"] < 90], key=lambda x: (x["score"], x["label"])),
    }
