from __future__ import annotations

import asyncio
import json
import logging
from collections import Counter
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

from fastapi import BackgroundTasks, Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import inspect, text, or_, func
from sqlalchemy.orm import Session
from starlette.requests import Request

from .config import settings
from .ui_i18n import configure_templates, STATUS_ZH, SEVERITY_ZH
from .db import Base, SessionLocal, engine, get_db
from .schema_migrations import ensure_schema_current
from .models import (
    AgentEvent,
    AgentRun,
    Asset,
    Endpoint,
    EndpointParameter,
    Evidence,
    EvidenceProvenance,
    Finding,
    Project,
    RouteCandidate,
    Service,
    Task,
    WebArtifact,
    Identity,
    StoredRequest,
    ReplayResult,
    AuthorizationCase,
    AuthorizationMatrixRun,
    SkillDefinition,
    ProjectSkill,
    SkillRun,
    SkillPlan,
    ExecutionGraphNode,
    ProofCapsule,
    RetestRun,
    BrowserSession,
    BrowserEvent,
    BrowserArtifact,
    KnowledgeNode,
    KnowledgeEdge,
    AssessmentMemory,
    SpecialistAgentRun,
    AgentHandoff,
    CoverageSnapshot,
    CopilotQuery,
    FindingLifecycle,
    RemediationEvent,
    PersistentJob,
    JobWorker,
    ImportBatch,
    TechnologyFingerprint,
    ScanProfile,
    NetworkRouteProfile,
    BatchAssessment,
    WorkspaceDraft,
)
from .orchestrator import run_authorized_scan
from .policy import classify_action
from .scope import normalize_scope_rules, target_in_scope
from .request_routes import router as request_workspace_router
from .authorization_routes import router as authorization_workspace_router
from .skill_routes import router as skill_hub_router
from .browser_routes import router as browser_workspace_router
from .intelligence_routes import router as intelligence_workspace_router
from .closure_routes import router as closure_workspace_router
from .job_routes import router as job_center_router
from .authorization_matrix_routes import router as authorization_matrix_router
from .import_routes import router as import_workspace_router
from .personal_routes import router as personal_workspace_router
from .reliability_routes import router as reliability_router
from .asset_intelligence_routes import router as asset_intelligence_router
from .skills.registry import seed_builtin_skills, ensure_project_skill_rows, enabled_skills, enabled_capabilities
from .services.proof_capsule import capsule_payload, get_or_create_capsule, run_retest
from .services.execution_graph import graph_payload
from .services.knowledge_graph import rebuild_knowledge_graph, graph_summary
from .services.assessment_memory import refresh_assessment_memory, memory_summary
from .skills.runtime import finish_skill_run, start_skill_run
from .services.multi_agent import team_summary
from .services.coverage_matrix import latest_coverage, coverage_payload, snapshot_coverage
from .services.remediation import ensure_lifecycle, ensure_project_lifecycles, remediation_summary, retest_lifecycle
from .services.job_engine import enqueue_job, worker_loop, run_job_now
from .services.endpoint_inventory import sync_project_endpoint_inventory, endpoint_parameters
from .services.project_portability import export_project_zip, parse_project_zip, import_project_manifest
from .services.finding_service import ensure_finding_metadata
from .services.evidence_chain import backfill_project_evidence, evidence_chain_payload, project_evidence_summary
from .services.finding_states import update_finding_states, FINDING_STATES, VERIFICATION_STATES, REMEDIATION_STATES
from .services.txb02_report import generate_txb02_docx
from .ai.factory import current_ai_provider_name
from .services.personal_settings import get_personal_settings, ai_runtime_settings
from .services.project_templates import PROJECT_TEMPLATES, apply_project_template, template_list
from .services.personal_next_steps import suggested_next_steps
from .services.evidence_attachments import finding_attachments
from .services.personal_backup import run_due_backups_once
from .services.finding_quality import finding_quality, project_quality_summary, report_preflight
from .services.recovery import prepare_recovery, recovery_snapshot

BASE_DIR = Path(__file__).resolve().parent


def _migrate_sqlite_if_needed():
    if engine.dialect.name != "sqlite":
        return
    inspector = inspect(engine)
    if "evidence" in inspector.get_table_names():
        columns = {c["name"] for c in inspector.get_columns("evidence")}
        if "task_id" not in columns:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE evidence ADD COLUMN task_id INTEGER REFERENCES tasks(id)"))


async def _personal_backup_scheduler() -> None:
    while True:
        try:
            result = await asyncio.to_thread(run_due_backups_once)
            if result.get("errors"):
                logging.getLogger(__name__).error("Automatic backup failed for projects: %s", [item["project_id"] for item in result["errors"]])
        except asyncio.CancelledError:
            raise
        except Exception:
            logging.getLogger(__name__).exception("Automatic backup scheduler failed")
        await asyncio.sleep(3600)


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.tool_slots = asyncio.Semaphore(4)
    ensure_schema_current()
    db = SessionLocal()
    try:
        seed_builtin_skills(db)
        for project in db.query(Project).all():
            ensure_project_skill_rows(db, project.id)
        prepare_recovery(db)
    finally:
        db.close()

    workers = [
        asyncio.create_task(worker_loop(f"embedded-{idx+1}"))
        for idx in range(max(0, settings.job_embedded_workers))
    ]
    app.state.job_workers = workers
    backup_scheduler = asyncio.create_task(_personal_backup_scheduler())
    app.state.backup_scheduler = backup_scheduler
    try:
        yield
    finally:
        backup_scheduler.cancel()
        await asyncio.gather(backup_scheduler, return_exceptions=True)
        for worker in workers:
            worker.cancel()
        await asyncio.gather(*workers, return_exceptions=True)


from .version import VERSION, PRODUCT_NAME
from .local_security import LocalOriginMiddleware
app = FastAPI(title=PRODUCT_NAME, version=VERSION, lifespan=lifespan)
app.add_middleware(LocalOriginMiddleware,allowed_hosts=settings.local_allowed_hosts)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
app.include_router(request_workspace_router)
app.include_router(authorization_workspace_router)
app.include_router(skill_hub_router)
app.include_router(browser_workspace_router)
app.include_router(intelligence_workspace_router)
app.include_router(closure_workspace_router)
app.include_router(job_center_router)
app.include_router(authorization_matrix_router)
app.include_router(import_workspace_router)
app.include_router(personal_workspace_router)
app.include_router(reliability_router)
app.include_router(asset_intelligence_router)
from .utility_routes import router as utility_router
app.include_router(utility_router)
from .workbench_routes import router as workbench_router
app.include_router(workbench_router)
from .scan_routes import router as scan_center_router
app.include_router(scan_center_router)
from .finding_editor_routes import router as finding_editor_router
app.include_router(finding_editor_router)
from .project_editor_routes import router as project_editor_router
app.include_router(project_editor_router)
from .network_management_routes import router as network_management_router
app.include_router(network_management_router)
from .workflow_routes import router as workflow_router
app.include_router(workflow_router)
from .delivery_routes import router as delivery_router
app.include_router(delivery_router)
templates = configure_templates(Jinja2Templates(directory=BASE_DIR / "templates"))


def _download_disposition(filename: str, fallback: str) -> str:
    """Return an ASCII-safe Content-Disposition while preserving UTF-8 filenames."""
    safe_fallback = "".join(c if c.isascii() and (c.isalnum() or c in "-_.") else "_" for c in fallback)
    safe_fallback = safe_fallback[:120] or "download.bin"
    encoded = quote(filename, safe="-_.()")
    return f"attachment; filename=\"{safe_fallback}\"; filename*=UTF-8''{encoded}"


def _scope_rules(project: Project) -> list[str]:
    return [x.strip() for x in project.scope_text.splitlines() if x.strip()]


def _project_stats(db: Session, project_id: int) -> dict:
    severity_counts = db.query(Finding.severity, func.count(Finding.id)).filter(Finding.project_id == project_id).group_by(Finding.severity).all()
    asset_ids = [row[0] for row in db.query(Asset.id).filter(Asset.project_id == project_id)] or [-1]
    asset_count = db.query(Asset).filter(Asset.project_id == project_id).count()
    task_counts = dict(db.query(Task.status, func.count(Task.id)).filter(Task.project_id == project_id).group_by(Task.status))

    services = db.query(Service).filter(Service.asset_id.in_(asset_ids)).count()
    endpoints = db.query(Endpoint).filter(Endpoint.asset_id.in_(asset_ids)).count()
    endpoint_parameters_count = db.query(EndpointParameter).join(Endpoint, EndpointParameter.endpoint_id == Endpoint.id).filter(Endpoint.asset_id.in_(asset_ids)).count()
    web_artifacts = db.query(WebArtifact).filter(WebArtifact.asset_id.in_(asset_ids)).count()
    routes = db.query(RouteCandidate).filter(RouteCandidate.asset_id.in_(asset_ids)).count()
    agent_runs = db.query(AgentRun).filter(AgentRun.project_id == project_id).count()
    stored_requests = db.query(StoredRequest).filter(StoredRequest.project_id == project_id).count()
    identities = db.query(Identity).filter(Identity.project_id == project_id).count()
    replays = db.query(ReplayResult).filter(ReplayResult.project_id == project_id).count()
    authorization_cases = db.query(AuthorizationCase).filter(AuthorizationCase.project_id == project_id).count()
    authorization_matrix_runs = db.query(AuthorizationMatrixRun).filter(AuthorizationMatrixRun.project_id == project_id).count()
    ensure_project_skill_rows(db, project_id)
    skills_enabled = (
        db.query(ProjectSkill)
        .filter(ProjectSkill.project_id == project_id, ProjectSkill.enabled == 1)
        .count()
    )
    skill_runs = db.query(SkillRun).filter(SkillRun.project_id == project_id).count()
    skill_plans = db.query(SkillPlan).filter(SkillPlan.project_id == project_id).count()
    proof_capsules = db.query(ProofCapsule).filter(ProofCapsule.project_id == project_id).count()
    retest_runs = db.query(RetestRun).filter(RetestRun.project_id == project_id).count()
    browser_sessions = db.query(BrowserSession).filter(BrowserSession.project_id == project_id).count()
    browser_events = db.query(BrowserEvent).filter(BrowserEvent.project_id == project_id).count()
    browser_artifacts = db.query(BrowserArtifact).filter(BrowserArtifact.project_id == project_id).count()
    knowledge_nodes = db.query(KnowledgeNode).filter(KnowledgeNode.project_id == project_id).count()
    knowledge_edges = db.query(KnowledgeEdge).filter(KnowledgeEdge.project_id == project_id).count()
    assessment_memories = db.query(AssessmentMemory).filter(AssessmentMemory.project_id == project_id).count()
    specialist_runs = db.query(SpecialistAgentRun).filter(SpecialistAgentRun.project_id == project_id).count()
    agent_handoffs = db.query(AgentHandoff).filter(AgentHandoff.project_id == project_id).count()
    coverage_snapshots = db.query(CoverageSnapshot).filter(CoverageSnapshot.project_id == project_id).count()
    copilot_queries = db.query(CopilotQuery).filter(CopilotQuery.project_id == project_id).count()
    remediation_items = db.query(FindingLifecycle).filter(FindingLifecycle.project_id == project_id).count()
    remediation_open = db.query(FindingLifecycle).filter(
        FindingLifecycle.project_id == project_id,
        FindingLifecycle.status.notin_(["resolved", "accepted_risk", "false_positive"]),
    ).count()
    persistent_jobs = db.query(PersistentJob).filter(PersistentJob.project_id == project_id).count()
    active_jobs = db.query(PersistentJob).filter(PersistentJob.project_id == project_id, PersistentJob.status.in_(["queued", "running", "retry_wait", "cancel_requested"])).count()
    import_batches = db.query(ImportBatch).filter(ImportBatch.project_id == project_id).count()
    evidence_integrity_ready = db.query(Evidence).filter(Evidence.project_id == project_id, Evidence.integrity_sha256 != "").count()
    fingerprints = db.query(TechnologyFingerprint).filter(TechnologyFingerprint.project_id == project_id).count()
    batch_runs = db.query(BatchAssessment).filter(BatchAssessment.project_id == project_id).count()

    severities = Counter()
    for severity, count in severity_counts:
        severities[(severity or "info").lower()] += count
    return {
        "assets": asset_count,
        "services": services,
        "endpoints": endpoints,
        "endpoint_parameters": endpoint_parameters_count,
        "web_artifacts": web_artifacts,
        "routes": routes,
        "findings": sum(severities.values()),
        "critical": severities.get("critical", 0),
        "high": severities.get("high", 0),
        "medium": severities.get("medium", 0),
        "low": severities.get("low", 0),
        "info": severities.get("info", 0),
        "running_tasks": task_counts.get("queued", 0) + task_counts.get("running", 0),
        "completed_tasks": task_counts.get("done", 0),
        "failed_tasks": task_counts.get("error", 0),
        "agent_runs": agent_runs,
        "stored_requests": stored_requests,
        "identities": identities,
        "replays": replays,
        "authorization_cases": authorization_cases,
        "authorization_matrix_runs": authorization_matrix_runs,
        "skills_enabled": skills_enabled,
        "skill_runs": skill_runs,
        "skill_plans": skill_plans,
        "proof_capsules": proof_capsules,
        "retest_runs": retest_runs,
        "browser_sessions": browser_sessions,
        "browser_events": browser_events,
        "browser_artifacts": browser_artifacts,
        "knowledge_nodes": knowledge_nodes,
        "knowledge_edges": knowledge_edges,
        "assessment_memories": assessment_memories,
        "specialist_runs": specialist_runs,
        "agent_handoffs": agent_handoffs,
        "coverage_snapshots": coverage_snapshots,
        "copilot_queries": copilot_queries,
        "remediation_items": remediation_items,
        "remediation_open": remediation_open,
        "persistent_jobs": persistent_jobs,
        "active_jobs": active_jobs,
        "import_batches": import_batches,
        "evidence_hashed": evidence_integrity_ready,
        "fingerprints": fingerprints,
        "batch_runs": batch_runs,
    }


def _project_context(db: Session, project: Project, active_nav: str) -> dict:
    selected = enabled_skills(db, project.id)
    return {
        "project": project,
        "active_nav": active_nav,
        "stats": _project_stats(db, project.id),
        "ai_provider": current_ai_provider_name(),
        "ai_model": get_personal_settings(db).get("ai_model") or settings.ai_model or "Mock / not configured",
        "scope_rules": _scope_rules(project),
        "enabled_skills": selected,
        "enabled_skill_slugs": [skill.slug for skill in selected],
        "enabled_capability_names": sorted(enabled_capabilities(db, project.id)),
        "recovery_count": recovery_snapshot(db).get("total", 0),
    }


def _latest_agent(db: Session, project_id: int):
    run = (
        db.query(AgentRun)
        .filter(AgentRun.project_id == project_id)
        .order_by(AgentRun.id.desc())
        .first()
    )
    if not run:
        return None, []
    events = (
        db.query(AgentEvent)
        .filter(AgentEvent.agent_run_id == run.id)
        .order_by(AgentEvent.id.desc())
        .limit(20)
        .all()
    )
    return run, events


async def _run_scan_background(project_id: int, target: str, parent_task_id: int):
    db = SessionLocal()
    try:
        project = db.get(Project, project_id)
        parent = db.get(Task, parent_task_id)
        if not project or not parent:
            return
        parent.status = "running"
        db.commit()
        try:
            await run_authorized_scan(db, project, target)
            rebuild_knowledge_graph(db, project.id)
            refresh_assessment_memory(db, project.id)
            parent.status = "done"
            parent.detail = "Workspace assessment workflow completed; Knowledge Graph and Assessment Memory refreshed."
        except Exception as exc:
            parent.status = "error"
            parent.detail = f"{type(exc).__name__}: {exc}"
        db.commit()
    finally:
        db.close()


@app.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)):
    projects = db.query(Project).order_by(Project.id.desc()).all()
    asset_counts = dict(db.query(Asset.project_id, func.count(Asset.id)).group_by(Asset.project_id))
    route_counts = dict(db.query(Asset.project_id, func.count(RouteCandidate.id)).join(RouteCandidate, RouteCandidate.asset_id == Asset.id).group_by(Asset.project_id))
    running_counts = dict(db.query(Task.project_id, func.count(Task.id)).filter(Task.status.in_(["queued", "running"])).group_by(Task.project_id))
    severity_counts = {}
    for pid, severity, count in db.query(Finding.project_id, Finding.severity, func.count(Finding.id)).group_by(Finding.project_id, Finding.severity):
        severity_counts.setdefault(pid, Counter())[(severity or "info").lower()] += count
    cards = [{"project": p, "stats": {"assets": asset_counts.get(p.id, 0), "routes": route_counts.get(p.id, 0), "running_tasks": running_counts.get(p.id, 0), **{key: severity_counts.get(p.id, {}).get(key, 0) for key in ("high", "medium", "low", "info")}}} for p in projects]
    global_stats = {
        "projects": len(projects),
        "assets": db.query(Asset).count(),
        "findings": db.query(Finding).count(),
        "running_tasks": db.query(Task).filter(Task.status.in_(["queued", "running"])).count(),
        "routes": db.query(RouteCandidate).count(),
    }
    recent_findings = db.query(Finding).order_by(Finding.id.desc()).limit(8).all()
    recent_runs = db.query(AgentRun).order_by(AgentRun.id.desc()).limit(6).all()
    personal = get_personal_settings(db)
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "cards": cards,
            "global_stats": global_stats,
            "recent_findings": recent_findings,
            "recent_runs": recent_runs,
            "ai_provider": current_ai_provider_name(),
            "active_nav": "dashboard",
            "personal_settings": personal,
            "setup_required": not personal.get("setup_completed", False),
            "project_templates": template_list(),
            "recovery_count": recovery_snapshot(db).get("total", 0),
        },
    )


@app.post("/projects")
def create_project(
    name: str = Form(...),
    scope: str = Form(""),
    skip_scope: str = Form(""),
    template_slug: str = Form("web-api"),
    db: Session = Depends(get_db),
):
    if skip_scope == "yes":
        rules = ["*"]
    else:
        try:
            rules = normalize_scope_rules(scope.splitlines())
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        if not rules:
            raise HTTPException(400, "请填写目标范围，或选择“不限制目标”。")
    if template_slug not in PROJECT_TEMPLATES:
        template_slug = "web-api"
    project = Project(
        name=name.strip(), scope_text="\n".join(rules), template_slug=template_slug,
        engagement_type=PROJECT_TEMPLATES[template_slug].get("engagement_type", "authorized_pentest"),
        status="testing",
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    seed_builtin_skills(db)
    ensure_project_skill_rows(db, project.id)
    apply_project_template(db, project.id, template_slug)
    return RedirectResponse(f"/projects/{project.id}", status_code=303)


@app.get("/projects/{project_id}", response_class=HTMLResponse)
def project_overview(project_id: int, request: Request, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)

    findings = db.query(Finding).filter(Finding.project_id == project_id).order_by(Finding.id.desc()).limit(8).all()
    tasks = db.query(Task).filter(Task.project_id == project_id).order_by(Task.id.desc()).limit(10).all()
    run, events = _latest_agent(db, project_id)
    context = _project_context(db, project, "overview")
    next_steps = suggested_next_steps(db, project)
    candidate_count = db.query(Finding).filter(
        Finding.project_id == project_id, Finding.finding_state == "candidate"
    ).count()
    retest_ready_count = db.query(FindingLifecycle).filter(
        FindingLifecycle.project_id == project_id, FindingLifecycle.status == "retest_ready"
    ).count()
    draft_rows = db.query(WorkspaceDraft).filter(
        WorkspaceDraft.project_id == project_id, WorkspaceDraft.entity_type == "stored_request"
    ).order_by(WorkspaceDraft.updated_at.desc()).all()
    active_job_rows = db.query(PersistentJob).filter(
        PersistentJob.project_id == project_id,
        PersistentJob.status.in_(["queued", "running", "retry_wait", "cancel_requested"]),
    ).order_by(PersistentJob.priority.asc(), PersistentJob.id.desc()).limit(4).all()

    read_only_ids = {
        r.id for r in db.query(StoredRequest).filter(
            StoredRequest.project_id == project_id, StoredRequest.policy_class == "READ_ONLY"
        ).all()
    }
    tested_request_ids = {
        x[0] for x in db.query(AuthorizationCase.stored_request_id).filter(
            AuthorizationCase.project_id == project_id,
            AuthorizationCase.stored_request_id.is_not(None),
        ).distinct().all()
    }
    auth_gap_count = len(read_only_ids - tested_request_ids)

    latest_cov = latest_coverage(db, project)
    current_coverage = coverage_payload(latest_cov) if latest_cov else None

    continue_cards = []
    if draft_rows:
        continue_cards.append({
            "kind": "draft", "title": "恢复请求草稿",
            "detail": f"有 {len(draft_rows)} 条请求草稿尚未正式保存。",
            "url": f"/projects/{project_id}/requests?selected={draft_rows[0].entity_id}",
            "count": len(draft_rows),
        })
    if retest_ready_count:
        continue_cards.append({
            "kind": "retest", "title": "继续漏洞复测",
            "detail": f"{retest_ready_count} 个漏洞已经进入复测就绪状态。",
            "url": f"/projects/{project_id}/remediation", "count": retest_ready_count,
        })
    if candidate_count:
        continue_cards.append({
            "kind": "finding", "title": "处理待确认漏洞",
            "detail": f"{candidate_count} 个 Candidate 还需要人工确认或补证据。",
            "url": f"/projects/{project_id}/findings", "count": candidate_count,
        })
    if auth_gap_count:
        continue_cards.append({
            "kind": "authorization", "title": "补齐权限验证",
            "detail": f"{auth_gap_count} 条只读请求还没有进入权限差异验证。",
            "url": f"/projects/{project_id}/authorization-matrix", "count": auth_gap_count,
        })
    if active_job_rows:
        continue_cards.append({
            "kind": "job", "title": "查看正在执行的任务",
            "detail": f"{len(active_job_rows)} 个任务正在排队或执行。",
            "url": f"/projects/{project_id}/jobs", "count": len(active_job_rows),
        })
    if not continue_cards and next_steps:
        step = next_steps[0]
        continue_cards.append({
            "kind": step.get("kind", "next"), "title": step["title"],
            "detail": step["reason"], "url": step["url"], "count": 1,
        })

    context.update({
        "findings": findings,
        "tasks": tasks,
        "agent_run": run,
        "agent_events": events,
        "next_steps": next_steps,
        "project_template": PROJECT_TEMPLATES.get(project.template_slug, PROJECT_TEMPLATES["web-api"]),
        "continue_cards": continue_cards[:5],
        "candidate_count": candidate_count,
        "retest_ready_count": retest_ready_count,
        "request_draft_count": len(draft_rows),
        "auth_gap_count": auth_gap_count,
        "active_job_rows": active_job_rows,
        "current_coverage": current_coverage,
    })
    return templates.TemplateResponse(request=request, name="project.html", context=context)


@app.post("/projects/{project_id}/scan")
def scan(
    project_id: int,
    background_tasks: BackgroundTasks,
    target: str = Form(...),
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)

    target = target.strip()
    rules = _scope_rules(project)
    if not rules:
        raise HTTPException(400, "项目尚未设置授权范围，请先到项目设置中添加范围。")
    if not target_in_scope(target, rules):
        raise HTTPException(400, "Target is outside the project's authorized scope.")

    from .scan_routes import prepare_scan_draft
    return prepare_scan_draft(db,project,target)


@app.get("/projects/{project_id}/assets")
def legacy_assets(project_id: int):
    return RedirectResponse(f"/projects/{project_id}/attack-surface", status_code=302)


@app.get("/projects/{project_id}/attack-surface", response_class=HTMLResponse)
def attack_surface(project_id: int, request: Request, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)

    assets = db.query(Asset).filter(Asset.project_id == project_id).order_by(Asset.target).all()
    rows = []
    technologies = set()

    for asset in assets:
        services = db.query(Service).filter(Service.asset_id == asset.id).order_by(Service.port).all()
        endpoints = db.query(Endpoint).filter(Endpoint.asset_id == asset.id).order_by(Endpoint.id.desc()).all()
        artifacts = db.query(WebArtifact).filter(WebArtifact.asset_id == asset.id).order_by(WebArtifact.id.desc()).all()
        routes = db.query(RouteCandidate).filter(RouteCandidate.asset_id == asset.id).order_by(RouteCandidate.id.desc()).all()

        for artifact in artifacts:
            if artifact.artifact_type == "technology_snapshot":
                try:
                    data = json.loads(artifact.metadata_json or "{}")
                    technologies.update(data.get("technologies", []))
                except Exception:
                    pass

        rows.append({
            "asset": asset,
            "services": services,
            "endpoints": endpoints,
            "artifacts": artifacts,
            "routes": routes,
        })

    fingerprint_rows = db.query(TechnologyFingerprint).filter(TechnologyFingerprint.project_id == project_id).order_by(TechnologyFingerprint.confidence.desc()).all()
    context = _project_context(db, project, "attack_surface")
    context.update({"asset_rows": rows, "technologies": sorted(technologies), "fingerprint_rows": fingerprint_rows})
    return templates.TemplateResponse(request=request, name="attack_surface.html", context=context)


def _paginate(query, request, q):
    try:
        page = max(1, int(request.query_params.get('page', 1)))
    except ValueError:
        page = 1
    total = query.count()
    pages = max(1, (total + 49) // 50)
    page = min(page, pages)
    model = query.column_descriptions[0]['entity']
    return {'items': query.order_by(model.id.desc()).offset((page - 1) * 50).limit(50).all(),
            'page': page, 'pages': pages, 'total': total, 'q': q,
            'previous': str(request.url.include_query_params(page=page - 1)),
            'next': str(request.url.include_query_params(page=page + 1))}


@app.get("/projects/{project_id}/endpoints", response_class=HTMLResponse)
def endpoints_page(project_id: int, request: Request, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)

    assets = db.query(Asset).filter(Asset.project_id == project_id).all()
    asset_ids = [a.id for a in assets] or [-1]
    query = db.query(Endpoint).filter(Endpoint.asset_id.in_(asset_ids))
    q = request.query_params.get('q', '').strip()[:200]
    if q:
        query = query.filter(or_(Endpoint.url.contains(q, autoescape=True), Endpoint.normalized_path.contains(q, autoescape=True), Endpoint.method.contains(q, autoescape=True)))
    pagination = _paginate(query, request, q)
    endpoints = pagination.pop('items')
    routes = db.query(RouteCandidate).filter(RouteCandidate.asset_id.in_(asset_ids)).order_by(RouteCandidate.id.desc()).limit(100).all()
    asset_map = {a.id: a.target for a in assets}
    parameter_map = endpoint_parameters(db, [e.id for e in endpoints])
    fps = db.query(TechnologyFingerprint).filter(TechnologyFingerprint.project_id == project_id).all()
    fingerprint_map = {}
    for fp in fps:
        fingerprint_map.setdefault(fp.asset_id, []).append(fp)

    context = _project_context(db, project, "endpoints")
    context.update({"pagination": pagination, "endpoints": endpoints, "routes": routes, "asset_map": asset_map, "parameter_map": parameter_map, "fingerprint_map": fingerprint_map})
    return templates.TemplateResponse(request=request, name="endpoints.html", context=context)


@app.get("/projects/{project_id}/agent", response_class=HTMLResponse)
def agent_page(project_id: int, request: Request, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)

    runs = db.query(AgentRun).filter(AgentRun.project_id == project_id).order_by(AgentRun.id.desc()).limit(20).all()
    run, events = _latest_agent(db, project_id)
    context = _project_context(db, project, "agent")
    skill_runs = db.query(SkillRun).filter(SkillRun.project_id == project_id).order_by(SkillRun.id.desc()).limit(20).all()
    skill_map = {skill.id: skill for skill in db.query(SkillDefinition).all()}
    context.update({"runs": runs, "agent_run": run, "agent_events": events, "skill_runs": skill_runs, "skill_map": skill_map})
    return templates.TemplateResponse(request=request, name="agent.html", context=context)


@app.get("/projects/{project_id}/findings", response_class=HTMLResponse)
def project_findings(project_id: int, request: Request, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    query = db.query(Finding).filter(Finding.project_id == project_id)
    q = request.query_params.get('q', '').strip()[:200]
    if q:
        query = query.filter(or_(Finding.title.contains(q, autoescape=True), Finding.target.contains(q, autoescape=True), Finding.severity.contains(q, autoescape=True)))
    pagination = _paginate(query, request, q)
    findings = pagination.pop('items')
    for finding in findings:
        ensure_finding_metadata(db, finding)
    context = _project_context(db, project, "findings")
    context["findings"] = findings
    context["pagination"] = pagination
    context["finding_quality_summary"] = project_quality_summary(db, project_id)
    context["finding_quality_map"] = {row["finding_id"]: row for row in context["finding_quality_summary"]["rows"]}
    return templates.TemplateResponse(request=request, name="findings.html", context=context)


@app.get("/projects/{project_id}/evidence", response_class=HTMLResponse)
def evidence_page(project_id: int, request: Request, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)

    backfill_project_evidence(db, project_id)
    evidence = (
        db.query(Evidence)
        .filter(Evidence.project_id == project_id)
        .order_by(Evidence.id.desc())
        .limit(250)
        .all()
    )
    context = _project_context(db, project, "evidence")
    context["evidence_rows"] = evidence
    try:
        selected_id = int(request.query_params.get('selected', '0'))
    except ValueError:
        selected_id = 0
    if selected_id and not any(row.id == selected_id for row in evidence):
        selected_evidence = db.get(Evidence, selected_id)
        if selected_evidence and selected_evidence.project_id == project_id:
            context['evidence_rows'] = [selected_evidence] + evidence
    context["evidence_summary"] = project_evidence_summary(db, project_id)
    return templates.TemplateResponse(request=request, name="evidence.html", context=context)


@app.get("/projects/{project_id}/tasks", response_class=HTMLResponse)
def project_tasks(project_id: int, request: Request, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    tasks = db.query(Task).filter(Task.project_id == project_id).order_by(Task.id.desc()).all()
    context = _project_context(db, project, "tasks")
    context["tasks"] = tasks
    return templates.TemplateResponse(request=request, name="tasks.html", context=context)


@app.get("/projects/{project_id}/reports", response_class=HTMLResponse)
def reports_page(project_id: int, request: Request, db: Session = Depends(get_db)):
    if request.query_params.get("legacy") != "1":
        from .delivery_routes import view
        return view(request,db,project_id)
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    findings = db.query(Finding).filter(Finding.project_id == project_id).order_by(Finding.severity, Finding.id.desc()).all()
    auth_cases = db.query(AuthorizationCase).filter(AuthorizationCase.project_id == project_id).order_by(AuthorizationCase.id.desc()).all()
    run, events = _latest_agent(db, project_id)
    capsules = db.query(ProofCapsule).filter(ProofCapsule.project_id == project_id).order_by(ProofCapsule.id.desc()).all()
    latest_plan = db.query(SkillPlan).filter(SkillPlan.project_id == project_id).order_by(SkillPlan.id.desc()).first()
    context = _project_context(db, project, "reports")
    rebuild_knowledge_graph(db, project_id)
    refresh_assessment_memory(db, project_id)
    browser_sessions = db.query(BrowserSession).filter(BrowserSession.project_id == project_id).order_by(BrowserSession.id.desc()).limit(20).all()
    latest_team_parent = (
        db.query(AgentRun)
        .filter(AgentRun.project_id == project_id, AgentRun.mission.like("Run an analysis-only specialist team%"))
        .order_by(AgentRun.id.desc())
        .first()
    )
    specialist_report = team_summary(db, project_id, latest_team_parent.id if latest_team_parent else None)
    ensure_project_lifecycles(db, project_id)
    coverage_report = coverage_payload(latest_coverage(db, project, refresh=True))
    remediation_report = remediation_summary(db, project_id)
    context.update({
        "findings": findings,
        "authorization_cases": auth_cases,
        "agent_run": run,
        "browser_sessions_report": browser_sessions,
        "knowledge_report": graph_summary(db, project_id),
        "memory_report": memory_summary(db, project_id),
        "latest_team_parent": latest_team_parent,
        "specialist_report": specialist_report,
        "coverage_report": coverage_report,
        "remediation_report": remediation_report,
        "proof_capsules": capsules,
        "proof_map": {c.finding_id: c for c in capsules},
        "latest_plan": latest_plan,
        "execution_graph": graph_payload(db, latest_plan.id) if latest_plan else {"node_count": 0, "stages": [], "status_counts": {}},
        "report_preflight": report_preflight(db, project_id),
        "finding_quality_map": {f.id: finding_quality(db, f) for f in findings},
    })
    return templates.TemplateResponse(request=request, name="reports.html", context=context)


@app.get("/projects/{project_id}/reports/export.md", response_class=PlainTextResponse)
def export_report_markdown(project_id: int, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    rebuild_knowledge_graph(db, project_id)
    refresh_assessment_memory(db, project_id)
    stats = _project_stats(db, project_id)
    knowledge_export = graph_summary(db, project_id)
    memory_export = memory_summary(db, project_id)
    latest_team_export = (
        db.query(AgentRun)
        .filter(AgentRun.project_id == project_id, AgentRun.mission.like("Run an analysis-only specialist team%"))
        .order_by(AgentRun.id.desc())
        .first()
    )
    specialist_export = team_summary(db, project_id, latest_team_export.id if latest_team_export else None)
    ensure_project_lifecycles(db, project_id)
    coverage_export = coverage_payload(latest_coverage(db, project, refresh=True))
    remediation_export = remediation_summary(db, project_id)
    findings = db.query(Finding).filter(Finding.project_id == project_id).order_by(Finding.id.asc()).all()
    browser_sessions_export = db.query(BrowserSession).filter(BrowserSession.project_id == project_id).order_by(BrowserSession.id.asc()).all()
    auth_cases = db.query(AuthorizationCase).filter(AuthorizationCase.project_id == project_id).order_by(AuthorizationCase.id.asc()).all()
    capsules = db.query(ProofCapsule).filter(ProofCapsule.project_id == project_id).order_by(ProofCapsule.id.asc()).all()
    proof_map = {c.finding_id: c for c in capsules}
    latest_plan = db.query(SkillPlan).filter(SkillPlan.project_id == project_id).order_by(SkillPlan.id.desc()).first()
    execution_graph = graph_payload(db, latest_plan.id) if latest_plan else {"node_count": 0, "status_counts": {}}
    selected_skills = enabled_skills(db, project_id)
    agent, _ = _latest_agent(db, project_id)
    report_skill_run = start_skill_run(db, project_id, "reporting", f"project:{project_id}", agent, "reporting")
    lines = [
        f"# {project.name} — 授权渗透测试报告",
        "",
        "## 执行摘要",
        "",
        f"Assets: {stats['assets']} | Services: {stats['services']} | Route candidates: {stats['routes']} | Findings: {stats['findings']}",
        "",
        "## 已启用技能",
        "",
    ]
    if selected_skills:
        for skill in selected_skills:
            lines.append(f"- {skill.name} (`{skill.slug}`) — {skill.execution_mode}")
    else:
        lines.append("- 未启用技能。")
    lines += [
        "",
        "## 权限测试摘要",
        "",
    ]
    if auth_cases:
        for case in auth_cases:
            lines.append(f"- Case #{case.id}: {case.test_type} → {case.classification} ({case.confidence}%)")
    else:
        lines.append("- 暂无权限测试记录。")
    lines += [
        "",
        "## 知识图谱摘要",
        "",
        f"- Nodes: {knowledge_export.get('nodes', 0)}",
        f"- Edges: {knowledge_export.get('edges', 0)}",
        f"- Findings represented: {knowledge_export.get('finding_nodes', 0)}",
        f"- Evidence nodes: {knowledge_export.get('evidence_nodes', 0)}",
        "",
        "## 测试记忆摘要",
        "",
        f"- Memories: {memory_export.get('count', 0)}",
        f"- Avoid-repeat guidance: {memory_export.get('avoid_repeat', 0)}",
        f"- Needs review / retest: {memory_export.get('needs_review', 0)}",
        "",
        "## 专家复核",
        "",
    ]
    if latest_team_export:
        lines.append(f"- Team run #{latest_team_export.id}: {latest_team_export.status} — {latest_team_export.summary}")
        lines.append(f"- Specialist runs: {len(specialist_export.get('runs', []))}")
        lines.append(f"- Handoffs: {len(specialist_export.get('handoffs', []))}")
        lines.append(f"- Intent drift blocked: {specialist_export.get('drift_blocked', 0)}")
    else:
        lines.append("- 暂无专家复核记录。")
    lines += [
        "",
        "## 覆盖情况摘要",
        "",
        f"- Coverage score: {coverage_export.get('score', 0)}/100",
        f"- Covered: {coverage_export.get('covered', 0)}",
        f"- Partial: {coverage_export.get('partial', 0)}",
        f"- Gaps: {coverage_export.get('gap', 0)}",
        f"- Needs review: {coverage_export.get('needs_review', 0)}",
        "",
        "## 整改摘要",
        "",
        f"- Total workflow items: {remediation_export.get('count', 0)}",
        f"- Open work: {remediation_export.get('open', 0)}",
        f"- In remediation: {remediation_export.get('remediation', 0)}",
        f"- Retest ready: {remediation_export.get('retest_ready', 0)}",
        f"- Resolved: {remediation_export.get('resolved', 0)}",
        "",
        "## 浏览器观察摘要",
        "",
    ]
    if browser_sessions_export:
        for session in browser_sessions_export:
            try:
                summary = json.loads(session.summary_json or "{}")
            except Exception:
                summary = {}
            lines.append(
                f"- Browser Session #{session.id}: {session.status} | {session.target_url} | "
                f"requests={summary.get('requests', 0)} | xhr/fetch={summary.get('xhr_fetch', 0)} | "
                f"blocked_out_of_scope={summary.get('blocked_out_of_scope', 0)}"
            )
    else:
        lines.append("- 暂无浏览器观察记录。")
    lines += [
        "",
        "## 执行过程摘要",
        "",
    ]
    if latest_plan:
        lines.append(f"- Plan #{latest_plan.id}: {latest_plan.status} | nodes={execution_graph.get('node_count', 0)} | agent_run={latest_plan.executed_agent_run_id or '—'}")
        for status, count in execution_graph.get("status_counts", {}).items():
            lines.append(f"  - {status}: {count}")
    else:
        lines.append("- 暂无技能执行计划。")
    lines += [
        "",
        "## 漏洞验证摘要",
        "",
    ]
    if capsules:
        for capsule in capsules:
            lines.append(f"- Finding #{capsule.finding_id}: {capsule.verifier_type} → {capsule.status} | retests={capsule.retest_count}")
    else:
        lines.append("- 暂无自动验证包；人工复测见漏洞详情。")
    lines += [
        "",
        "## 漏洞清单",
        "",
    ]
    for finding in findings:
        lines += [
            f"### [{SEVERITY_ZH.get(finding.severity,finding.severity)}] {finding.title}",
            "",
            f"**目标：** `{finding.target}`",
            "",
            f"**验证状态：** {STATUS_ZH.get(finding.verification_state,finding.verification_state)}",
            f"**类型 / 参数：** {finding.vuln_type} / {finding.parameter}",
            f"**分类：** {finding.cwe_id} · {finding.txb02_category} · {finding.owasp_category}",
            "",
            finding.description,
            "",
            "**修复建议**",
            "",
            finding.recommendation,
            "",
        ]
    finish_skill_run(db, report_skill_run, "done", {
        "format": "markdown",
        "findings": len(findings),
        "authorization_cases": len(auth_cases),
        "enabled_skills": len(selected_skills),
    }, agent)
    return PlainTextResponse("\n".join(lines), media_type="text/markdown; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="project-{project_id}-report.md"'})


@app.get("/projects/{project_id}/reports/export.html", response_class=HTMLResponse)
def export_report_html(project_id: int, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    rebuild_knowledge_graph(db, project_id)
    refresh_assessment_memory(db, project_id)
    knowledge_html = graph_summary(db, project_id)
    memory_html = memory_summary(db, project_id)
    latest_team_html = (
        db.query(AgentRun)
        .filter(AgentRun.project_id == project_id, AgentRun.mission.like("Run an analysis-only specialist team%"))
        .order_by(AgentRun.id.desc())
        .first()
    )
    specialist_html = team_summary(db, project_id, latest_team_html.id if latest_team_html else None)
    ensure_project_lifecycles(db, project_id)
    coverage_html = coverage_payload(latest_coverage(db, project, refresh=True))
    remediation_html = remediation_summary(db, project_id)
    findings = db.query(Finding).filter(Finding.project_id == project_id).order_by(Finding.id.asc()).all()
    browser_sessions_html = db.query(BrowserSession).filter(BrowserSession.project_id == project_id).order_by(BrowserSession.id.asc()).all()
    auth_cases = db.query(AuthorizationCase).filter(AuthorizationCase.project_id == project_id).order_by(AuthorizationCase.id.asc()).all()
    capsules = db.query(ProofCapsule).filter(ProofCapsule.project_id == project_id).order_by(ProofCapsule.id.asc()).all()
    proof_map = {c.finding_id: c for c in capsules}
    latest_plan = db.query(SkillPlan).filter(SkillPlan.project_id == project_id).order_by(SkillPlan.id.desc()).first()
    execution_graph = graph_payload(db, latest_plan.id) if latest_plan else {"node_count": 0, "status_counts": {}}
    selected_skills = enabled_skills(db, project_id)
    stats = _project_stats(db, project_id)
    agent, _ = _latest_agent(db, project_id)
    report_skill_run = start_skill_run(db, project_id, "reporting", f"project:{project_id}", agent, "reporting")
    esc = __import__('html').escape
    blocks = []
    skill_items = "".join(
        f"<li>{esc(skill.name)} (<code>{esc(skill.slug)}</code>) — {esc(skill.execution_mode)}</li>"
        for skill in selected_skills
    ) or "<li>未启用技能。</li>"
    blocks.append(f"<section><h2>已启用技能</h2><ul>{skill_items}</ul></section>")
    auth_items = "".join(
        f"<li>Case #{case.id}: {esc(case.test_type)} &rarr; {esc(case.classification)} ({case.confidence}%)</li>"
        for case in auth_cases
    ) or "<li>暂无权限测试记录。</li>"
    blocks.append(f"<section><h2>权限测试摘要</h2><ul>{auth_items}</ul></section>")
    blocks.append(
        f"<section><h2>知识图谱摘要</h2>"
        f"<p>Nodes {knowledge_html.get('nodes', 0)} · Edges {knowledge_html.get('edges', 0)} · "
        f"Finding nodes {knowledge_html.get('finding_nodes', 0)} · Evidence nodes {knowledge_html.get('evidence_nodes', 0)}</p></section>"
    )
    blocks.append(
        f"<section><h2>测试记忆摘要</h2>"
        f"<p>Memories {memory_html.get('count', 0)} · Avoid-repeat {memory_html.get('avoid_repeat', 0)} · "
        f"Review/retest {memory_html.get('needs_review', 0)}</p></section>"
    )
    if latest_team_html:
        blocks.append(
            f"<section><h2>专家复核</h2>"
            f"<p>Team run #{latest_team_html.id}: {esc(latest_team_html.status)} · "
            f"specialists={len(specialist_html.get('runs', []))} · handoffs={len(specialist_html.get('handoffs', []))} · "
            f"drift_blocked={specialist_html.get('drift_blocked', 0)}</p>"
            f"<p>{esc(latest_team_html.summary or '')}</p></section>"
        )
    else:
        blocks.append("<section><h2>专家复核</h2><p>暂无专家复核记录。</p></section>")
    blocks.append(
        f"<section><h2>覆盖情况摘要</h2>"
        f"<p>Score {coverage_html.get('score', 0)}/100 · covered {coverage_html.get('covered', 0)} · "
        f"partial {coverage_html.get('partial', 0)} · gaps {coverage_html.get('gap', 0)} · "
        f"review {coverage_html.get('needs_review', 0)}</p></section>"
    )
    blocks.append(
        f"<section><h2>整改摘要</h2>"
        f"<p>Total {remediation_html.get('count', 0)} · open {remediation_html.get('open', 0)} · "
        f"remediation {remediation_html.get('remediation', 0)} · retest ready {remediation_html.get('retest_ready', 0)} · "
        f"resolved {remediation_html.get('resolved', 0)}</p></section>"
    )
    browser_items = []
    for session in browser_sessions_html:
        try:
            summary = json.loads(session.summary_json or "{}")
        except Exception:
            summary = {}
        browser_items.append(
            f"<li>Session #{session.id}: {esc(session.status)} · <code>{esc(session.target_url)}</code> · "
            f"requests={summary.get('requests', 0)} · xhr/fetch={summary.get('xhr_fetch', 0)} · "
            f"blocked={summary.get('blocked_out_of_scope', 0)}</li>"
        )
    blocks.append(
        "<section><h2>浏览器观察摘要</h2><ul>"
        + ("".join(browser_items) if browser_items else "<li>暂无浏览器观察记录。</li>")
        + "</ul></section>"
    )
    if latest_plan:
        graph_items = "".join(
            f"<li>{esc(str(status))}: {count}</li>"
            for status, count in execution_graph.get("status_counts", {}).items()
        ) or "<li>暂无执行状态。</li>"
        blocks.append(f"<section><h2>执行过程摘要</h2><p>Plan #{latest_plan.id} · {esc(latest_plan.status)} · {execution_graph.get('node_count', 0)} nodes</p><ul>{graph_items}</ul></section>")
    else:
        blocks.append("<section><h2>执行过程摘要</h2><p>暂无技能执行计划。</p></section>")
    proof_items = "".join(
        f"<li>Finding #{c.finding_id}: {esc(c.verifier_type)} &rarr; {esc(c.status)} · retests={c.retest_count}</li>"
        for c in capsules
    ) or "<li>暂无自动验证包；人工复测见漏洞详情。</li>"
    blocks.append(f"<section><h2>漏洞验证摘要</h2><ul>{proof_items}</ul></section>")
    for finding in findings:
        verification = finding.verification_state
        blocks.append(f"<section><h2>[{esc(SEVERITY_ZH.get(finding.severity,finding.severity))}] {esc(finding.title)}</h2><code>{esc(finding.target)}</code><p><b>验证状态：</b> {esc(STATUS_ZH.get(verification,verification))}</p><p>{esc(finding.description)}</p><h3>修复建议</h3><p>{esc(finding.recommendation)}</p></section>")
    body = f"""<!doctype html><html><head><meta charset='utf-8'><title>{esc(project.name)} Report</title><style>body{{font:15px/1.6 system-ui;max-width:900px;margin:48px auto;padding:0 24px;color:#18202a}}code{{background:#f2f4f7;padding:3px 6px}}section{{border-top:1px solid #ddd;padding:18px 0}}.summary{{padding:16px;background:#f5f7fa}}</style></head><body><h1>{esc(project.name)}</h1><p>授权渗透测试报告</p><div class='summary'>Assets {stats['assets']} · Services {stats['services']} · Routes {stats['routes']} · Findings {stats['findings']}</div>{''.join(blocks)}</body></html>"""
    finish_skill_run(db, report_skill_run, "done", {
        "format": "html",
        "findings": len(findings),
        "authorization_cases": len(auth_cases),
        "enabled_skills": len(selected_skills),
    }, agent)
    return HTMLResponse(body, headers={"Content-Disposition": f'attachment; filename="project-{project_id}-report.html"'})



@app.get("/projects/{project_id}/reports/export.docx")
def export_report_docx(project_id: int, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    payload = generate_txb02_docx(db, project)
    desired_name = f"{project.name}_txb02_report.docx"
    return Response(
        content=payload,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": _download_disposition(desired_name, f"project_{project_id}_txb02_report.docx")},
    )


@app.get("/projects/{project_id}/settings", response_class=HTMLResponse)
def project_settings(project_id: int, request: Request, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    context = _project_context(db, project, "settings")
    try:
        project_testers = json.loads(project.testers_json or "[]")
    except Exception:
        project_testers = []
    personal_ai = ai_runtime_settings(db)
    context.update({
        "project_testers": project_testers,
        "request_timeout": settings.request_timeout_seconds,
        "max_body": settings.max_response_body_bytes,
        "max_tasks": settings.max_project_tasks,
        "ai_include_response_body": settings.ai_include_response_body,
        "api_base": personal_ai.get("api_base") or settings.ai_api_base,
        "secret_key_configured": settings.app_secret_key not in {"", "CHANGE-ME-IN-PRODUCTION", "replace-with-a-long-random-secret"},
        "authorization_auto_candidate_findings": settings.authorization_auto_candidate_findings,
        "authorization_auto_candidate_min_confidence": settings.authorization_auto_candidate_min_confidence,
    })
    return templates.TemplateResponse(request=request, name="settings.html", context=context)


@app.post("/projects/{project_id}/settings/engagement")
def update_engagement_settings(
    project_id: int,
    client_name: str = Form(""),
    environment: str = Form("test"),
    engagement_type: str = Form("authorized_pentest"),
    project_status: str = Form("preparing"),
    start_date: str = Form(""),
    end_date: str = Form(""),
    testers: str = Form(""),
    authorization_note: str = Form(""),
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    allowed_statuses = {"preparing", "testing", "paused", "remediation", "retesting", "completed", "archived"}
    if project_status not in allowed_statuses:
        raise HTTPException(400, "Invalid project status.")
    project.client_name = client_name.strip()[:240]
    project.environment = environment.strip()[:80] or "test"
    project.engagement_type = engagement_type.strip()[:80] or "authorized_pentest"
    project.status = project_status
    project.start_date = start_date.strip()[:32]
    project.end_date = end_date.strip()[:32]
    project.authorization_note = authorization_note.strip()[:12000]
    project.testers_json = json.dumps(
        [x.strip() for x in testers.replace("，", ",").split(",") if x.strip()][:50],
        ensure_ascii=False,
    )
    db.commit()
    return RedirectResponse(f"/projects/{project_id}/settings?saved=1", status_code=303)


@app.get("/projects/{project_id}/export")
def export_project(project_id: int, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    payload = export_project_zip(db, project)
    desired_name = f"{project.name}_sanitized_v1_6_2.zip"
    return Response(
        content=payload,
        media_type="application/zip",
        headers={"Content-Disposition": _download_disposition(desired_name, f"project_{project.id}_sanitized_v1_6_2.zip")},
    )


@app.post("/projects/import")
async def import_project(
    package: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    raw = await package.read(10 * 1024 * 1024 + 1)
    try:
        manifest = parse_project_zip(raw)
        project = import_project_manifest(db, manifest)
        seed_builtin_skills(db)
        ensure_project_skill_rows(db, project.id)
        sync_project_endpoint_inventory(db, project.id)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return RedirectResponse(f"/projects/{project.id}/settings?imported=1", status_code=303)


@app.get("/findings/{finding_id}", response_class=HTMLResponse)
def finding_page(finding_id: int, request: Request, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404)
    project = db.get(Project, finding.project_id)
    ensure_finding_metadata(db, finding)
    evidence = db.query(Evidence).filter(Evidence.finding_id == finding_id).order_by(Evidence.id.asc()).all()
    evidence_chains = {e.id: evidence_chain_payload(db, e) for e in evidence}
    proof_capsule = (
        db.query(ProofCapsule)
        .filter(ProofCapsule.finding_id == finding_id)
        .order_by(ProofCapsule.id.desc())
        .first()
    )
    retest_runs = []
    proof_payload = None
    if proof_capsule:
        proof_payload = capsule_payload(proof_capsule)
        retest_runs = (
            db.query(RetestRun)
            .filter(RetestRun.proof_capsule_id == proof_capsule.id)
            .order_by(RetestRun.id.desc())
            .limit(30)
            .all()
        )
    lifecycle = ensure_lifecycle(db, finding)
    attachments = finding_attachments(db, finding.id)
    from .models import RemediationEvent
    manual_history=db.query(RemediationEvent).filter(RemediationEvent.finding_id==finding.id,RemediationEvent.event_type.in_(['finding_created','finding_edited','evidence_added','manual_retest_recorded'])).order_by(RemediationEvent.id.desc()).limit(50).all()
    context = _project_context(db, project, "findings")
    context.update({
        "finding": finding,
        "manual_history": manual_history,
        "finding_lifecycle": lifecycle,
        "evidence": evidence,
        "evidence_chains": evidence_chains,
        "attachments": attachments,
        "finding_states": sorted(FINDING_STATES),
        "verification_states": sorted(VERIFICATION_STATES),
        "remediation_states": sorted(REMEDIATION_STATES),
        "proof_capsule": proof_capsule,
        "proof_payload": proof_payload,
        "retest_runs": retest_runs,
        "finding_quality": finding_quality(db, finding),
    })
    return templates.TemplateResponse(request=request, name="finding.html", context=context)



@app.post("/findings/{finding_id}/states")
def update_finding_state_route(
    finding_id: int,
    finding_state: str = Form(...),
    remediation_state: str = Form(...),
    verification_state: str = Form(...),
    db: Session = Depends(get_db),
):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404)
    try:
        update_finding_states(
            db,
            finding,
            finding_state=finding_state,
            remediation_state=remediation_state,
            verification_state=verification_state,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return RedirectResponse(f"/findings/{finding_id}", status_code=303)


@app.post("/findings/{finding_id}/proof-capsule")
def create_finding_proof_capsule(finding_id: int, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404)
    capsule = get_or_create_capsule(db, finding)
    lifecycle = ensure_lifecycle(db, finding)
    lifecycle.proof_capsule_id = capsule.id
    db.commit()
    return RedirectResponse(f"/findings/{finding_id}#proof-capsule", status_code=303)


@app.post("/findings/{finding_id}/proof-capsule/retest")
def retest_finding_proof_capsule(
    finding_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404)
    project = db.get(Project, finding.project_id)
    if not project:
        raise HTTPException(404)
    lifecycle = ensure_lifecycle(db, finding)
    lifecycle.retest_status = "queued"
    lifecycle.status = "retest_ready"
    db.commit()
    job = enqueue_job(
        db,
        project,
        "proof_retest",
        target=f"finding:{finding.id}",
        payload={"lifecycle_id": lifecycle.id},
        priority=40,
        timeout_seconds=180,
        max_attempts=1,
    )
    background_tasks.add_task(run_job_now, job.id)
    return RedirectResponse(f"/findings/{finding_id}#proof-capsule", status_code=303)


@app.get("/api/health")
def health():
    return {"ok": True, "version": VERSION, "ai_provider": current_ai_provider_name()}


@app.get("/api/projects/{project_id}/scope-check")
def scope_check(project_id: int, target: str, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    return {"target": target, "allowed": target_in_scope(target, _scope_rules(project))}


@app.get("/api/projects/{project_id}/status")
def project_status(project_id: int, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)

    tasks = db.query(Task).filter(Task.project_id == project_id).order_by(Task.id.desc()).limit(20).all()
    run, events = _latest_agent(db, project_id)
    return {
        "stats": _project_stats(db, project_id),
        "tasks": [
            {
                "id": t.id,
                "action": t.action,
                "target": t.target,
                "policy_class": t.policy_class,
                "status": t.status,
                "detail": t.detail,
            }
            for t in tasks
        ],
        "agent": None if not run else {
            "id": run.id,
            "target": run.target,
            "mission": run.mission,
            "stage": run.stage,
            "status": run.status,
            "summary": run.summary,
            "events": [
                {
                    "id": e.id,
                    "event_type": e.event_type,
                    "stage": e.stage,
                    "title": e.title,
                    "detail": e.detail,
                    "policy_class": e.policy_class,
                    "status": e.status,
                }
                for e in events
            ],
        },
    }

from .hash_routes import router as hash_analysis_router
app.include_router(hash_analysis_router)
