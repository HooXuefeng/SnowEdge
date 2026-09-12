from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.requests import Request

from .db import SessionLocal, get_db
from .ui_i18n import configure_templates
from .models import (
    CopilotQuery,
    CoverageSnapshot,
    Finding,
    FindingLifecycle,
    Project,
    RemediationEvent,
    RetestRun,
)
from .services.analyst_copilot import (
    copilot_payload,
    create_copilot_query,
    resolve_citation,
    run_copilot_query,
)
from .services.assessment_memory import refresh_assessment_memory
from .services.coverage_matrix import coverage_dimension_summary, coverage_payload, latest_coverage, snapshot_coverage
from .services.knowledge_graph import rebuild_knowledge_graph
from .services.job_engine import enqueue_job, run_job_now
from .services.remediation import (
    VALID_PRIORITIES,
    VALID_STATUSES,
    ensure_project_lifecycles,
    remediation_summary,
    retest_lifecycle,
    update_lifecycle,
)

BASE_DIR = Path(__file__).resolve().parent
templates = configure_templates(Jinja2Templates(directory=BASE_DIR / "templates"))
router = APIRouter()


def _context(db: Session, project: Project, active_nav: str) -> dict:
    from .main import _project_context
    return _project_context(db, project, active_nav)


def _loads(raw: str, default):
    try:
        return json.loads(raw or "")
    except Exception:
        return default


@router.get("/projects/{project_id}/coverage", response_class=HTMLResponse)
def coverage_page(
    project_id: int,
    request: Request,
    snapshot: int | None = None,
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)

    selected = db.get(CoverageSnapshot, snapshot) if snapshot else None
    if selected and selected.project_id != project_id:
        selected = None
    if selected is None:
        selected = latest_coverage(db, project)

    history = (
        db.query(CoverageSnapshot)
        .filter(CoverageSnapshot.project_id == project_id)
        .order_by(CoverageSnapshot.id.desc())
        .limit(30)
        .all()
    )
    payload = coverage_payload(selected)
    categories = {}
    for item in payload["matrix"]:
        categories.setdefault(item["category"], []).append(item)

    context = _context(db, project, "coverage")
    context.update({
        "coverage": payload,
        "coverage_categories": categories,
        "coverage_history": history,
        "coverage_dimensions": coverage_dimension_summary(db, project),
    })
    return templates.TemplateResponse(request=request, name="coverage.html", context=context)


@router.post("/projects/{project_id}/coverage/refresh")
def refresh_coverage(project_id: int, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    rebuild_knowledge_graph(db, project_id)
    refresh_assessment_memory(db, project_id)
    row = snapshot_coverage(db, project)
    return RedirectResponse(f"/projects/{project_id}/coverage?snapshot={row.id}", status_code=303)


async def _run_copilot_background(project_id: int, query_id: int):
    db = SessionLocal()
    try:
        project = db.get(Project, project_id)
        row = db.get(CopilotQuery, query_id)
        if not project or not row or row.project_id != project_id:
            return
        await run_copilot_query(db, project, row)
    finally:
        db.close()


@router.get("/projects/{project_id}/copilot", response_class=HTMLResponse)
def copilot_page(
    project_id: int,
    request: Request,
    selected: int | None = None,
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)

    history = (
        db.query(CopilotQuery)
        .filter(CopilotQuery.project_id == project_id)
        .order_by(CopilotQuery.id.desc())
        .limit(40)
        .all()
    )
    row = db.get(CopilotQuery, selected) if selected else (history[0] if history else None)
    if row and row.project_id != project_id:
        row = None

    payload = copilot_payload(row) if row else None
    citations = []
    if payload:
        for ref in payload["answer"].get("citations", []):
            resolved = resolve_citation(db, project_id, ref)
            if resolved:
                citations.append(resolved)

    context = _context(db, project, "copilot")
    context.update({
        "copilot_history": history,
        "selected_query": row,
        "copilot": payload,
        "copilot_citations": citations,
    })
    return templates.TemplateResponse(request=request, name="copilot.html", context=context)


@router.post("/projects/{project_id}/copilot")
def create_copilot(
    project_id: int,
    background_tasks: BackgroundTasks,
    question: str = Form(...),
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    try:
        row = create_copilot_query(db, project, question)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    job = enqueue_job(
        db,
        project,
        "copilot_query",
        target=f"copilot:{row.id}",
        payload={"query_id": row.id},
        priority=90,
        timeout_seconds=180,
        max_attempts=2,
    )
    background_tasks.add_task(run_job_now, job.id)
    return RedirectResponse(
        f"/projects/{project_id}/copilot?selected={row.id}&job={job.id}",
        status_code=303,
    )


@router.get("/api/projects/{project_id}/copilot/{query_id}")
def copilot_status(project_id: int, query_id: int, db: Session = Depends(get_db)):
    row = db.get(CopilotQuery, query_id)
    if not row or row.project_id != project_id:
        raise HTTPException(404)
    payload = copilot_payload(row)
    return {
        "id": row.id,
        "status": row.status,
        "citation_count": row.citation_count,
        "drift_count": row.drift_count,
        "answer_ready": bool(payload.get("answer", {}).get("answer")),
    }


async def _run_retest_background(project_id: int, lifecycle_id: int):
    db = SessionLocal()
    try:
        project = db.get(Project, project_id)
        lifecycle = db.get(FindingLifecycle, lifecycle_id)
        if not project or not lifecycle or lifecycle.project_id != project_id:
            return
        try:
            await retest_lifecycle(db, project, lifecycle)
        finally:
            rebuild_knowledge_graph(db, project_id)
            refresh_assessment_memory(db, project_id)
            snapshot_coverage(db, project)
    finally:
        db.close()


@router.get("/projects/{project_id}/remediation", response_class=HTMLResponse)
def remediation_page(
    project_id: int,
    request: Request,
    selected: int | None = None,
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)

    lifecycles = ensure_project_lifecycles(db, project_id)
    finding_ids = [row.finding_id for row in lifecycles] or [-1]
    findings = {
        f.id: f
        for f in db.query(Finding).filter(Finding.id.in_(finding_ids)).all()
    }
    selected_lifecycle = db.get(FindingLifecycle, selected) if selected else (lifecycles[0] if lifecycles else None)
    if selected_lifecycle and selected_lifecycle.project_id != project_id:
        selected_lifecycle = None

    events = []
    retest = None
    if selected_lifecycle:
        events = (
            db.query(RemediationEvent)
            .filter(RemediationEvent.lifecycle_id == selected_lifecycle.id)
            .order_by(RemediationEvent.id.desc())
            .limit(80)
            .all()
        )
        if selected_lifecycle.last_retest_run_id:
            retest = db.get(RetestRun, selected_lifecycle.last_retest_run_id)

    columns = {status: [] for status in [
        "open", "triaged", "remediation", "retest_ready", "resolved", "accepted_risk", "false_positive"
    ]}
    for row in lifecycles:
        columns.setdefault(row.status, []).append(row)

    context = _context(db, project, "remediation")
    context.update({
        "lifecycles": lifecycles,
        "finding_map": findings,
        "remediation_columns": columns,
        "remediation_summary": remediation_summary(db, project_id),
        "selected_lifecycle": selected_lifecycle,
        "selected_finding": findings.get(selected_lifecycle.finding_id) if selected_lifecycle else None,
        "remediation_events": events,
        "selected_retest": retest,
        "valid_statuses": sorted(VALID_STATUSES),
        "valid_priorities": sorted(VALID_PRIORITIES),
    })
    return templates.TemplateResponse(request=request, name="remediation.html", context=context)


@router.post("/projects/{project_id}/remediation/{lifecycle_id}/update")
def update_remediation(
    project_id: int,
    lifecycle_id: int,
    status: str = Form(...),
    owner: str = Form(""),
    priority: str = Form("normal"),
    remediation_note: str = Form(""),
    db: Session = Depends(get_db),
):
    lifecycle = db.get(FindingLifecycle, lifecycle_id)
    if not lifecycle or lifecycle.project_id != project_id:
        raise HTTPException(404)
    try:
        update_lifecycle(
            db,
            lifecycle,
            status=status,
            owner=owner,
            priority=priority,
            remediation_note=remediation_note,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    rebuild_knowledge_graph(db, project_id)
    refresh_assessment_memory(db, project_id)
    project = db.get(Project, project_id)
    if project:
        snapshot_coverage(db, project)
    return RedirectResponse(f"/projects/{project_id}/remediation?selected={lifecycle_id}", status_code=303)


@router.post("/projects/{project_id}/remediation/{lifecycle_id}/retest")
def queue_retest(
    project_id: int,
    lifecycle_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    lifecycle = db.get(FindingLifecycle, lifecycle_id)
    if not lifecycle or lifecycle.project_id != project_id:
        raise HTTPException(404)

    lifecycle.retest_status = "queued"
    lifecycle.status = "retest_ready"
    db.add(RemediationEvent(
        project_id=project_id,
        finding_id=lifecycle.finding_id,
        lifecycle_id=lifecycle.id,
        event_type="retest_queued",
        from_status=lifecycle.status,
        to_status="retest_ready",
        detail="Retest queued through the Finding Proof Capsule workflow.",
        source="analyst",
    ))
    db.commit()

    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    job = enqueue_job(
        db,
        project,
        "proof_retest",
        target=f"finding:{lifecycle.finding_id}",
        payload={"lifecycle_id": lifecycle.id},
        priority=40,
        timeout_seconds=180,
        max_attempts=1,
    )
    background_tasks.add_task(run_job_now, job.id)
    return RedirectResponse(
        f"/projects/{project_id}/remediation?selected={lifecycle.id}&job={job.id}",
        status_code=303,
    )


@router.get("/api/projects/{project_id}/remediation/{lifecycle_id}")
def remediation_status(project_id: int, lifecycle_id: int, db: Session = Depends(get_db)):
    lifecycle = db.get(FindingLifecycle, lifecycle_id)
    if not lifecycle or lifecycle.project_id != project_id:
        raise HTTPException(404)
    return {
        "id": lifecycle.id,
        "status": lifecycle.status,
        "retest_status": lifecycle.retest_status,
        "proof_capsule_id": lifecycle.proof_capsule_id,
        "last_retest_run_id": lifecycle.last_retest_run_id,
    }
