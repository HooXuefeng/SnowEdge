from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.requests import Request

from .config import settings
from .ai.factory import current_ai_provider_name
from .services.personal_settings import get_personal_settings
from .ui_i18n import configure_templates
from .db import get_db
from .models import (
    AgentRun,
    Asset,
    AuthorizationCase,
    Endpoint,
    Finding,
    Identity,
    Project,
    ReplayResult,
    ResponseDiff,
    RouteCandidate,
    Service,
    StoredRequest,
    Task,
    WebArtifact,
    ProjectSkill,
)
from .services.authorization_testing import promote_authorization_case, run_authorization_case
from .services.knowledge_graph import rebuild_knowledge_graph
from .services.assessment_memory import refresh_assessment_memory

BASE_DIR = Path(__file__).resolve().parent
templates = configure_templates(Jinja2Templates(directory=BASE_DIR / "templates"))
router = APIRouter()


def _scope_rules(project: Project) -> list[str]:
    return [x.strip() for x in project.scope_text.splitlines() if x.strip()]


def _stats(db: Session, project: Project) -> dict:
    assets = db.query(Asset).filter(Asset.project_id == project.id).all()
    asset_ids = [a.id for a in assets] or [-1]
    tasks = db.query(Task).filter(Task.project_id == project.id).all()
    findings = db.query(Finding).filter(Finding.project_id == project.id).all()
    cases = db.query(AuthorizationCase).filter(AuthorizationCase.project_id == project.id).all()
    return {
        "assets": len(assets),
        "services": db.query(Service).filter(Service.asset_id.in_(asset_ids)).count(),
        "endpoints": db.query(Endpoint).filter(Endpoint.asset_id.in_(asset_ids)).count(),
        "web_artifacts": db.query(WebArtifact).filter(WebArtifact.asset_id.in_(asset_ids)).count(),
        "routes": db.query(RouteCandidate).filter(RouteCandidate.asset_id.in_(asset_ids)).count(),
        "findings": len(findings),
        "running_tasks": sum(1 for t in tasks if t.status in {"queued", "running"}),
        "stored_requests": db.query(StoredRequest).filter(StoredRequest.project_id == project.id).count(),
        "identities": db.query(Identity).filter(Identity.project_id == project.id).count(),
        "replays": db.query(ReplayResult).filter(ReplayResult.project_id == project.id).count(),
        "agent_runs": db.query(AgentRun).filter(AgentRun.project_id == project.id).count(),
        "authorization_cases": len(cases),
        "authorization_candidates": sum(1 for c in cases if c.classification.startswith("potential_")),
        "authorization_enforced": sum(1 for c in cases if "enforced" in c.classification),
        "authorization_review": sum(1 for c in cases if c.classification.endswith("needs_review")),
        "skills_enabled": db.query(ProjectSkill).filter(ProjectSkill.project_id == project.id, ProjectSkill.enabled == 1).count(),
    }


def _context(db: Session, project: Project, active_nav: str) -> dict:
    return {
        "project": project,
        "active_nav": active_nav,
        "ai_provider": current_ai_provider_name(),
        "ai_model": get_personal_settings(db).get("ai_model") or settings.ai_model or "Mock / not configured",
        "scope_rules": _scope_rules(project),
        "stats": _stats(db, project),
    }


def _identity_from_form(db: Session, project_id: int, value: str) -> Identity | None:
    value = (value or "").strip()
    if not value or value == "anonymous":
        return None
    try:
        identity_id = int(value)
    except ValueError:
        raise HTTPException(400, "Invalid identity.")
    identity = db.get(Identity, identity_id)
    if not identity or identity.project_id != project_id:
        raise HTTPException(400, "Identity does not belong to this project.")
    return identity


@router.get("/projects/{project_id}/authorization", response_class=HTMLResponse)
def authorization_lab(project_id: int, request: Request, selected: int | None = None, request_id: int | None = None, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)

    stored_requests = (
        db.query(StoredRequest)
        .filter(
            StoredRequest.project_id == project_id,
            StoredRequest.method.in_(["GET", "HEAD"]),
            StoredRequest.policy_class == "READ_ONLY",
        )
        .order_by(StoredRequest.id.desc())
        .all()
    )
    identities = db.query(Identity).filter(Identity.project_id == project_id).order_by(Identity.id.asc()).all()
    cases = db.query(AuthorizationCase).filter(AuthorizationCase.project_id == project_id).order_by(AuthorizationCase.id.desc()).all()
    selected_case = db.get(AuthorizationCase, selected) if selected else (cases[0] if cases else None)
    if selected_case and selected_case.project_id != project_id:
        selected_case = None

    identity_map = {i.id: i for i in identities}
    request_map = {r.id: r for r in stored_requests}
    context = _context(db, project, "authorization")
    context.update({
        "stored_requests": stored_requests,
        "identities": identities,
        "cases": cases,
        "selected_case": selected_case,
        "identity_map": identity_map,
        "request_map": request_map,
        "selected_request_id": request_id if request_id in request_map else None,
        "selected_summary": json.loads(selected_case.summary_json or "{}") if selected_case else {},
    })
    return templates.TemplateResponse(request=request, name="authorization.html", context=context)


@router.post("/projects/{project_id}/authorization/run")
async def run_case(
    project_id: int,
    stored_request_id: int = Form(...),
    test_type: str = Form(...),
    baseline_identity_id: str = Form(""),
    comparison_identity_id: str = Form("anonymous"),
    expected_owner_identity_id: str = Form(""),
    object_label: str = Form(""),
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    stored = db.get(StoredRequest, stored_request_id)
    if not project or not stored or stored.project_id != project_id:
        raise HTTPException(404)

    if stored.method.upper() not in {"GET", "HEAD"} or stored.policy_class != "READ_ONLY":
        raise HTTPException(400, "Authorization automation only accepts READ_ONLY GET/HEAD requests.")

    if test_type not in {"unauthenticated", "horizontal", "vertical"}:
        raise HTTPException(400, "Unsupported authorization test type.")

    baseline = _identity_from_form(db, project_id, baseline_identity_id)
    comparison = _identity_from_form(db, project_id, comparison_identity_id)

    expected_owner = None
    if expected_owner_identity_id.strip():
        owner = _identity_from_form(db, project_id, expected_owner_identity_id)
        if owner is None:
            raise HTTPException(400, "Expected owner must be an authenticated identity.")
        expected_owner = owner.id

    if test_type == "unauthenticated":
        if baseline is None:
            raise HTTPException(400, "Unauthenticated comparison requires an authenticated baseline identity.")
        comparison = None
    elif test_type == "horizontal":
        if baseline is None or comparison is None:
            raise HTTPException(400, "Horizontal testing requires two authenticated identities.")
        if baseline.id == comparison.id:
            raise HTTPException(400, "Horizontal testing requires two different identities.")
    elif test_type == "vertical":
        if baseline is None or comparison is None:
            raise HTTPException(400, "Vertical testing requires two authenticated identities.")
        if baseline.id == comparison.id:
            raise HTTPException(400, "Vertical testing requires two different identities.")

    case = AuthorizationCase(
        project_id=project_id,
        stored_request_id=stored.id,
        test_type=test_type,
        baseline_identity_id=baseline.id if baseline else None,
        comparison_identity_id=comparison.id if comparison else None,
        expected_owner_identity_id=expected_owner,
        object_label=object_label[:300],
        status="queued",
    )
    db.add(case)
    db.commit()
    db.refresh(case)

    try:
        await run_authorization_case(
            db,
            _scope_rules(project),
            case,
            baseline,
            comparison,
            auto_candidate_finding=settings.authorization_auto_candidate_findings,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    rebuild_knowledge_graph(db, project_id)
    refresh_assessment_memory(db, project_id)
    return RedirectResponse(f"/projects/{project_id}/authorization?selected={case.id}", status_code=303)


@router.get("/projects/{project_id}/authorization/{case_id}", response_class=HTMLResponse)
def authorization_case_detail(project_id: int, case_id: int, request: Request, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    case = db.get(AuthorizationCase, case_id)
    if not project or not case or case.project_id != project_id:
        raise HTTPException(404)

    stored = db.get(StoredRequest, case.stored_request_id)
    baseline = db.get(ReplayResult, case.baseline_replay_id) if case.baseline_replay_id else None
    comparison = db.get(ReplayResult, case.comparison_replay_id) if case.comparison_replay_id else None
    diff = db.get(ResponseDiff, case.response_diff_id) if case.response_diff_id else None
    identities = db.query(Identity).filter(Identity.project_id == project_id).all()
    identity_map = {i.id: i for i in identities}

    context = _context(db, project, "authorization")
    context.update({
        "case": case,
        "stored": stored,
        "baseline": baseline,
        "comparison": comparison,
        "diff": diff,
        "summary": json.loads(case.summary_json or "{}"),
        "ai_review": json.loads(case.ai_review_json or "{}"),
        "diff_summary": json.loads(diff.summary_json or "{}") if diff else {},
        "identity_map": identity_map,
    })
    return templates.TemplateResponse(request=request, name="authorization_case.html", context=context)


@router.post("/projects/{project_id}/authorization/{case_id}/promote")
def promote_case(project_id: int, case_id: int, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    case = db.get(AuthorizationCase, case_id)
    if not project or not case or case.project_id != project_id:
        raise HTTPException(404)
    try:
        finding = promote_authorization_case(db, case)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    rebuild_knowledge_graph(db, project_id)
    refresh_assessment_memory(db, project_id)
    return RedirectResponse(f"/findings/{finding.id}", status_code=303)
