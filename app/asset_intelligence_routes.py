from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.requests import Request

from .db import get_db
from .models import (
    Asset, BatchAssessment, BatchAssessmentItem, BrowserSession, Endpoint, FingerprintRule, NetworkRouteProfile,
    Project, ScanProfile, SkillDefinition, ProjectSkill, TechnologyFingerprint,
)
from .services.batch_assessment import create_batch
from .services.fingerprint_engine import SAFE_CATEGORIES, SAFE_SOURCES, fingerprint_recommendation, refresh_project_fingerprints
from .services.job_engine import enqueue_job, run_job_now
from .services.network_routes import create_route_profile, route_payload, select_route
from .services.scan_profiles import apply_profile, capture_profile, profile_payload
from .scope import target_in_scope
from .ui_i18n import configure_templates

BASE_DIR = Path(__file__).resolve().parent
templates = configure_templates(Jinja2Templates(directory=BASE_DIR / "templates"))
router = APIRouter()


def _context(db: Session, project: Project, active_nav: str) -> dict:
    from .main import _project_context
    return _project_context(db, project, active_nav)


@router.get("/projects/{project_id}/asset-intelligence", response_class=HTMLResponse)
def asset_intelligence(project_id: int, request: Request, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    # Local-only refresh: reads existing Evidence/Artifacts/Service banners, performs no network access.
    fp_summary = refresh_project_fingerprints(db, project)
    fingerprints = (
        db.query(TechnologyFingerprint)
        .filter(TechnologyFingerprint.project_id == project_id)
        .order_by(TechnologyFingerprint.confidence.desc(), TechnologyFingerprint.id.desc())
        .all()
    )
    rules = (
        db.query(FingerprintRule)
        .filter((FingerprintRule.project_id.is_(None)) | (FingerprintRule.project_id == project_id))
        .order_by(FingerprintRule.id.desc()).all()
    )
    profiles = db.query(ScanProfile).order_by(ScanProfile.name.asc()).all()
    route_profiles = db.query(NetworkRouteProfile).filter(NetworkRouteProfile.enabled == 1).order_by(NetworkRouteProfile.name.asc()).all()
    batches = db.query(BatchAssessment).filter(BatchAssessment.project_id == project_id).order_by(BatchAssessment.id.desc()).limit(30).all()
    batch_items = {
        b.id: db.query(BatchAssessmentItem).filter(BatchAssessmentItem.batch_id == b.id).order_by(BatchAssessmentItem.id.asc()).all()
        for b in batches
    }
    skill_rows = (
        db.query(SkillDefinition, ProjectSkill)
        .join(ProjectSkill, ProjectSkill.skill_id == SkillDefinition.id)
        .filter(ProjectSkill.project_id == project_id)
        .order_by(SkillDefinition.name.asc()).all()
    )
    context = _context(db, project, "asset_intelligence")
    context.update({
        "fingerprints": fingerprints,
        "fingerprint_summary": fp_summary,
        "fingerprint_recommendations": {x.id: fingerprint_recommendation(x) for x in fingerprints},
        "fingerprint_rules": rules,
        "safe_categories": sorted(SAFE_CATEGORIES),
        "safe_sources": sorted(SAFE_SOURCES),
        "scan_profiles": profiles,
        "scan_profile_payloads": {p.id: profile_payload(p) for p in profiles},
        "active_scan_profile": db.get(ScanProfile, project.scan_profile_id) if project.scan_profile_id else None,
        "route_profiles": route_profiles,
        "route_payloads": {r.id: route_payload(r) for r in route_profiles},
        "active_route_profile": db.get(NetworkRouteProfile, project.network_route_profile_id) if project.network_route_profile_id else None,
        "batch_runs": batches,
        "batch_items": batch_items,
        "skill_rows": skill_rows,
        "asset_map": {a.id: a.target for a in db.query(Asset).filter(Asset.project_id == project_id).all()},
    })
    return templates.TemplateResponse(request=request, name="asset_intelligence.html", context=context)




@router.post("/projects/{project_id}/context/endpoints/{endpoint_id}/browser")
def endpoint_browser_action(
    project_id: int, endpoint_id: int, background_tasks: BackgroundTasks, db: Session = Depends(get_db),
):
    project=db.get(Project,project_id); endpoint=db.get(Endpoint,endpoint_id)
    if not project or not endpoint: raise HTTPException(404)
    asset=db.get(Asset,endpoint.asset_id)
    rules=[x.strip() for x in project.scope_text.splitlines() if x.strip()]
    if not asset or asset.project_id != project_id or not target_in_scope(endpoint.url,rules):
        raise HTTPException(400,"Endpoint is outside the current authorized scope.")
    session=BrowserSession(project_id=project_id,target_url=endpoint.url,status="queued")
    db.add(session);db.commit();db.refresh(session)
    job=enqueue_job(db,project,"browser_observe",target=endpoint.url,payload={"session_id":session.id,"identity_id":None},priority=70,timeout_seconds=180,max_attempts=1)
    background_tasks.add_task(run_job_now,job.id)
    return RedirectResponse(f"/projects/{project_id}/browser?selected={session.id}&job={job.id}",status_code=303)


@router.post("/projects/{project_id}/fingerprints/refresh")
def refresh_fingerprints(project_id: int, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    refresh_project_fingerprints(db, project)
    return RedirectResponse(f"/projects/{project_id}/asset-intelligence#fingerprints", status_code=303)


@router.post("/projects/{project_id}/fingerprint-rules")
def create_fingerprint_rule(
    project_id: int,
    name: str = Form(...), product: str = Form(...), category: str = Form("technology"),
    source: str = Form("body"), header_name: str = Form(""), pattern: str = Form(...),
    confidence: int = Form(80), global_rule: str = Form(""),
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    if category not in SAFE_CATEGORIES or source not in SAFE_SOURCES:
        raise HTTPException(400, "Unsupported fingerprint category/source.")
    if not pattern.strip() or len(pattern.strip()) > 300:
        raise HTTPException(400, "Fingerprint contains pattern must be 1-300 characters.")
    row = FingerprintRule(
        project_id=None if global_rule == "on" else project_id,
        name=name.strip()[:200], category=category, product=product.strip()[:200],
        source=source, header_name=header_name.strip()[:120], pattern=pattern.strip()[:300],
        confidence=max(1, min(int(confidence), 100)), enabled=1,
    )
    db.add(row); db.commit()
    refresh_project_fingerprints(db, project)
    return RedirectResponse(f"/projects/{project_id}/asset-intelligence#rules", status_code=303)


@router.post("/projects/{project_id}/fingerprint-rules/{rule_id}/delete")
def delete_fingerprint_rule(project_id: int, rule_id: int, db: Session = Depends(get_db)):
    project = db.get(Project, project_id); row = db.get(FingerprintRule, rule_id)
    if not project or not row:
        raise HTTPException(404)
    if row.project_id not in {None, project_id}:
        raise HTTPException(403)
    # Global custom rules can be deleted from any project in this single-user product.
    db.delete(row); db.commit()
    return RedirectResponse(f"/projects/{project_id}/asset-intelligence#rules", status_code=303)


@router.post("/projects/{project_id}/scan-profiles/capture")
def capture_scan_profile(
    project_id: int, name: str = Form(...), description: str = Form(""), batch_target_limit: int = Form(20),
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    try:
        profile = capture_profile(db, project, name, description, batch_target_limit)
        apply_profile(db, project, profile)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return RedirectResponse(f"/projects/{project_id}/asset-intelligence#profiles", status_code=303)


@router.post("/projects/{project_id}/scan-profiles/{profile_id}/apply")
def apply_scan_profile(project_id: int, profile_id: int, db: Session = Depends(get_db)):
    project = db.get(Project, project_id); profile = db.get(ScanProfile, profile_id)
    if not project or not profile:
        raise HTTPException(404)
    apply_profile(db, project, profile)
    return RedirectResponse(f"/projects/{project_id}/asset-intelligence#profiles", status_code=303)


@router.post("/projects/{project_id}/scan-profiles/{profile_id}/delete")
def delete_scan_profile(project_id: int, profile_id: int, db: Session = Depends(get_db)):
    project = db.get(Project, project_id); profile = db.get(ScanProfile, profile_id)
    if not project or not profile:
        raise HTTPException(404)
    if project.scan_profile_id == profile.id:
        project.scan_profile_id = None
    db.delete(profile); db.commit()
    return RedirectResponse(f"/projects/{project_id}/asset-intelligence#profiles", status_code=303)


@router.post("/projects/{project_id}/network-routes")
def add_network_route(
    project_id: int, name: str = Form(...), route_type: str = Form("direct"),
    host: str = Form(""), port: int = Form(0), username: str = Form(""), password: str = Form(""), notes: str = Form(""),
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    try:
        row = create_route_profile(db, name=name, route_type=route_type, host=host, port=port, username=username, password=password, notes=notes)
        select_route(db, project, row.id)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return RedirectResponse(f"/projects/{project_id}/asset-intelligence#routes", status_code=303)


@router.post("/projects/{project_id}/network-routes/select")
def choose_network_route(project_id: int, route_id: str = Form(""), db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    try:
        select_route(db, project, int(route_id) if route_id.strip() else None)
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, str(exc))
    return RedirectResponse(f"/projects/{project_id}/asset-intelligence#routes", status_code=303)


@router.post("/projects/{project_id}/batch-assessments")
def create_batch_assessment(
    project_id: int, background_tasks: BackgroundTasks,
    name: str = Form("Batch Assessment"), targets: str = Form(...), profile_id: str = Form(""),
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    from .scan_routes import prepare_scan_draft
    return prepare_scan_draft(db,project,targets)
