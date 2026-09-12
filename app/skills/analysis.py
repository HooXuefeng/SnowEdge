from __future__ import annotations
import json
from sqlalchemy.orm import Session
from ..models import (
    Asset, AuthorizationCase, Endpoint, Evidence, Finding, Identity, Project,
    ReplayResult, RouteCandidate, Service, StoredRequest, Task, WebArtifact
)

def coverage_snapshot(db: Session, project_id: int) -> dict:
    assets = db.query(Asset).filter(Asset.project_id == project_id).all()
    asset_ids = [a.id for a in assets] or [-1]
    tasks = db.query(Task).filter(Task.project_id == project_id).all()
    actions = {t.action for t in tasks if t.status == "done"}

    checks = [
        ("network_recon", "port_scan" in actions or db.query(Service).filter(Service.asset_id.in_(asset_ids)).count() > 0),
        ("http_baseline", "http_probe" in actions or db.query(Endpoint).filter(Endpoint.asset_id.in_(asset_ids)).count() > 0),
        ("web_discovery", "web_discovery" in actions or db.query(WebArtifact).filter(WebArtifact.asset_id.in_(asset_ids)).count() > 0),
        ("js_route_mapping", db.query(RouteCandidate).filter(RouteCandidate.asset_id.in_(asset_ids)).count() > 0),
        ("request_validation", db.query(ReplayResult).filter(ReplayResult.project_id == project_id).count() > 0),
        ("authorization_testing", db.query(AuthorizationCase).filter(AuthorizationCase.project_id == project_id).count() > 0),
        ("findings_triage", db.query(Finding).filter(Finding.project_id == project_id).count() > 0),
        ("evidence_capture", db.query(Evidence).join(Task, Evidence.task_id == Task.id).filter(Task.project_id == project_id).count() > 0),
    ]
    covered = [name for name, ok in checks if ok]
    gaps = [name for name, ok in checks if not ok]
    return {
        "covered": covered,
        "gaps": gaps,
        "coverage_percent": round((len(covered) / len(checks)) * 100) if checks else 0,
        "note": "Coverage indicates evidence presence, not exhaustive vulnerability-class testing.",
    }

def guardrail_snapshot() -> dict:
    return {
        "scope_engine": "enforced",
        "unknown_actions": "default-deny",
        "auto_allowed_classes": ["READ_ONLY", "LOW_RISK_VALIDATE"],
        "external_skill_execution": "knowledge-only",
        "arbitrary_shell_from_skill": "disabled",
        "state_change_automation": "disabled by default",
    }
