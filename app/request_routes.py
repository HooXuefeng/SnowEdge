from __future__ import annotations

import json
import secrets
from pathlib import Path
from urllib.parse import urljoin

from fastapi import APIRouter, Depends, Form, Header, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.requests import Request

from .config import settings
from .ai.factory import current_ai_provider_name
from .services.personal_settings import get_personal_settings, burp_ingest_token
from .services.secret_vault import item_summary
from .services.workspace_drafts import delete_draft, load_draft
from .ui_i18n import configure_templates
from .db import get_db
from .models import Asset, AuthorizationCase, Endpoint, Identity, ReplayResult, ResponseDiff, RouteCandidate, StoredRequest, StoredRequestRevision, SecretVaultItem, ProjectSkill
from .scope import target_in_scope
from .services.request_workspace import create_stored_request, parse_raw_http_request, replay_request, request_raw_text, request_revisions, restore_request_revision, update_stored_request
from .services.response_diff import compare_responses
from .services.knowledge_graph import rebuild_knowledge_graph
from .services.assessment_memory import refresh_assessment_memory
from .services.secret_store import encrypt_json, masked_cookie_summary, masked_header_summary
from .skills.runtime import finish_skill_run, start_skill_run
from .models import Project

BASE_DIR = Path(__file__).resolve().parent
templates = configure_templates(Jinja2Templates(directory=BASE_DIR / "templates"))
router = APIRouter()


def _latest_agent_for_project(db: Session, project_id: int):
    from .models import AgentRun
    return (
        db.query(AgentRun)
        .filter(AgentRun.project_id == project_id)
        .order_by(AgentRun.id.desc())
        .first()
    )


def _pretty_json(raw: str) -> str:
    if not raw:
        return ""
    try:
        return json.dumps(json.loads(raw), ensure_ascii=False, indent=2)
    except Exception:
        return raw


def _scope_rules(project: Project) -> list[str]:
    return [x.strip() for x in project.scope_text.splitlines() if x.strip()]


def _context(db: Session, project: Project, active_nav: str) -> dict:
    from .models import AgentRun, Finding, Service, Task, WebArtifact
    assets = db.query(Asset).filter(Asset.project_id == project.id).all()
    asset_ids = [a.id for a in assets] or [-1]
    tasks = db.query(Task).filter(Task.project_id == project.id).all()
    findings = db.query(Finding).filter(Finding.project_id == project.id).all()
    return {
        "project": project,
        "active_nav": active_nav,
        "ai_provider": current_ai_provider_name(),
        "ai_model": get_personal_settings(db).get("ai_model") or settings.ai_model or "Mock / not configured",
        "scope_rules": _scope_rules(project),
        "stats": {
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
            "authorization_cases": db.query(AuthorizationCase).filter(AuthorizationCase.project_id == project.id).count(),
            "skills_enabled": db.query(ProjectSkill).filter(ProjectSkill.project_id == project.id, ProjectSkill.enabled == 1).count(),
        },
    }


@router.get("/projects/{project_id}/requests", response_class=HTMLResponse)
def request_workspace(project_id: int, request: Request, selected: int | None = None, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    requests = db.query(StoredRequest).filter(StoredRequest.project_id == project_id).order_by(StoredRequest.id.desc()).all()
    identities = db.query(Identity).filter(Identity.project_id == project_id).order_by(Identity.id.asc()).all()
    selected_request = db.get(StoredRequest, selected) if selected else (requests[0] if requests else None)
    if selected_request and selected_request.project_id != project_id:
        selected_request = None
    replays = []
    if selected_request:
        replays = db.query(ReplayResult).filter(ReplayResult.stored_request_id == selected_request.id).order_by(ReplayResult.id.desc()).limit(30).all()
    context = _context(db, project, "requests")
    selected_replay = replays[0] if replays else None
    context.update({
        "stored_requests": requests,
        "selected_request": selected_request,
        "identities": identities,
        "identity_map": {i.id: i.name for i in identities},
        "replays": replays,
        "selected_replay": selected_replay,
        "selected_response_headers": json.loads(selected_replay.response_headers_json or "{}") if selected_replay else {},
        "secret_summary": masked_header_summary(selected_request.secret_headers_encrypted) if selected_request else [],
        "request_raw": request_raw_text(selected_request) if selected_request else "",
        "request_public_headers_text": "\n".join(
            f"{k}: {v}" for k, v in json.loads(selected_request.headers_json or "{}").items()
        ) if selected_request else "",
        "request_revisions": request_revisions(db, selected_request.id) if selected_request else [],
        "request_draft": load_draft(db, project_id, "stored_request", selected_request.id) if selected_request else None,
        "request_body_pretty": _pretty_json(selected_request.body) if selected_request else "",
        "selected_response_pretty": _pretty_json(selected_replay.response_body) if selected_replay else "",
    })
    return templates.TemplateResponse(request=request, name="requests.html", context=context)


@router.post("/projects/{project_id}/requests/import")
def import_raw_request(
    project_id: int,
    raw_request: str = Form(...),
    scheme: str = Form("https"),
    name: str = Form("Imported Burp Request"),
    explicit_read_only: bool = Form(False),
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    try:
        parsed = parse_raw_http_request(raw_request, scheme=scheme)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if not target_in_scope(parsed.url, _scope_rules(project)):
        raise HTTPException(400, "Imported request URL is outside authorized scope.")
    stored = create_stored_request(
        db, project_id, name, parsed.method, parsed.url, parsed.headers, parsed.body,
        source="burp_raw", explicit_read_only=explicit_read_only,
    )
    from .models import Evidence
    from .services.report_data import raw_http
    from .services.evidence_chain import ensure_evidence_integrity
    original=Evidence(project_id=project_id,source_type='report_raw_request',source_id=stored.id,kind='http_request',content=raw_http(raw_request),redaction_state='redacted')
    db.add(original);db.commit();ensure_evidence_integrity(db,original)
    return RedirectResponse(f"/projects/{project_id}/requests?selected={stored.id}", status_code=303)


@router.post("/projects/{project_id}/requests/from-endpoint/{endpoint_id}")
def endpoint_to_request(project_id: int, endpoint_id: int, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    endpoint = db.get(Endpoint, endpoint_id)
    if not project or not endpoint:
        raise HTTPException(404)
    asset = db.get(Asset, endpoint.asset_id)
    if not asset or asset.project_id != project_id or not target_in_scope(endpoint.url, _scope_rules(project)):
        raise HTTPException(400, "Endpoint is not part of this authorized project.")
    stored = create_stored_request(
        db, project_id, f"{endpoint.method} {endpoint.url}", endpoint.method, endpoint.url,
        source="endpoint", explicit_read_only=endpoint.method.upper() in {"GET", "HEAD"},
    )
    return RedirectResponse(f"/projects/{project_id}/requests?selected={stored.id}", status_code=303)


@router.post("/projects/{project_id}/requests/from-route/{route_id}")
def route_to_request(project_id: int, route_id: int, base_url: str = Form(""), db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    route = db.get(RouteCandidate, route_id)
    if not project or not route:
        raise HTTPException(404)
    asset = db.get(Asset, route.asset_id)
    if not asset or asset.project_id != project_id:
        raise HTTPException(400, "Route does not belong to this project.")
    url = route.path if route.path.startswith(("http://", "https://")) else urljoin((base_url or route.source or f"https://{asset.target}/"), route.path)
    if not target_in_scope(url, _scope_rules(project)):
        raise HTTPException(400, "Route resolves outside authorized scope.")
    method = route.method if route.method != "UNKNOWN" else "GET"
    stored = create_stored_request(
        db, project_id, f"{method} {route.path}", method, url, source="route_candidate",
        explicit_read_only=method.upper() in {"GET", "HEAD"},
    )
    return RedirectResponse(f"/projects/{project_id}/requests?selected={stored.id}", status_code=303)



@router.post("/projects/{project_id}/requests/{request_id}/edit")
def edit_stored_request(
    project_id: int,
    request_id: int,
    name: str = Form(...),
    method: str = Form(...),
    url: str = Form(...),
    headers_text: str = Form(""),
    body: str = Form(""),
    change_note: str = Form(""),
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    stored = db.get(StoredRequest, request_id)
    if not project or not stored or stored.project_id != project_id:
        raise HTTPException(404)
    if not target_in_scope(url, _scope_rules(project)):
        raise HTTPException(400, "Edited request URL is outside authorized scope.")
    try:
        update_stored_request(
            db, stored,
            name=name, method=method, url=url, headers_text=headers_text,
            body=body, change_note=change_note,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    delete_draft(db, project_id, "stored_request", request_id)
    return RedirectResponse(f"/projects/{project_id}/requests?selected={request_id}&edited=1", status_code=303)


@router.post("/projects/{project_id}/requests/{request_id}/restore/{revision_id}")
def restore_stored_request(
    project_id: int,
    request_id: int,
    revision_id: int,
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    stored = db.get(StoredRequest, request_id)
    revision = db.get(StoredRequestRevision, revision_id)
    if not project or not stored or stored.project_id != project_id or not revision:
        raise HTTPException(404)
    if not target_in_scope(revision.url, _scope_rules(project)):
        raise HTTPException(400, "Revision URL is outside authorized scope.")
    try:
        restore_request_revision(db, stored, revision)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    delete_draft(db, project_id, "stored_request", request_id)
    return RedirectResponse(f"/projects/{project_id}/requests?selected={request_id}&restored={revision.revision_no}", status_code=303)


@router.post("/api/projects/{project_id}/burp/send")
async def burp_send_to_workspace(
    project_id: int,
    request: Request,
    x_snowedge_token: str = Header(""),
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    expected = burp_ingest_token(db)
    supplied=x_snowedge_token or request.headers.get('x-ai-pentest-token','')
    if not expected or not secrets.compare_digest(supplied, expected):
        raise HTTPException(401, "Invalid local Burp integration token.")
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(400, "JSON body required.")
    raw_request = str(payload.get("raw_request") or "")
    scheme = str(payload.get("scheme") or "https")
    name = str(payload.get("name") or "Burp → Workspace")
    try:
        parsed = parse_raw_http_request(raw_request, scheme=scheme)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if not target_in_scope(parsed.url, _scope_rules(project)):
        raise HTTPException(400, "Burp request URL is outside authorized scope.")
    stored = create_stored_request(
        db, project_id, name, parsed.method, parsed.url, parsed.headers, parsed.body,
        source="burp_extension", explicit_read_only=False,
    )
    return JSONResponse({
        "ok": True,
        "stored_request_id": stored.id,
        "policy_class": stored.policy_class,
        "workspace_path": f"/projects/{project_id}/requests?selected={stored.id}",
    })


@router.post("/projects/{project_id}/requests/{request_id}/mark-read-only")
def mark_request_read_only(project_id: int, request_id: int, db: Session = Depends(get_db)):
    stored = db.get(StoredRequest, request_id)
    if not stored or stored.project_id != project_id:
        raise HTTPException(404)
    stored.policy_class = "READ_ONLY"
    db.commit()
    return RedirectResponse(f"/projects/{project_id}/requests?selected={request_id}", status_code=303)


@router.post("/projects/{project_id}/requests/{request_id}/replay")
async def replay_stored_request(project_id: int, request_id: int, identity_id: str = Form(""), db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    stored = db.get(StoredRequest, request_id)
    if not project or not stored or stored.project_id != project_id:
        raise HTTPException(404)
    identity = None
    if identity_id.strip():
        identity = db.get(Identity, int(identity_id))
        if not identity or identity.project_id != project_id:
            raise HTTPException(400, "Identity does not belong to this project.")
    agent = _latest_agent_for_project(db, project_id)
    skill_run = start_skill_run(db, project_id, "request_workspace", stored.url, agent, "request_validation")
    try:
        result = await replay_request(db, _scope_rules(project), stored, identity)
        finish_skill_run(db, skill_run, "done", {
            "replay_id": result.id,
            "status_code": result.status_code,
            "identity_id": identity.id if identity else None,
            "method": stored.method,
        }, agent)
    except ValueError as exc:
        finish_skill_run(db, skill_run, "error", {"error": str(exc)}, agent)
        raise HTTPException(400, str(exc))
    return RedirectResponse(f"/projects/{project_id}/requests?selected={request_id}&replay={result.id}", status_code=303)


@router.get("/projects/{project_id}/sessions", response_class=HTMLResponse)
def sessions_page(project_id: int, request: Request, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    identities = db.query(Identity).filter(Identity.project_id == project_id).order_by(Identity.id.asc()).all()
    vault_items = db.query(SecretVaultItem).filter(SecretVaultItem.deleted == 0, SecretVaultItem.disabled == 0).filter((SecretVaultItem.project_id == project_id) | (SecretVaultItem.project_id.is_(None))).order_by(SecretVaultItem.id.asc()).all()
    vault_map = {v.id: item_summary(v) for v in vault_items}
    rows = [{
        "identity": i,
        "headers": masked_header_summary(i.headers_encrypted) if not i.vault_item_id else [],
        "cookies": masked_cookie_summary(i.cookies_encrypted) if not i.vault_item_id else [],
        "vault": vault_map.get(i.vault_item_id),
    } for i in identities]
    context = _context(db, project, "sessions")
    context["identity_rows"] = rows
    context["vault_items"] = [item_summary(v) for v in vault_items if v.secret_type == "http_identity"]
    return templates.TemplateResponse(request=request, name="sessions.html", context=context)


@router.post("/projects/{project_id}/sessions")
def create_identity(
    project_id: int,
    name: str = Form(...),
    role: str = Form("User"),
    headers_json: str = Form("{}"),
    cookies: str = Form(""),
    vault_item_id: str = Form(""),
    notes: str = Form(""),
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    try:
        headers = json.loads(headers_json or "{}")
        if not isinstance(headers, dict):
            raise ValueError
    except Exception:
        raise HTTPException(400, "Headers must be a JSON object.")
    cookie_map = {}
    for part in cookies.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            cookie_map[key.strip()] = value.strip()
    vault_ref = None
    if vault_item_id.strip():
        try: vault_ref = db.get(SecretVaultItem, int(vault_item_id))
        except ValueError: vault_ref = None
        if not vault_ref or vault_ref.deleted or vault_ref.disabled or vault_ref.secret_type != "http_identity" or vault_ref.project_id not in {None, project_id}:
            raise HTTPException(400, "Vault HTTP Identity 不可用或不属于当前项目。")
    identity = Identity(
        project_id=project_id, name=name[:120], role=role[:80],
        headers_encrypted="" if vault_ref else encrypt_json(headers),
        cookies_encrypted="" if vault_ref else encrypt_json(cookie_map),
        vault_item_id=vault_ref.id if vault_ref else None, notes=notes,
    )
    db.add(identity)
    db.commit()
    return RedirectResponse(f"/projects/{project_id}/sessions", status_code=303)


@router.post("/projects/{project_id}/diff")
def create_diff(project_id: int, left_id: int = Form(...), right_id: int = Form(...), db: Session = Depends(get_db)):
    left = db.get(ReplayResult, left_id)
    right = db.get(ReplayResult, right_id)
    if not left or not right or left.project_id != project_id or right.project_id != project_id:
        raise HTTPException(400, "Replay results must belong to this project.")
    agent = _latest_agent_for_project(db, project_id)
    skill_run = start_skill_run(db, project_id, "response_diff", f"replay:{left.id}↔{right.id}", agent, "response_diff")
    summary = compare_responses(
        left.status_code, json.loads(left.response_headers_json or "{}"), left.response_body,
        right.status_code, json.loads(right.response_headers_json or "{}"), right.response_body,
    )
    diff = ResponseDiff(project_id=project_id, left_replay_id=left.id, right_replay_id=right.id, summary_json=json.dumps(summary, ensure_ascii=False))
    db.add(diff)
    db.commit()
    db.refresh(diff)
    finish_skill_run(db, skill_run, "done", {
        "diff_id": diff.id,
        "left_replay_id": left.id,
        "right_replay_id": right.id,
        "text_similarity": summary.get("text_similarity"),
    }, agent)
    rebuild_knowledge_graph(db, project_id)
    refresh_assessment_memory(db, project_id)
    return RedirectResponse(f"/projects/{project_id}/diff/{diff.id}", status_code=303)


@router.get("/projects/{project_id}/diff/{diff_id}", response_class=HTMLResponse)
def diff_page(project_id: int, diff_id: int, request: Request, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    diff = db.get(ResponseDiff, diff_id)
    if not project or not diff or diff.project_id != project_id:
        raise HTTPException(404)
    left = db.get(ReplayResult, diff.left_replay_id)
    right = db.get(ReplayResult, diff.right_replay_id)
    stored = db.get(StoredRequest, left.stored_request_id) if left else None
    context = _context(db, project, "requests")
    context.update({"diff": diff, "summary": json.loads(diff.summary_json), "left": left, "right": right, "stored": stored})
    return templates.TemplateResponse(request=request, name="diff.html", context=context)
