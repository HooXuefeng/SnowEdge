from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, Form, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.requests import Request

from .config import settings
from .ui_i18n import configure_templates
from .db import SessionLocal, get_db
from .models import (
    BrowserArtifact,
    BrowserEvent,
    BrowserSession,
    Evidence,
    Identity,
    Project,
    StoredRequest,
    Task,
)
from .scope import target_in_scope
from .services.browser_workspace import browser_runtime_status, capture_browser_session
from .services.request_workspace import create_stored_request
from .services.job_engine import enqueue_job, run_job_now
from .services.knowledge_graph import rebuild_knowledge_graph
from .services.assessment_memory import refresh_assessment_memory

BASE_DIR = Path(__file__).resolve().parent
templates = configure_templates(Jinja2Templates(directory=BASE_DIR / "templates"))
router = APIRouter()


def _scope_rules(project: Project) -> list[str]:
    return [x.strip() for x in project.scope_text.splitlines() if x.strip()]


def _context(db: Session, project: Project, active_nav: str) -> dict:
    from .main import _project_context
    return _project_context(db, project, active_nav)


def _event_detail(event: BrowserEvent) -> dict:
    try:
        data = json.loads(event.detail_json or "{}")
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


async def _run_browser_background(project_id: int, session_id: int, identity_id: int | None):
    db = SessionLocal()
    try:
        project = db.get(Project, project_id)
        session = db.get(BrowserSession, session_id)
        identity = db.get(Identity, identity_id) if identity_id else None
        if not project or not session:
            return
        if identity and identity.project_id != project_id:
            session.status = "error"
            session.error = "Selected Identity does not belong to this project."
            db.commit()
            return
        await capture_browser_session(db, project, session, identity)
        rebuild_knowledge_graph(db, project_id)
        refresh_assessment_memory(db, project_id)
    finally:
        db.close()


@router.get("/projects/{project_id}/browser", response_class=HTMLResponse)
async def browser_workspace(
    project_id: int,
    request: Request,
    selected: int | None = None,
    event: int | None = None,
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)

    sessions = (
        db.query(BrowserSession)
        .filter(BrowserSession.project_id == project_id)
        .order_by(BrowserSession.id.desc())
        .limit(50)
        .all()
    )
    selected_session = db.get(BrowserSession, selected) if selected else (sessions[0] if sessions else None)
    if selected_session and selected_session.project_id != project_id:
        selected_session = None

    events = []
    artifacts = []
    selected_event = None
    event_detail = {}
    summary = {}
    if selected_session:
        events = (
            db.query(BrowserEvent)
            .filter(BrowserEvent.browser_session_id == selected_session.id)
            .order_by(BrowserEvent.id.asc())
            .limit(1200)
            .all()
        )
        artifacts = (
            db.query(BrowserArtifact)
            .filter(BrowserArtifact.browser_session_id == selected_session.id)
            .order_by(BrowserArtifact.id.asc())
            .all()
        )
        try:
            summary = json.loads(selected_session.summary_json or "{}")
        except Exception:
            summary = {}

        if event:
            candidate = db.get(BrowserEvent, event)
            if candidate and candidate.browser_session_id == selected_session.id:
                selected_event = candidate
        if not selected_event:
            selected_event = next(
                (e for e in reversed(events) if e.event_type in {"request", "response", "console", "blocked_out_of_scope"}),
                None,
            )
        if selected_event:
            event_detail = _event_detail(selected_event)

    identities = db.query(Identity).filter(Identity.project_id == project_id).order_by(Identity.id.asc()).all()
    runtime = await browser_runtime_status()
    screenshot = next((a for a in artifacts if a.artifact_type == "screenshot"), None)
    dom_artifact = next((a for a in artifacts if a.artifact_type == "dom_snapshot"), None)
    dom_meta = {}
    runtime_artifact = next((a for a in artifacts if a.artifact_type == "runtime_metadata"), None)
    runtime_meta = {}
    if runtime_artifact:
        try:
            runtime_meta = json.loads(runtime_artifact.content_text or "{}")
        except Exception:
            runtime_meta = {}
    if dom_artifact:
        try:
            dom_meta = json.loads(dom_artifact.metadata_json or "{}")
        except Exception:
            dom_meta = {}

    context = _context(db, project, "browser")
    context.update({
        "sessions": sessions,
        "selected_session": selected_session,
        "events": events,
        "selected_event": selected_event,
        "selected_event_detail": event_detail,
        "artifacts": artifacts,
        "screenshot": screenshot,
        "dom_artifact": dom_artifact,
        "dom_meta": dom_meta,
        "runtime_artifact": runtime_artifact,
        "runtime_meta": runtime_meta,
        "summary": summary,
        "identities": identities,
        "runtime": runtime,
    })
    return templates.TemplateResponse(request=request, name="browser.html", context=context)


@router.post("/projects/{project_id}/browser/start")
def start_browser_session(
    project_id: int,
    background_tasks: BackgroundTasks,
    target_url: str = Form(...),
    identity_id: str = Form(""),
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)

    target_url = target_url.strip()
    if not target_in_scope(target_url, _scope_rules(project)):
        raise HTTPException(400, "Browser target is outside the project's authorized scope.")

    identity = None
    if identity_id.strip():
        try:
            identity = db.get(Identity, int(identity_id))
        except ValueError:
            identity = None
        if not identity or identity.project_id != project_id:
            raise HTTPException(400, "Identity does not belong to this project.")

    session = BrowserSession(
        project_id=project_id,
        target_url=target_url,
        identity_id=identity.id if identity else None,
        status="queued",
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    job = enqueue_job(
        db,
        project,
        "browser_observe",
        target=target_url,
        payload={
            "session_id": session.id,
            "identity_id": identity.id if identity else None,
        },
        priority=70,
        timeout_seconds=180,
        max_attempts=1,
    )
    background_tasks.add_task(run_job_now, job.id)
    return RedirectResponse(
        f"/projects/{project_id}/browser?selected={session.id}&job={job.id}",
        status_code=303,
    )


@router.get("/api/projects/{project_id}/browser-sessions/{session_id}")
def browser_session_status(project_id: int, session_id: int, db: Session = Depends(get_db)):
    session = db.get(BrowserSession, session_id)
    if not session or session.project_id != project_id:
        raise HTTPException(404)
    try:
        summary = json.loads(session.summary_json or "{}")
    except Exception:
        summary = {}
    return {
        "id": session.id,
        "status": session.status,
        "target_url": session.target_url,
        "final_url": session.final_url,
        "title": session.title,
        "browser_name": session.browser_name,
        "summary": summary,
        "error": session.error,
    }


@router.get("/projects/{project_id}/browser-artifacts/{artifact_id}")
def browser_artifact_file(project_id: int, artifact_id: int, db: Session = Depends(get_db)):
    artifact = db.get(BrowserArtifact, artifact_id)
    if not artifact or artifact.project_id != project_id or not artifact.file_path:
        raise HTTPException(404)

    path = Path(artifact.file_path).resolve()
    base = Path(settings.browser_artifact_dir).expanduser()
    if not base.is_absolute():
        base = Path.cwd() / base
    base = base.resolve()

    try:
        path.relative_to(base)
    except ValueError:
        raise HTTPException(403, "Artifact path is outside the configured browser artifact directory.")

    if not path.exists() or not path.is_file():
        raise HTTPException(404)

    media_type = "image/png" if path.suffix.lower() == ".png" else "application/octet-stream"
    return FileResponse(path, media_type=media_type, filename=path.name)


def _browser_event_to_stored_request(
    db: Session,
    project: Project,
    event: BrowserEvent,
) -> StoredRequest:
    if event.project_id != project.id or event.event_type != "request" or not event.in_scope:
        raise ValueError("Only in-scope Browser request events can be stored.")

    detail = _event_detail(event)
    headers = {}
    for key, value in (detail.get("headers") or {}).items():
        if value == "•••• protected ••••":
            continue
        headers[str(key)] = str(value)

    explicit_read_only = event.method.upper() in {"GET", "HEAD"}
    stored = create_stored_request(
        db,
        project.id,
        f"Browser #{event.browser_session_id} · {event.method} {event.url}",
        event.method or "GET",
        event.url,
        headers=headers,
        body="",
        source="browser_event",
        explicit_read_only=explicit_read_only,
    )
    return stored


@router.post("/projects/{project_id}/browser/events/{event_id}/to-request")
def browser_event_to_request(project_id: int, event_id: int, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    event = db.get(BrowserEvent, event_id)
    if not project or not event:
        raise HTTPException(404)
    if not target_in_scope(event.url, _scope_rules(project)):
        raise HTTPException(400, "Browser event URL is outside current project scope.")
    try:
        stored = _browser_event_to_stored_request(db, project, event)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return RedirectResponse(f"/projects/{project_id}/requests?selected={stored.id}", status_code=303)


@router.post("/projects/{project_id}/browser/events/{event_id}/to-authorization")
def browser_event_to_authorization(project_id: int, event_id: int, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    event = db.get(BrowserEvent, event_id)
    if not project or not event:
        raise HTTPException(404)
    if event.method.upper() not in {"GET", "HEAD"}:
        raise HTTPException(400, "Authorization Lab only accepts READ_ONLY GET/HEAD requests.")
    if not target_in_scope(event.url, _scope_rules(project)):
        raise HTTPException(400, "Browser event URL is outside current project scope.")
    try:
        stored = _browser_event_to_stored_request(db, project, event)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return RedirectResponse(
        f"/projects/{project_id}/authorization?request_id={stored.id}",
        status_code=303,
    )


@router.post("/projects/{project_id}/browser/events/{event_id}/evidence")
def browser_event_to_evidence(project_id: int, event_id: int, db: Session = Depends(get_db)):
    event = db.get(BrowserEvent, event_id)
    if not event or event.project_id != project_id:
        raise HTTPException(404)

    task = Task(
        project_id=project_id,
        action="browser_event_evidence",
        target=event.url or f"browser-session:{event.browser_session_id}",
        policy_class="READ_ONLY",
        status="done",
        detail=f"Promoted Browser Event #{event.id} to Evidence.",
    )
    db.add(task)
    db.flush()

    evidence = Evidence(
        task_id=task.id,
        kind="browser_event",
        content=json.dumps({
            "browser_session_id": event.browser_session_id,
            "browser_event_id": event.id,
            "event_type": event.event_type,
            "method": event.method,
            "url": event.url,
            "resource_type": event.resource_type,
            "status_code": event.status_code,
            "in_scope": bool(event.in_scope),
            "detail": _event_detail(event),
        }, ensure_ascii=False, indent=2),
    )
    db.add(evidence)
    db.commit()

    return RedirectResponse(
        f"/projects/{project_id}/browser?selected={event.browser_session_id}&event={event.id}&evidence=created",
        status_code=303,
    )
