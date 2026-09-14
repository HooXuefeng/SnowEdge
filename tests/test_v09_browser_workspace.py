import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from app.db import Base, SessionLocal, engine
from app.main import app
from app.models import (
    BrowserArtifact,
    BrowserEvent,
    BrowserSession,
    Evidence,
    Identity,
    Project,
    ProjectSkill,
    SkillDefinition,
    StoredRequest,
    Task,
)
from app.services.browser_workspace import redact_headers, redact_url
from app.services.secret_store import encrypt_json
from app.services.skill_planner import approve_skill_plan, generate_skill_plan
from app.services.execution_graph import graph_nodes
from app.skills.registry import ensure_project_skill_rows, seed_builtin_skills


def test_browser_header_redaction_masks_secrets():
    result = redact_headers({
        "Accept": "text/html",
        "Authorization": "Bearer secret-token",
        "Cookie": "sid=secret",
        "X-API-Key": "top-secret",
    })
    assert result["Accept"] == "text/html"
    assert result["Authorization"] == "•••• protected ••••"
    assert result["Cookie"] == "•••• protected ••••"
    assert result["X-API-Key"] == "•••• protected ••••"
    assert "secret-token" not in json.dumps(result)
    assert "sid=secret" not in json.dumps(result)



def test_browser_url_redaction_masks_sensitive_query_values():
    url = "https://app.test/callback?code=secret-code&ticket=t123&lang=zh&api_key=superkey"
    redacted = redact_url(url)
    assert "secret-code" not in redacted
    assert "t123" not in redacted
    assert "superkey" not in redacted
    assert "lang=zh" in redacted
    assert "code=" in redacted

def test_browser_skill_is_builtin_manual_workspace_and_planner_recommends_it():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_builtin_skills(db)
        skill = (
            db.query(SkillDefinition)
            .filter(SkillDefinition.slug == "browser-observation-workspace")
            .one()
        )
        assert skill.execution_mode == "MANUAL_WORKSPACE"
        assert "browser_workspace" in json.loads(skill.capabilities_json)

        project = Project(name="V09 Planner Browser", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)
        plan = asyncio.run(generate_skill_plan(db, project, "http://127.0.0.1/"))
        recs = json.loads(plan.recommendations_json)
        slugs = [r["slug"] for r in recs]
        assert "browser-observation-workspace" in slugs

        approve_skill_plan(
            db,
            project.id,
            plan.id,
            ["web-attack-surface-mapping", "browser-observation-workspace"],
        )
        nodes = {n.skill_slug: n for n in graph_nodes(db, plan.id)}
        assert nodes["browser-observation-workspace"].status == "manual_ready"
    finally:
        db.close()


@pytest.mark.parametrize("target,status", [
    ("http://127.0.0.1/", 303),
    ("https://example.com/", 400),
])
def test_browser_start_scope_gate(monkeypatch, target, status):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name=f"V09 Scope {target}", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)
        pid = project.id
    finally:
        db.close()

    async def fake_capture(db, project, session, identity=None):
        session.status = "done"
        session.final_url = session.target_url
        session.title = "Fake Browser"
        session.browser_name = "fake"
        session.summary_json = json.dumps({"requests": 0, "blocked_out_of_scope": 0})
        db.commit()
        return session

    monkeypatch.setattr("app.browser_routes.capture_browser_session", fake_capture)

    with TestClient(app) as client:
        response = client.post(
            f"/projects/{pid}/browser/start",
            data={"target_url": target, "identity_id": ""},
            follow_redirects=False,
        )
        assert response.status_code == status


def test_browser_event_handoffs_and_evidence(monkeypatch):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="V09 Handoffs", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)
        identity = Identity(
            project_id=project.id,
            name="User A",
            role="User",
            headers_encrypted=encrypt_json({"Authorization": "Bearer auth-secret"}),
            cookies_encrypted=encrypt_json({"sid": "cookie-secret"}),
        )
        db.add(identity); db.commit(); db.refresh(identity)
        pid = project.id
    finally:
        db.close()

    async def fake_capture(db, project, session, identity=None):
        session.status = "done"
        session.final_url = session.target_url
        session.title = "Browser QA"
        session.browser_name = "fake-chromium"
        session.summary_json = json.dumps({
            "requests": 2,
            "xhr_fetch": 1,
            "forms": 1,
            "scripts": 1,
            "console_messages": 1,
            "blocked_out_of_scope": 1,
        })
        req = BrowserEvent(
            project_id=project.id,
            browser_session_id=session.id,
            event_type="request",
            method="GET",
            url="http://127.0.0.1/api/profile/1001",
            resource_type="xhr",
            in_scope=1,
            detail_json=json.dumps({
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "•••• protected ••••",
                    "Cookie": "•••• protected ••••",
                },
                "post_data_omitted": False,
            }),
        )
        blocked = BrowserEvent(
            project_id=project.id,
            browser_session_id=session.id,
            event_type="blocked_out_of_scope",
            method="GET",
            url="https://third-party.example/analytics.js",
            resource_type="script",
            in_scope=0,
            detail_json=json.dumps({"reason": "blocked_out_of_scope"}),
        )
        db.add_all([req, blocked])
        db.commit()
        return session

    monkeypatch.setattr("app.browser_routes.capture_browser_session", fake_capture)

    with TestClient(app) as client:
        started = client.post(
            f"/projects/{pid}/browser/start",
            data={"target_url": "http://127.0.0.1/", "identity_id": ""},
            follow_redirects=False,
        )
        assert started.status_code == 303

    db = SessionLocal()
    try:
        session = db.query(BrowserSession).filter(BrowserSession.project_id == pid).order_by(BrowserSession.id.desc()).first()
        assert session and session.status == "done"
        req = (
            db.query(BrowserEvent)
            .filter(BrowserEvent.browser_session_id == session.id, BrowserEvent.event_type == "request")
            .one()
        )
        blocked = (
            db.query(BrowserEvent)
            .filter(BrowserEvent.browser_session_id == session.id, BrowserEvent.event_type == "blocked_out_of_scope")
            .one()
        )
        session_id, req_id, blocked_id = session.id, req.id, blocked.id
    finally:
        db.close()

    with TestClient(app) as client:
        page = client.get(f"/projects/{pid}/browser?selected={session_id}&event={req_id}")
        assert page.status_code == 200
        assert "Browser Workspace" in page.text
        assert "Send to Request Workspace" in page.text
        assert "Send to Authorization Lab" in page.text
        assert "auth-secret" not in page.text
        assert "cookie-secret" not in page.text
        assert "protected" in page.text.lower()
        assert "third-party.example" in page.text

        to_request = client.post(
            f"/projects/{pid}/browser/events/{req_id}/to-request",
            follow_redirects=False,
        )
        assert to_request.status_code == 303

    db = SessionLocal()
    try:
        stored = (
            db.query(StoredRequest)
            .filter(StoredRequest.project_id == pid, StoredRequest.source == "browser_event")
            .order_by(StoredRequest.id.desc())
            .first()
        )
        assert stored is not None
        assert stored.method == "GET"
        assert stored.policy_class == "READ_ONLY"
        headers = json.loads(stored.headers_json)
        assert headers["Accept"] == "application/json"
        assert "Authorization" not in headers
        assert "Cookie" not in headers
        stored_id = stored.id
    finally:
        db.close()

    with TestClient(app) as client:
        auth = client.post(
            f"/projects/{pid}/browser/events/{req_id}/to-authorization",
            follow_redirects=False,
        )
        assert auth.status_code == 303
        assert "authorization?request_id=" in auth.headers["location"]

        promoted = client.post(
            f"/projects/{pid}/browser/events/{req_id}/evidence",
            follow_redirects=False,
        )
        assert promoted.status_code == 303

        blocked_transfer = client.post(
            f"/projects/{pid}/browser/events/{blocked_id}/to-request",
            follow_redirects=False,
        )
        assert blocked_transfer.status_code == 400

    db = SessionLocal()
    try:
        browser_tasks = db.query(Task).filter(Task.project_id == pid, Task.action == "browser_event_evidence").all()
        assert browser_tasks
        evidence = db.query(Evidence).filter(Evidence.task_id == browser_tasks[-1].id).one()
        assert evidence.kind == "browser_event"
        assert "api/profile/1001" in evidence.content
    finally:
        db.close()


def test_browser_post_observation_stays_state_change_when_stored():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="V09 POST Policy", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)
        session = BrowserSession(
            project_id=project.id,
            target_url="http://127.0.0.1/",
            status="done",
        )
        db.add(session); db.commit(); db.refresh(session)
        event = BrowserEvent(
            project_id=project.id,
            browser_session_id=session.id,
            event_type="request",
            method="POST",
            url="http://127.0.0.1/api/update",
            resource_type="xhr",
            in_scope=1,
            detail_json=json.dumps({
                "headers": {"Content-Type": "application/json"},
                "post_data_omitted": True,
            }),
        )
        db.add(event); db.commit(); db.refresh(event)
        pid, event_id = project.id, event.id
    finally:
        db.close()

    with TestClient(app) as client:
        stored_response = client.post(
            f"/projects/{pid}/browser/events/{event_id}/to-request",
            follow_redirects=False,
        )
        assert stored_response.status_code == 303

        auth_response = client.post(
            f"/projects/{pid}/browser/events/{event_id}/to-authorization",
            follow_redirects=False,
        )
        assert auth_response.status_code == 400

    db = SessionLocal()
    try:
        stored = (
            db.query(StoredRequest)
            .filter(StoredRequest.project_id == pid, StoredRequest.source == "browser_event")
            .order_by(StoredRequest.id.desc())
            .first()
        )
        assert stored.method == "POST"
        assert stored.policy_class == "STATE_CHANGE"
        assert stored.body == ""
    finally:
        db.close()


def test_authorization_lab_preselects_browser_request():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="V09 Auth Preselect", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)
        stored = StoredRequest(
            project_id=project.id,
            name="Browser GET profile",
            method="GET",
            url="http://127.0.0.1/api/profile/1",
            headers_json="{}",
            secret_headers_encrypted="",
            body="",
            source="browser_event",
            policy_class="READ_ONLY",
        )
        db.add(stored); db.commit(); db.refresh(stored)
        pid, sid = project.id, stored.id
    finally:
        db.close()

    with TestClient(app) as client:
        page = client.get(f"/projects/{pid}/authorization?request_id={sid}")
        assert page.status_code == 200
        assert f'value="{sid}" selected' in page.text


def test_browser_report_exports_include_observation_summary():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="V09 Browser Report", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)
        session = BrowserSession(
            project_id=project.id,
            target_url="http://127.0.0.1/",
            status="done",
            final_url="http://127.0.0.1/",
            title="Report Browser",
            browser_name="QA Chromium",
            summary_json=json.dumps({
                "requests": 5,
                "xhr_fetch": 2,
                "blocked_out_of_scope": 1,
            }),
        )
        db.add(session); db.commit()
        pid = project.id
    finally:
        db.close()

    with TestClient(app) as client:
        preview = client.get(f"/projects/{pid}/reports?legacy=1")
        md = client.get(f"/projects/{pid}/reports/export.md")
        html = client.get(f"/projects/{pid}/reports/export.html")
        assert preview.status_code == 200
        assert md.status_code == 200
        assert html.status_code == 200
        assert "浏览器观察摘要" in preview.text
        assert "浏览器观察摘要" in md.text
        assert "Browser Session" in md.text
        assert "浏览器观察摘要" in html.text


def test_browser_artifact_route_enforces_configured_root(monkeypatch, tmp_path):
    from app.config import settings

    Base.metadata.create_all(bind=engine)
    artifact_root = tmp_path / "browser_artifacts"
    artifact_root.mkdir()
    allowed_file = artifact_root / "shot.png"
    allowed_file.write_bytes(b"\x89PNG\r\n\x1a\nQA")

    outside_file = tmp_path / "outside.png"
    outside_file.write_bytes(b"\x89PNG\r\n\x1a\nOUT")

    monkeypatch.setattr(settings, "browser_artifact_dir", str(artifact_root))

    db = SessionLocal()
    try:
        project = Project(name="V09 Artifact Guard", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)
        session = BrowserSession(
            project_id=project.id,
            target_url="http://127.0.0.1/",
            status="done",
        )
        db.add(session); db.commit(); db.refresh(session)

        allowed = BrowserArtifact(
            project_id=project.id,
            browser_session_id=session.id,
            artifact_type="screenshot",
            label="Allowed",
            file_path=str(allowed_file),
        )
        outside = BrowserArtifact(
            project_id=project.id,
            browser_session_id=session.id,
            artifact_type="screenshot",
            label="Outside",
            file_path=str(outside_file),
        )
        db.add_all([allowed, outside]); db.commit(); db.refresh(allowed); db.refresh(outside)
        pid, allowed_id, outside_id = project.id, allowed.id, outside.id
    finally:
        db.close()

    with TestClient(app) as client:
        ok = client.get(f"/projects/{pid}/browser-artifacts/{allowed_id}")
        blocked = client.get(f"/projects/{pid}/browser-artifacts/{outside_id}")
        assert ok.status_code == 200
        assert blocked.status_code == 403
