import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi.testclient import TestClient

from app.db import Base, SessionLocal, engine
from app.main import app
from app.models import (
    AgentEvent,
    AgentRun,
    AuthorizationCase,
    Evidence,
    Finding,
    Identity,
    Project,
    ReplayResult,
    StoredRequest,
)
from app.services.authorization_testing import analyze_authorization, run_authorization_case
from app.services.request_workspace import create_stored_request
from app.services.secret_store import encrypt_json


def _replay(status: int, body: str) -> ReplayResult:
    return ReplayResult(
        project_id=1,
        stored_request_id=1,
        status="done",
        status_code=status,
        response_headers_json='{"content-type":"application/json"}',
        response_body=body,
    )


def _identity(identity_id: int, name: str, role: str) -> Identity:
    return Identity(id=identity_id, project_id=1, name=name, role=role)


def test_control_enforced_classification():
    baseline = _replay(200, '{"id":1,"name":"Alice"}')
    comparison = _replay(403, '{"error":"forbidden"}')
    summary = {"text_similarity": 0.2, "json": {"changed": {}, "added": {}, "removed": {}}}
    result = analyze_authorization(
        "horizontal",
        baseline,
        comparison,
        summary,
        _identity(1, "User A", "User"),
        _identity(2, "User B", "User"),
        1,
    )
    assert result["classification"] == "authorization_control_enforced"
    assert result["confidence"] >= 90


def test_horizontal_candidate_requires_ownership_signal():
    body = '{"profile":{"id":1001,"email":"alice@example.test","phone":"13800000000"},"role":"user"}'
    baseline = _replay(200, body)
    comparison = _replay(200, body)
    summary = {"text_similarity": 1.0, "json": {"changed": {}, "added": {}, "removed": {}}}
    result = analyze_authorization(
        "horizontal",
        baseline,
        comparison,
        summary,
        _identity(1, "User A", "User"),
        _identity(2, "User B", "User"),
        1,
    )
    assert result["classification"] == "potential_horizontal_authorization_gap"
    assert result["confidence"] >= 90
    assert "$.profile.email" in result["comparison"]["sensitive_paths"]
    # Values must not be copied into structural sensitive-path evidence.
    assert "alice@example.test" not in json.dumps(result["comparison"]["sensitive_paths"])


def test_vertical_candidate_role_difference():
    body = '{"report":{"id":7,"title":"finance"},"permissions":["view"]}'
    result = analyze_authorization(
        "vertical",
        _replay(200, body),
        _replay(200, body),
        {"text_similarity": 1.0, "json": {"changed": {}, "added": {}, "removed": {}}},
        _identity(1, "Admin", "Admin"),
        _identity(2, "User", "User"),
        None,
    )
    assert result["classification"] == "potential_vertical_authorization_gap"
    assert result["confidence"] >= 85


class AuthzHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        token = self.headers.get("Authorization", "")
        # Deliberately vulnerable-looking local test fixture:
        # both users receive User A's resource.
        if token in {"Bearer user-a", "Bearer user-b"}:
            body = json.dumps({
                "resource": {"owner": "user-a", "id": 1001, "email": "alice@example.test"},
                "viewer": "user-a",
            }).encode()
            self.send_response(200)
        else:
            body = json.dumps({"error": "unauthorized"}).encode()
            self.send_response(401)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def test_authorization_case_e2e_creates_candidate_finding_and_evidence():
    Base.metadata.create_all(bind=engine)
    server = HTTPServer(("127.0.0.1", 8955), AuthzHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    db = SessionLocal()
    try:
        project = Project(name="V05 AuthZ", scope_text="127.0.0.1")
        db.add(project)
        db.flush()

        user_a = Identity(
            project_id=project.id,
            name="User A",
            role="User",
            headers_encrypted=encrypt_json({"Authorization": "Bearer user-a"}),
            cookies_encrypted=encrypt_json({}),
        )
        user_b = Identity(
            project_id=project.id,
            name="User B",
            role="User",
            headers_encrypted=encrypt_json({"Authorization": "Bearer user-b"}),
            cookies_encrypted=encrypt_json({}),
        )
        db.add_all([user_a, user_b])
        db.flush()

        stored = create_stored_request(
            db,
            project.id,
            "User A profile",
            "GET",
            "http://127.0.0.1:8955/api/profile/1001",
        )

        agent = AgentRun(
            project_id=project.id,
            target=stored.url,
            mission="Authorized test",
            stage="request_validation",
            status="running",
        )
        db.add(agent)
        db.flush()

        case = AuthorizationCase(
            project_id=project.id,
            stored_request_id=stored.id,
            test_type="horizontal",
            baseline_identity_id=user_a.id,
            comparison_identity_id=user_b.id,
            expected_owner_identity_id=user_a.id,
            object_label="User A profile #1001",
        )
        db.add(case)
        db.commit()
        db.refresh(case)

        asyncio.run(run_authorization_case(
            db,
            ["127.0.0.1"],
            case,
            user_a,
            user_b,
            auto_candidate_finding=True,
        ))
        db.refresh(case)

        assert case.status == "done"
        assert case.classification == "potential_horizontal_authorization_gap"
        assert case.confidence >= 90
        assert case.response_diff_id is not None
        assert case.finding_id is not None
        ai_review = json.loads(case.ai_review_json)
        assert "assessment" in ai_review
        assert "alice@example.test" not in case.ai_review_json

        finding = db.get(Finding, case.finding_id)
        assert "Potential Horizontal Authorization Gap" in finding.title
        assert "manual confirmation" in finding.description.lower()

        evidence = db.query(Evidence).filter(Evidence.kind == "authorization_analysis").all()
        assert evidence
        assert "alice@example.test" not in evidence[-1].content
        assert "$.resource.email" in evidence[-1].content

        events = db.query(AgentEvent).filter(AgentEvent.agent_run_id == agent.id).all()
        assert any(e.stage == "authorization_testing" for e in events)
        assert any(e.event_type == "ai_review" for e in events)
    finally:
        db.close()
        server.shutdown()


def test_authorization_automation_rejects_post_even_if_marked_read_only():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="V05 POST Guard", scope_text="127.0.0.1")
        db.add(project)
        db.flush()
        stored = create_stored_request(
            db,
            project.id,
            "Non-mutating-looking POST",
            "POST",
            "http://127.0.0.1:9999/query",
            explicit_read_only=True,
        )
        case = AuthorizationCase(
            project_id=project.id,
            stored_request_id=stored.id,
            test_type="unauthenticated",
        )
        db.add(case)
        db.commit()
        with pytest.raises(ValueError, match="GET/HEAD"):
            asyncio.run(run_authorization_case(db, ["127.0.0.1"], case, None, None))
    finally:
        db.close()


def test_authorization_pages_render():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="V05 UI", scope_text="127.0.0.1")
        db.add(project)
        db.flush()
        identity = Identity(
            project_id=project.id,
            name="User A",
            role="User",
            headers_encrypted=encrypt_json({}),
            cookies_encrypted=encrypt_json({}),
        )
        db.add(identity)
        db.flush()
        stored = create_stored_request(
            db, project.id, "Profile", "GET", "http://127.0.0.1:8000/profile"
        )
        case = AuthorizationCase(
            project_id=project.id,
            stored_request_id=stored.id,
            test_type="unauthenticated",
            baseline_identity_id=identity.id,
            status="done",
            classification="needs_review",
            confidence=55,
            summary_json=json.dumps({
                "similarity": 0.7,
                "manual_confirmation_required": True,
                "rationale": ["UI fixture"],
                "json_changes": {"changed": 1, "added": 0, "removed": 0},
                "baseline": {"identity": "User A (User)", "status_code": 200, "length": 100, "sensitive_paths": []},
                "comparison": {"identity": "Anonymous", "status_code": 200, "length": 90, "sensitive_paths": []},
            }),
        )
        db.add(case)
        db.commit()
        db.refresh(project)
        db.refresh(case)
        pid, cid = project.id, case.id
    finally:
        db.close()

    with TestClient(app) as client:
        r = client.get(f"/projects/{pid}/authorization")
        assert r.status_code == 200
        assert "Authorization Lab" in r.text
        assert "New differential test" in r.text

        r = client.get(f"/projects/{pid}/authorization/{cid}")
        assert r.status_code == 200
        assert f"Case #{cid}" in r.text
        assert "Authorization assessment" in r.text



def test_manual_promotion_for_review_case():
    from app.services.authorization_testing import promote_authorization_case

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="V05 Promote", scope_text="127.0.0.1")
        db.add(project)
        db.flush()
        stored = create_stored_request(
            db, project.id, "Review me", "GET", "http://127.0.0.1:8000/review"
        )
        case = AuthorizationCase(
            project_id=project.id,
            stored_request_id=stored.id,
            test_type="horizontal",
            status="done",
            classification="horizontal_access_needs_review",
            confidence=64,
            summary_json=json.dumps({
                "classification": "horizontal_access_needs_review",
                "confidence": 64,
                "rationale": ["Ownership evidence is missing."],
            }),
            ai_review_json=json.dumps({
                "assessment": "Manual ownership confirmation required.",
                "risk": "review",
                "confidence_adjustment": 0,
                "manual_checks": ["Confirm owner."],
            }),
        )
        db.add(case)
        db.commit()
        db.refresh(case)

        finding = promote_authorization_case(db, case)
        assert finding.id == case.finding_id
        assert finding.severity == "low"
        assert "Requires Review" in finding.title
        assert "Manual ownership confirmation required." in db.query(Evidence).filter(Evidence.finding_id == finding.id).first().content
    finally:
        db.close()
