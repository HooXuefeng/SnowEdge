import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from fastapi.testclient import TestClient

from app.db import Base, SessionLocal, engine
from app.main import app
from app.models import (
    Asset,
    AuthorizationCase,
    BrowserSession,
    CopilotQuery,
    CoverageSnapshot,
    Endpoint,
    Evidence,
    Finding,
    FindingLifecycle,
    Identity,
    Project,
    RemediationEvent,
    Service,
    StoredRequest,
    Task,
)
from app.services.analyst_copilot import answer_copilot_query
from app.services.coverage_matrix import coverage_payload, snapshot_coverage
from app.services.finding_service import create_finding
from app.services.proof_capsule import get_or_create_capsule
from app.services.remediation import ensure_lifecycle, retest_lifecycle, update_lifecycle
from app.services.secret_store import encrypt_json


def test_coverage_matrix_score_increases_with_real_workspace_evidence():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="V11 Coverage", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)

        empty = coverage_payload(snapshot_coverage(db, project))
        assert empty["score"] < 40
        assert empty["gap"] > 0

        asset = Asset(project_id=project.id, target="127.0.0.1", kind="ip")
        db.add(asset); db.commit(); db.refresh(asset)
        db.add(Service(asset_id=asset.id, port=443, protocol="tcp", name="https", banner=""))
        db.add(Endpoint(asset_id=asset.id, url="https://127.0.0.1/", method="GET", status_code=200))
        db.add_all([
            Task(project_id=project.id, action="http_probe", target="https://127.0.0.1/", policy_class="READ_ONLY", status="done", detail=""),
            Task(project_id=project.id, action="headers_check", target="https://127.0.0.1/", policy_class="READ_ONLY", status="done", detail=""),
            Task(project_id=project.id, action="tls_check", target="127.0.0.1", policy_class="READ_ONLY", status="done", detail=""),
            Task(project_id=project.id, action="web_discovery", target="https://127.0.0.1/", policy_class="READ_ONLY", status="done", detail=""),
        ])
        db.add(BrowserSession(
            project_id=project.id,
            target_url="https://127.0.0.1/",
            status="done",
            final_url="https://127.0.0.1/",
            title="Home",
            browser_name="Chromium",
            summary_json=json.dumps({"requests": 5, "xhr_fetch": 1}),
        ))
        id1 = Identity(project_id=project.id, name="User A", role="User")
        id2 = Identity(project_id=project.id, name="User B", role="User")
        db.add_all([id1, id2]); db.commit(); db.refresh(id1); db.refresh(id2)
        req = StoredRequest(
            project_id=project.id,
            name="GET profile",
            method="GET",
            url="https://127.0.0.1/profile",
            headers_json="{}",
            secret_headers_encrypted="",
            body="",
            source="manual",
            policy_class="READ_ONLY",
        )
        db.add(req); db.commit(); db.refresh(req)
        db.add(AuthorizationCase(
            project_id=project.id,
            stored_request_id=req.id,
            test_type="horizontal",
            baseline_identity_id=id1.id,
            comparison_identity_id=id2.id,
            status="done",
            classification="authorization_control_enforced",
            confidence=95,
        ))
        finding = create_finding(
            db=db,
            project_id=project.id,
            title="Manual QA finding",
            severity="low",
            target="https://127.0.0.1/",
            description="Evidence QA.",
            recommendation="Review.",
            source="manual",
            evidence_kind="qa",
            evidence_content={"ok": True},
        )
        get_or_create_capsule(db, finding)
        db.commit()

        richer = coverage_payload(snapshot_coverage(db, project))
        assert richer["score"] > empty["score"]
        assert richer["covered"] > empty["covered"]
        keys = {x["key"]: x for x in richer["matrix"]}
        assert keys["http_baseline"]["status"] == "covered"
        assert keys["transport_headers"]["status"] == "covered"
        assert keys["browser_observation"]["status"] == "covered"
        assert keys["authorization_testing"]["status"] == "covered"
    finally:
        db.close()


def test_copilot_context_redacts_secrets_and_blocks_invalid_citations_and_tool_fields(monkeypatch):
    Base.metadata.create_all(bind=engine)
    captured = {}

    class AdversarialCopilot:
        async def analyst_copilot(self, question, context, allowed_refs):
            captured["context"] = context
            captured["allowed"] = allowed_refs
            valid = allowed_refs[0] if allowed_refs else ""
            return {
                "answer": "Evidence-grounded QA answer.",
                "citations": [valid, "kg:999999"],
                "gaps": ["Need analyst confirmation."],
                "suggested_views": ["knowledge_graph", "shell_console"],
                "tool_requests": [{"name": "arbitrary_command"}],
                "commands": ["whoami"],
            }

    monkeypatch.setattr("app.services.analyst_copilot.get_ai_provider", lambda: AdversarialCopilot())

    db = SessionLocal()
    try:
        project = Project(name="V11 Copilot Redaction", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)
        identity = Identity(
            project_id=project.id,
            name="User A",
            role="User",
            headers_encrypted=encrypt_json({"Authorization": "Bearer identity-secret"}),
            cookies_encrypted=encrypt_json({"sid": "cookie-secret"}),
        )
        db.add(identity)
        db.add(StoredRequest(
            project_id=project.id,
            name="Callback",
            method="GET",
            url="http://127.0.0.1/callback?ticket=t-secret&lang=zh",
            headers_json="{}",
            secret_headers_encrypted=encrypt_json({"Authorization": "Bearer request-secret"}),
            body="BODY-SECRET",
            source="manual",
            policy_class="READ_ONLY",
        ))
        db.commit()

        row = asyncio.run(answer_copilot_query(db, project, "What do we know about callback coverage?"))
        assert row.status == "done"
        payload = json.loads(row.answer_json)
        assert len(payload["citations"]) <= 1
        assert "kg:999999" not in payload["citations"]
        assert payload["suggested_views"] == ["knowledge_graph"]
        assert row.drift_count >= 4

        serialized = json.dumps(captured["context"], ensure_ascii=False)
        for secret in ["identity-secret", "cookie-secret", "request-secret", "BODY-SECRET", "t-secret"]:
            assert secret not in serialized
    finally:
        db.close()


class RetestFixture(BaseHTTPRequestHandler):
    fixed = False

    def do_GET(self):
        body = b"<html><body>retest</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        if type(self).fixed:
            self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def test_remediation_workflow_reproduced_then_resolved_via_proof_capsule():
    Base.metadata.create_all(bind=engine)
    server = HTTPServer(("127.0.0.1", 0), RetestFixture)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    db = SessionLocal()
    try:
        project = Project(name="V11 Remediation", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)
        target = f"http://127.0.0.1:{port}/"
        finding = create_finding(
            db=db,
            project_id=project.id,
            title="Missing security header: x-content-type-options",
            severity="low",
            target=target,
            description="Header absent.",
            recommendation="Add nosniff.",
            source="headers_check",
            evidence_kind="http_response_headers",
            evidence_content={"content-type": "text/html"},
        )
        lifecycle = ensure_lifecycle(db, finding)
        update_lifecycle(
            db, lifecycle,
            status="remediation",
            owner="Web Team",
            priority="high",
            remediation_note="Header change prepared.",
        )
        assert lifecycle.status == "remediation"
        assert lifecycle.owner == "Web Team"

        RetestFixture.fixed = False
        first = asyncio.run(retest_lifecycle(db, project, lifecycle))
        db.refresh(lifecycle)
        assert first.status == "reproduced"
        assert lifecycle.status == "remediation"
        assert lifecycle.retest_status == "reproduced"
        assert lifecycle.proof_capsule_id is not None

        RetestFixture.fixed = True
        second = asyncio.run(retest_lifecycle(db, project, lifecycle))
        db.refresh(lifecycle)
        assert second.status == "resolved"
        assert lifecycle.status == "resolved"
        assert lifecycle.retest_status == "resolved"
        assert lifecycle.last_retest_run_id == second.id

        events = db.query(RemediationEvent).filter(RemediationEvent.lifecycle_id == lifecycle.id).all()
        assert any(e.event_type == "retest_completed" and e.to_status == "resolved" for e in events)
    finally:
        RetestFixture.fixed = False
        db.close()
        server.shutdown()


def test_manual_finding_retest_never_fakes_resolution():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="V11 Manual Retest", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)
        finding = create_finding(
            db=db,
            project_id=project.id,
            title="Business logic candidate",
            severity="medium",
            target="http://127.0.0.1/",
            description="Manual validation required.",
            recommendation="Review manually.",
            source="manual_review",
            evidence_kind="analyst_note",
            evidence_content={"candidate": True},
        )
        lifecycle = ensure_lifecycle(db, finding)
        run = asyncio.run(retest_lifecycle(db, project, lifecycle))
        db.refresh(lifecycle)
        assert run.status == "needs_review"
        assert lifecycle.status == "retest_ready"
        assert lifecycle.status != "resolved"
    finally:
        db.close()


def test_v11_routes_render_copilot_citations_and_reports_include_closure_sections():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="V11 UI", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)
        db.add(Task(
            project_id=project.id,
            action="http_probe",
            target="http://127.0.0.1/",
            policy_class="READ_ONLY",
            status="done",
            detail="done",
        ))
        finding = create_finding(
            db=db,
            project_id=project.id,
            title="UI QA finding",
            severity="low",
            target="http://127.0.0.1/",
            description="QA",
            recommendation="QA",
            source="manual",
            evidence_kind="qa",
            evidence_content={"ok": True},
        )
        pid = project.id
    finally:
        db.close()

    with TestClient(app) as client:
        coverage = client.get(f"/projects/{pid}/coverage")
        remediation = client.get(f"/projects/{pid}/remediation")
        copilot_empty = client.get(f"/projects/{pid}/copilot")
        assert coverage.status_code == 200 and "Coverage Matrix" in coverage.text
        assert remediation.status_code == 200 and "Remediation & Retest" in remediation.text
        assert copilot_empty.status_code == 200 and "Analyst Copilot" in copilot_empty.text

        asked = client.post(
            f"/projects/{pid}/copilot",
            data={"question": "What project evidence exists?"},
            follow_redirects=False,
        )
        assert asked.status_code == 303

    db = SessionLocal()
    try:
        query = db.query(CopilotQuery).filter(CopilotQuery.project_id == pid).order_by(CopilotQuery.id.desc()).first()
        assert query is not None
        qid = query.id
        lifecycle = db.query(FindingLifecycle).filter(FindingLifecycle.project_id == pid).first()
        assert lifecycle is not None
        lid = lifecycle.id
    finally:
        db.close()

    with TestClient(app) as client:
        copilot = client.get(f"/projects/{pid}/copilot?selected={qid}")
        finding_page = client.get(f"/findings/{finding.id}")
        preview = client.get(f"/projects/{pid}/reports")
        md = client.get(f"/projects/{pid}/reports/export.md")
        html = client.get(f"/projects/{pid}/reports/export.html")
        assert copilot.status_code == 200
        assert "CITATIONS" in copilot.text
        assert "Remediation workflow" in finding_page.text
        for response in [preview, md, html]:
            assert response.status_code == 200
            assert "覆盖情况摘要" in response.text
            assert "整改摘要" in response.text
