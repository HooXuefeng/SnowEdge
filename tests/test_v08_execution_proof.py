import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from fastapi.testclient import TestClient

from app.db import Base, SessionLocal, engine
from app.main import app
from app.models import (
    ExecutionGraphNode, Finding, Project, ProofCapsule, RetestRun, SkillPlan
)
from app.services.execution_graph import graph_payload, mark_graph_approved
from app.services.finding_service import create_finding
from app.services.proof_capsule import get_or_create_capsule, run_retest
from app.services.skill_planner import approve_skill_plan, generate_skill_plan


def test_skill_plan_creates_execution_graph_and_approval_marks_nodes():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="V08 Graph", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)

        plan = asyncio.run(generate_skill_plan(db, project, "http://127.0.0.1/"))
        graph = graph_payload(db, plan.id)
        slugs = [
            node["slug"]
            for stage in graph["stages"]
            for node in stage["nodes"]
        ]
        assert "web-attack-surface-mapping" in slugs
        assert "javascript-api-mapper" in slugs
        assert graph["node_count"] >= 5

        approve_skill_plan(
            db,
            project.id,
            plan.id,
            ["web-attack-surface-mapping", "javascript-api-mapper", "pentest-coverage-judge"],
        )
        nodes = db.query(ExecutionGraphNode).filter(ExecutionGraphNode.skill_plan_id == plan.id).all()
        by_slug = {n.skill_slug: n for n in nodes}
        assert by_slug["web-attack-surface-mapping"].status == "approved"
        assert by_slug["javascript-api-mapper"].status == "approved"
        assert by_slug["pentest-coverage-judge"].status == "approved"
        assert any(n.status == "disabled" for n in nodes)
        deps = json.loads(by_slug["javascript-api-mapper"].depends_on_json)
        assert "web-attack-surface-mapping" in deps
    finally:
        db.close()


class HeaderFixture(BaseHTTPRequestHandler):
    include_header = False

    def do_GET(self):
        body = b"<html><body>proof fixture</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        if type(self).include_header:
            self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def test_proof_capsule_header_retest_reproduced_then_resolved():
    Base.metadata.create_all(bind=engine)
    server = HTTPServer(("127.0.0.1", 0), HeaderFixture)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    db = SessionLocal()
    try:
        project = Project(name="V08 Proof Header", scope_text="127.0.0.1")
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

        capsule = get_or_create_capsule(db, finding)
        assert capsule.verifier_type == "http_header_absence"
        assert capsule.status == "ready"

        HeaderFixture.include_header = False
        first = asyncio.run(run_retest(db, project, finding, capsule))
        assert first.status == "reproduced"
        db.refresh(capsule)
        assert capsule.status == "reproduced"

        HeaderFixture.include_header = True
        second = asyncio.run(run_retest(db, project, finding, capsule))
        assert second.status == "resolved"
        db.refresh(capsule)
        assert capsule.status == "resolved"
        assert capsule.retest_count == 2

        history = db.query(RetestRun).filter(RetestRun.proof_capsule_id == capsule.id).all()
        assert len(history) == 2
        assert all(run.evidence_id for run in history)
    finally:
        HeaderFixture.include_header = False
        db.close()
        server.shutdown()


def test_generic_finding_capsule_does_not_fake_automatic_proof():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="V08 Manual Capsule", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)
        finding = create_finding(
            db=db,
            project_id=project.id,
            title="Manual business logic candidate",
            severity="medium",
            target="http://127.0.0.1/",
            description="Needs analyst confirmation.",
            recommendation="Review manually.",
            source="manual_review",
            evidence_kind="analyst_note",
            evidence_content={"note": "candidate"},
        )
        capsule = get_or_create_capsule(db, finding)
        assert capsule.verifier_type == "evidence_snapshot"
        assert capsule.status == "needs_review"

        run = asyncio.run(run_retest(db, project, finding, capsule))
        assert run.status == "needs_review"
        assert "No automatic verifier" in run.detail
    finally:
        db.close()


def test_proof_capsule_retest_blocks_current_out_of_scope_target():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="V08 Scope Proof", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)
        finding = create_finding(
            db=db,
            project_id=project.id,
            title="Missing security header: x-content-type-options",
            severity="low",
            target="https://example.com/",
            description="Historical evidence.",
            recommendation="Review header.",
            source="headers_check",
            evidence_kind="http_response_headers",
            evidence_content={},
        )
        capsule = get_or_create_capsule(db, finding)
        run = asyncio.run(run_retest(db, project, finding, capsule))
        assert run.status == "error"
        assert "outside" in run.detail.lower()
    finally:
        db.close()


def test_execution_graph_and_proof_capsule_pages_render():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="V08 UI", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)
        plan = asyncio.run(generate_skill_plan(db, project, "http://127.0.0.1/"))
        finding = create_finding(
            db=db,
            project_id=project.id,
            title="Missing security header: referrer-policy",
            severity="low",
            target="http://127.0.0.1/",
            description="Missing policy.",
            recommendation="Add policy.",
            source="headers_check",
            evidence_kind="http_response_headers",
            evidence_content={},
        )
        pid, plan_id, finding_id = project.id, plan.id, finding.id
    finally:
        db.close()

    with TestClient(app) as client:
        graph = client.get(f"/projects/{pid}/execution-graph?plan={plan_id}")
        assert graph.status_code == 200
        assert "Execution Graph" in graph.text
        assert "web-attack-surface-mapping" in graph.text

        finding_page = client.get(f"/findings/{finding_id}")
        assert finding_page.status_code == 200
        assert "Finding Proof Capsule" in finding_page.text
        assert "Create Proof Capsule" in finding_page.text

        create = client.post(f"/findings/{finding_id}/proof-capsule", follow_redirects=False)
        assert create.status_code == 303
        finding_page = client.get(f"/findings/{finding_id}")
        assert "http_header_absence" in finding_page.text
        assert "Retest Finding" in finding_page.text


class GraphExecutionFixture(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            body = b"<html><body><a href='/next'>Next</a><script src='/app.js'></script></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/next":
            body = b"<html><body>next</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/app.js":
            body = b"fetch('/api/profile')"
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        pass


def test_approved_plan_execution_updates_graph_from_skill_runs():
    Base.metadata.create_all(bind=engine)
    server = HTTPServer(("127.0.0.1", 0), GraphExecutionFixture)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    db = SessionLocal()
    try:
        project = Project(name="V08 Graph Execute", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)
        plan = asyncio.run(generate_skill_plan(db, project, f"http://127.0.0.1:{port}/"))
        approve_skill_plan(
            db,
            project.id,
            plan.id,
            ["web-attack-surface-mapping", "javascript-api-mapper", "pentest-coverage-judge"],
        )
        pid, plan_id = project.id, plan.id
    finally:
        db.close()

    try:
        with TestClient(app) as client:
            response = client.post(
                f"/projects/{pid}/skills/planner/{plan_id}/execute",
                follow_redirects=False,
            )
            assert response.status_code == 303

        db = SessionLocal()
        try:
            plan = db.get(SkillPlan, plan_id)
            assert plan.status == "executed"
            nodes = {
                n.skill_slug: n
                for n in db.query(ExecutionGraphNode)
                .filter(ExecutionGraphNode.skill_plan_id == plan_id)
                .all()
            }
            assert nodes["web-attack-surface-mapping"].status == "done"
            assert nodes["web-attack-surface-mapping"].skill_run_id is not None
            assert nodes["javascript-api-mapper"].status == "done"
            assert nodes["pentest-coverage-judge"].status == "done"
            assert any(n.status == "disabled" for n in nodes.values())
        finally:
            db.close()
    finally:
        server.shutdown()


def test_report_exports_include_execution_and_verification_sections():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="V08 Report", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)
        plan = asyncio.run(generate_skill_plan(db, project, "http://127.0.0.1/"))
        finding = create_finding(
            db=db,
            project_id=project.id,
            title="Missing security header: referrer-policy",
            severity="low",
            target="http://127.0.0.1/",
            description="Missing policy.",
            recommendation="Add policy.",
            source="headers_check",
            evidence_kind="http_response_headers",
            evidence_content={},
        )
        get_or_create_capsule(db, finding)
        pid = project.id
    finally:
        db.close()

    with TestClient(app) as client:
        md = client.get(f"/projects/{pid}/reports/export.md")
        html = client.get(f"/projects/{pid}/reports/export.html")
        preview = client.get(f"/projects/{pid}/reports")
        assert md.status_code == 200
        assert html.status_code == 200
        assert preview.status_code == 200
        assert "执行过程摘要" in md.text
        assert "漏洞验证摘要" in md.text
        assert "验证状态：" in md.text
        assert "执行过程摘要" in html.text
        assert "漏洞验证摘要" in html.text
        assert "漏洞验证摘要" in preview.text
