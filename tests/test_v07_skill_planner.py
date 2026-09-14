import asyncio
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading

from fastapi.testclient import TestClient

from app.db import Base, SessionLocal, engine
from app.main import app
from app.models import Identity, Project, SkillDefinition, SkillPlan, StoredRequest, Task
from app.services.skill_planner import (
    approve_skill_plan,
    deterministic_candidates,
    evidence_profile,
    generate_skill_plan,
    plan_payload,
)
from app.skills.registry import ensure_project_skill_rows, seed_builtin_skills


def test_deterministic_planner_adds_request_and_authorization_skills_when_evidence_exists():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="Planner Evidence", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)
        db.add_all([
            Identity(project_id=project.id, name="User A", role="User"),
            Identity(project_id=project.id, name="User B", role="User"),
            StoredRequest(
                project_id=project.id,
                name="Read account",
                method="GET",
                url="http://127.0.0.1/account/1",
                policy_class="READ_ONLY",
            ),
        ])
        db.commit()
        profile = evidence_profile(db, project.id, "http://127.0.0.1/")
        slugs = [x["slug"] for x in deterministic_candidates(profile)]
        assert "request-response-diff" in slugs
        assert "authorization-differential-review" in slugs
        assert "web-attack-surface-mapping" in slugs
    finally:
        db.close()


def test_generate_plan_uses_allowlisted_catalog_and_mock_ai():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="Planner Generate", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)
        plan = asyncio.run(generate_skill_plan(db, project, "http://127.0.0.1/"))
        payload = plan_payload(plan)
        builtins = {
            s.slug for s in db.query(SkillDefinition).filter(SkillDefinition.builtin == 1).all()
        }
        assert plan.status == "draft"
        assert payload["recommendations"]
        assert {x["slug"] for x in payload["recommendations"]}.issubset(builtins)
        assert "Mock provider" in plan.ai_summary
    finally:
        db.close()


def test_approve_plan_applies_exact_builtin_selection():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_builtin_skills(db)
        project = Project(name="Planner Approve", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)
        ensure_project_skill_rows(db, project.id)
        plan = asyncio.run(generate_skill_plan(db, project, "http://127.0.0.1/"))
        approved = approve_skill_plan(
            db,
            project.id,
            plan.id,
            ["web-attack-surface-mapping", "pentest-coverage-judge"],
        )
        payload = plan_payload(approved)
        assert approved.status == "approved"
        assert payload["approved_skills"] == [
            "web-attack-surface-mapping",
            "pentest-coverage-judge",
        ]
        enabled = {
            s.slug
            for s in db.query(SkillDefinition)
            .join(__import__("app.models", fromlist=["ProjectSkill"]).ProjectSkill,
                  __import__("app.models", fromlist=["ProjectSkill"]).ProjectSkill.skill_id == SkillDefinition.id)
            .filter(
                __import__("app.models", fromlist=["ProjectSkill"]).ProjectSkill.project_id == project.id,
                __import__("app.models", fromlist=["ProjectSkill"]).ProjectSkill.enabled == 1,
                SkillDefinition.builtin == 1,
            ).all()
        }
        assert enabled == {"web-attack-surface-mapping", "pentest-coverage-judge"}
    finally:
        db.close()


def test_planner_ui_generate_approve_and_scope_block():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="Planner UI", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)
        pid = project.id
    finally:
        db.close()

    with TestClient(app) as client:
        page = client.get(f"/projects/{pid}/skills/planner")
        assert page.status_code == 200
        assert "AI Skill Planner" in page.text
        assert "Human approval required" in page.text

        blocked = client.post(
            f"/projects/{pid}/skills/planner/generate",
            data={"target": "https://example.com/"},
        )
        assert blocked.status_code == 400

        generated = client.post(
            f"/projects/{pid}/skills/planner/generate",
            data={"target": "http://127.0.0.1/"},
            follow_redirects=False,
        )
        assert generated.status_code == 303

    db = SessionLocal()
    try:
        plan = db.query(SkillPlan).filter(SkillPlan.project_id == pid).order_by(SkillPlan.id.desc()).first()
        assert plan is not None
        plan_id = plan.id
    finally:
        db.close()

    with TestClient(app) as client:
        approved = client.post(
            f"/projects/{pid}/skills/planner/{plan_id}/approve",
            data={"selected_slugs": ["web-attack-surface-mapping", "pentest-coverage-judge"]},
            follow_redirects=False,
        )
        assert approved.status_code == 303
        page = client.get(f"/projects/{pid}/skills/planner?plan={plan_id}")
        assert "approved" in page.text.lower()
        assert "Execute approved plan" in page.text


class PlannerTargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            body = b"<html><body><a href='/next'>Next</a></body></html>"
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
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        pass


def test_approved_plan_executes_only_approved_safe_skill_selection():
    Base.metadata.create_all(bind=engine)
    server = HTTPServer(("127.0.0.1", 0), PlannerTargetHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    db = SessionLocal()
    try:
        project = Project(name="Planner Execute", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)
        pid = project.id
        plan = asyncio.run(generate_skill_plan(db, project, f"http://127.0.0.1:{port}/"))
        approve_skill_plan(db, pid, plan.id, ["web-attack-surface-mapping"])
        plan_id = plan.id
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
            actions = [t.action for t in db.query(Task).filter(Task.project_id == pid).all()]
            assert "http_probe" in actions
            assert "web_discovery" in actions
            assert "port_scan" not in actions
        finally:
            db.close()
    finally:
        server.shutdown()
