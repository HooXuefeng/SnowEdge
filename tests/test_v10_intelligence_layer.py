import asyncio
import json

from fastapi.testclient import TestClient

from app.db import Base, SessionLocal, engine
from app.main import app
from app.models import (
    AgentHandoff,
    AssessmentMemory,
    Asset,
    AuthorizationCase,
    BrowserEvent,
    BrowserSession,
    Endpoint,
    Evidence,
    Finding,
    Identity,
    KnowledgeEdge,
    KnowledgeNode,
    Project,
    Service,
    SpecialistAgentRun,
    StoredRequest,
    Task,
)
from app.services.assessment_memory import memory_summary, refresh_assessment_memory
from app.services.knowledge_graph import graph_payload, rebuild_knowledge_graph
from app.services.multi_agent import ROLE_ORDER, run_specialist_team
from app.services.secret_store import encrypt_json
from app.services.skill_planner import generate_skill_plan


def test_knowledge_graph_materializes_relations_without_copying_secrets():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="V10 Graph Redaction", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)

        asset = Asset(project_id=project.id, target="127.0.0.1", kind="ip")
        db.add(asset); db.commit(); db.refresh(asset)
        db.add(Service(asset_id=asset.id, port=443, protocol="tcp", name="https", banner="present"))
        endpoint = Endpoint(asset_id=asset.id, url="https://127.0.0.1/profile", method="GET", status_code=200)
        db.add(endpoint)

        identity = Identity(
            project_id=project.id,
            name="User A",
            role="User",
            headers_encrypted=encrypt_json({"Authorization": "Bearer auth-secret"}),
            cookies_encrypted=encrypt_json({"sid": "cookie-secret"}),
        )
        db.add(identity); db.commit(); db.refresh(identity)

        stored = StoredRequest(
            project_id=project.id,
            name="GET profile",
            method="GET",
            url="https://127.0.0.1/profile?ticket=t-secret&lang=zh",
            headers_json=json.dumps({"Accept": "application/json"}),
            secret_headers_encrypted=encrypt_json({"Authorization": "Bearer stored-secret"}),
            body="SECRET-BODY",
            source="manual",
            policy_class="READ_ONLY",
        )
        db.add(stored); db.commit(); db.refresh(stored)

        finding = Finding(
            project_id=project.id,
            title="Graph finding",
            severity="medium",
            target=stored.url,
            description="Finding description.",
            recommendation="Review.",
            source="manual",
        )
        db.add(finding); db.commit(); db.refresh(finding)
        db.add(Evidence(finding_id=finding.id, kind="raw_test", content="RAW-SECRET-EVIDENCE"))

        case = AuthorizationCase(
            project_id=project.id,
            stored_request_id=stored.id,
            test_type="horizontal",
            baseline_identity_id=identity.id,
            comparison_identity_id=None,
            status="done",
            classification="authorization_control_enforced",
            confidence=96,
            finding_id=finding.id,
        )
        db.add(case)

        browser = BrowserSession(
            project_id=project.id,
            target_url="https://127.0.0.1/profile",
            identity_id=identity.id,
            status="done",
            final_url="https://127.0.0.1/profile",
            title="Profile",
            browser_name="Chromium",
            summary_json=json.dumps({"requests": 2, "xhr_fetch": 1}),
        )
        db.add(browser); db.commit(); db.refresh(browser)
        db.add(BrowserEvent(
            project_id=project.id,
            browser_session_id=browser.id,
            event_type="request",
            method="GET",
            url=stored.url,
            resource_type="xhr",
            in_scope=1,
            detail_json=json.dumps({"headers": {"Authorization": "•••• protected ••••"}}),
        ))
        db.commit()

        summary = rebuild_knowledge_graph(db, project.id)
        assert summary["nodes"] > 0
        assert summary["edges"] > 0

        payload = graph_payload(db, project.id, limit=500)
        serialized = json.dumps(payload, ensure_ascii=False)
        for secret in ["auth-secret", "cookie-secret", "stored-secret", "SECRET-BODY", "RAW-SECRET-EVIDENCE", "t-secret"]:
            assert secret not in serialized

        relations = {edge["relation"] for edge in payload["edges"]}
        assert "HAS_IDENTITY" in relations
        assert "TESTS_REQUEST" in relations
        assert "SUPPORTED_BY" in relations
        assert "HAS_BROWSER_SESSION" in relations

        request_node = next(n for n in payload["nodes"] if n["type"] == "request")
        assert request_node["summary"]["headers_in_graph"] is False
        assert request_node["summary"]["body_in_graph"] is False
        identity_node = next(n for n in payload["nodes"] if n["type"] == "identity")
        assert identity_node["summary"]["secret_material_in_graph"] is False
    finally:
        db.close()


def test_assessment_memory_refresh_is_stable_and_marks_repeat_guidance():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="V10 Memory", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)

        identity = Identity(project_id=project.id, name="User A", role="User")
        db.add(identity); db.commit(); db.refresh(identity)
        stored = StoredRequest(
            project_id=project.id,
            name="Profile",
            method="GET",
            url="http://127.0.0.1/profile",
            headers_json="{}",
            secret_headers_encrypted="",
            body="",
            source="manual",
            policy_class="READ_ONLY",
        )
        db.add(stored); db.commit(); db.refresh(stored)

        db.add(AuthorizationCase(
            project_id=project.id,
            stored_request_id=stored.id,
            test_type="unauthenticated",
            baseline_identity_id=identity.id,
            status="done",
            classification="authorization_control_enforced",
            confidence=95,
        ))
        db.add(BrowserSession(
            project_id=project.id,
            target_url="http://127.0.0.1/",
            status="done",
            final_url="http://127.0.0.1/",
            title="Home",
            browser_name="Chromium",
            summary_json=json.dumps({"requests": 4, "xhr_fetch": 1, "blocked_out_of_scope": 0}),
        ))
        db.add(Task(
            project_id=project.id,
            action="port_scan",
            target="127.0.0.1",
            policy_class="LOW_RISK_VALIDATE",
            status="done",
            detail="done",
        ))
        db.commit()

        first = refresh_assessment_memory(db, project.id)
        first_count = first["count"]
        second = refresh_assessment_memory(db, project.id)
        assert second["count"] == first_count
        assert second["avoid_repeat"] >= 3

        auth_mem = (
            db.query(AssessmentMemory)
            .filter(AssessmentMemory.project_id == project.id, AssessmentMemory.memory_type == "authorization_test")
            .one()
        )
        assert auth_mem.repeat_guidance == "avoid_repeat"
        browser_mem = (
            db.query(AssessmentMemory)
            .filter(AssessmentMemory.project_id == project.id, AssessmentMemory.memory_type == "browser_observation")
            .one()
        )
        assert browser_mem.repeat_guidance == "avoid_repeat_recent"
    finally:
        db.close()


def test_skill_planner_downgrades_recent_browser_observation():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="V10 Memory Planner", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)
        target = "http://127.0.0.1/"
        db.add(BrowserSession(
            project_id=project.id,
            target_url=target,
            status="done",
            final_url=target,
            title="Already observed",
            browser_name="Chromium",
            summary_json=json.dumps({"requests": 3, "xhr_fetch": 1}),
        ))
        db.commit()

        plan = asyncio.run(generate_skill_plan(db, project, target))
        recommendations = json.loads(plan.recommendations_json)
        browser_rec = next(r for r in recommendations if r["slug"] == "browser-observation-workspace")
        assert browser_rec["priority"] == "low"
        assert "memory_note" in browser_rec
        assert "Existing assessment memory" in browser_rec["memory_note"]
    finally:
        db.close()


def test_mock_specialist_team_creates_six_bounded_roles_and_handoffs():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="V10 Agent Team", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)
        finding = Finding(
            project_id=project.id,
            title="Review finding",
            severity="low",
            target="http://127.0.0.1/",
            description="Evidence-backed low-risk finding.",
            recommendation="Review.",
            source="headers_check",
        )
        db.add(finding); db.commit(); db.refresh(finding)
        db.add(Evidence(finding_id=finding.id, kind="http_response_headers", content="{}"))
        db.commit()

        parent = asyncio.run(run_specialist_team(db, project))
        assert parent.status == "done"

        runs = (
            db.query(SpecialistAgentRun)
            .filter(SpecialistAgentRun.parent_agent_run_id == parent.id)
            .order_by(SpecialistAgentRun.id.asc())
            .all()
        )
        assert len(runs) == len(ROLE_ORDER) == 6
        assert {r.role_slug for r in runs} == set(ROLE_ORDER)
        assert all(r.status == "done" for r in runs)
        assert all(r.drift_count == 0 for r in runs)

        for run in runs:
            contract = json.loads(run.intent_contract_json)
            assert contract["analysis_only"] is True
            assert contract["tool_invocation"] is False
            assert contract["unknown_action_policy"] == "DENY"

        handoffs = db.query(AgentHandoff).filter(AgentHandoff.project_id == project.id).all()
        assert handoffs
        assert db.query(KnowledgeNode).filter(KnowledgeNode.project_id == project.id).count() > 0
        assert db.query(AssessmentMemory).filter(AssessmentMemory.project_id == project.id).count() > 0
    finally:
        db.close()


def test_specialist_team_blocks_tool_requests_and_invalid_handoffs(monkeypatch):
    Base.metadata.create_all(bind=engine)

    class DriftProvider:
        async def specialist_review(self, role, context, allowed_handoffs):
            return {
                "summary": "Attempted unsupported output.",
                "observations": [],
                "handoffs": [
                    {"to_role": "not_allowed_agent", "reason": "invalid", "subject_keys": []},
                ],
                "next_checks": [],
                "tool_requests": [{"name": "arbitrary_command"}],
                "commands": ["whoami"],
            }

    monkeypatch.setattr("app.services.multi_agent.get_ai_provider", lambda: DriftProvider())

    db = SessionLocal()
    try:
        project = Project(name="V10 Drift Guard", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)
        parent = asyncio.run(run_specialist_team(db, project))
        runs = db.query(SpecialistAgentRun).filter(SpecialistAgentRun.parent_agent_run_id == parent.id).all()
        assert len(runs) == 6
        assert all(r.drift_count >= 3 for r in runs)
        assert db.query(AgentHandoff).filter(AgentHandoff.project_id == project.id).count() == 0
        assert "intent-drift" in parent.summary
    finally:
        db.close()


def test_v10_intelligence_routes_render_and_team_runs():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="V10 UI", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)
        db.add(Task(
            project_id=project.id,
            action="http_probe",
            target="http://127.0.0.1/",
            policy_class="READ_ONLY",
            status="done",
            detail="done",
        ))
        db.commit()
        pid = project.id
    finally:
        db.close()

    with TestClient(app) as client:
        kg = client.get(f"/projects/{pid}/knowledge-graph")
        mem = client.get(f"/projects/{pid}/memory")
        team = client.get(f"/projects/{pid}/agent-team")
        api = client.get(f"/api/projects/{pid}/knowledge-graph")
        assert kg.status_code == 200 and "Knowledge Graph" in kg.text
        assert mem.status_code == 200 and "Assessment Memory" in mem.text
        assert team.status_code == 200 and "Specialist Agent Team" in team.text
        assert api.status_code == 200
        assert api.json()["summary"]["nodes"] > 0

        run = client.post(f"/projects/{pid}/agent-team/run", follow_redirects=False)
        assert run.status_code == 303

    db = SessionLocal()
    try:
        assert db.query(SpecialistAgentRun).filter(SpecialistAgentRun.project_id == pid).count() == 6
    finally:
        db.close()


def test_v10_report_exports_include_intelligence_sections():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="V10 Report Intelligence", scope_text="127.0.0.1")
        db.add(project); db.commit(); db.refresh(project)
        db.add(Task(
            project_id=project.id,
            action="http_probe",
            target="http://127.0.0.1/",
            policy_class="READ_ONLY",
            status="done",
            detail="done",
        ))
        db.commit()
        asyncio.run(run_specialist_team(db, project))
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
        for heading in ["知识图谱摘要", "测试记忆摘要", "专家复核"]:
            assert heading in preview.text
            assert heading in md.text
            assert heading in html.text
