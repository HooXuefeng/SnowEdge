from pathlib import Path
import os

TEST_DB = Path(__file__).resolve().parent / "test_templates.db"
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB.as_posix()}"

from fastapi.testclient import TestClient
from app.db import Base, engine, SessionLocal
from app.main import app
from app.models import Project, Finding, Evidence

def setup_module():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

def teardown_module():
    pass

def _create_project(name="Template Test"):
    db = SessionLocal()
    try:
        project = Project(name=name, scope_text="127.0.0.1")
        db.add(project)
        db.commit()
        db.refresh(project)
        return project.id
    finally:
        db.close()

def test_home_template_renders():
    with TestClient(app) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert "Workspaces" in response.text
        assert "New workspace" in response.text

def test_project_overview_renders():
    project_id = _create_project()
    with TestClient(app) as client:
        response = client.get(f"/projects/{project_id}")
        assert response.status_code == 200
        assert "Template Test" in response.text
        assert "Launch assessment" in response.text
        assert "AI Mission Control" in response.text

def test_workspace_routes_render():
    project_id = _create_project("Navigation Test")
    routes = [
        (f"/projects/{project_id}/attack-surface", "Attack Surface"),
        (f"/projects/{project_id}/endpoints", "Endpoints & Route Candidates"),
        (f"/projects/{project_id}/agent", "Mission Control"),
        (f"/projects/{project_id}/authorization", "Authorization Lab"),
        (f"/projects/{project_id}/skills", "Skill Hub"),
        (f"/projects/{project_id}/tasks", "Tool Runs"),
        (f"/projects/{project_id}/findings", "Findings"),
        (f"/projects/{project_id}/evidence", "Evidence"),
        (f"/projects/{project_id}/reports", "Report Preview"),
        (f"/projects/{project_id}/settings", "Workspace Settings"),
    ]
    with TestClient(app) as client:
        for path, marker in routes:
            response = client.get(path)
            assert response.status_code == 200, path
            assert marker.lower() in response.text.lower(), path

def test_legacy_assets_redirects():
    project_id = _create_project("Redirect Test")
    with TestClient(app) as client:
        response = client.get(f"/projects/{project_id}/assets", follow_redirects=False)
        assert response.status_code == 302
        assert response.headers["location"].endswith(f"/projects/{project_id}/attack-surface")

def test_finding_template_renders():
    db = SessionLocal()
    try:
        project = Project(name="Finding Test", scope_text="127.0.0.1")
        db.add(project)
        db.flush()
        finding = Finding(
            project_id=project.id,
            title="Missing Test Header",
            severity="low",
            target="http://127.0.0.1",
            description="Regression finding.",
            recommendation="Regression recommendation.",
            source="test",
        )
        db.add(finding)
        db.flush()
        db.add(Evidence(finding_id=finding.id, kind="test_evidence", content='{"ok": true}'))
        db.commit()
        db.refresh(finding)
        finding_id = finding.id
    finally:
        db.close()

    with TestClient(app) as client:
        response = client.get(f"/findings/{finding_id}")
        assert response.status_code == 200
        assert "Missing Test Header" in response.text
        assert "Evidence chain" in response.text
        assert "Regression recommendation." in response.text
