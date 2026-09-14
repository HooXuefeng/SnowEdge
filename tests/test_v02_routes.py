from fastapi.testclient import TestClient
from app.main import app
from app.db import Base, engine, SessionLocal
from app.models import Project

def test_status_api_and_scope_check():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="Status API", scope_text="127.0.0.1")
        db.add(project)
        db.commit()
        db.refresh(project)
        pid = project.id
    finally:
        db.close()

    with TestClient(app) as client:
        r = client.get(f"/api/projects/{pid}/status")
        assert r.status_code == 200
        assert "stats" in r.json()
        assert "tasks" in r.json()

        r = client.get(f"/api/projects/{pid}/scope-check", params={"target": "http://127.0.0.1:8000"})
        assert r.status_code == 200
        assert r.json()["allowed"] is True

        r = client.get(f"/api/projects/{pid}/scope-check", params={"target": "http://example.com"})
        assert r.status_code == 200
        assert r.json()["allowed"] is False


def test_project_can_be_created_in_unrestricted_target_mode():
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as client:
        response = client.post(
            "/projects",
            data={"name": "不限制目标项目", "scope": "", "skip_scope": "yes", "template_slug": "web-api"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        pid = int(response.headers["location"].rstrip("/").split("/")[-1])
        with SessionLocal() as db:
            project = db.get(Project, pid)
            assert project.scope_text == "*"
            assert project.status == "testing"
        queued = client.post(f"/api/projects/{pid}/scans", json={"targets": "example.test", "stages": ["http"]})
        assert queued.status_code == 200
        page = client.get(f"/projects/{pid}/scan-center")
        assert page.status_code == 200
        assert "当前项目为“不限制目标”模式" in page.text
