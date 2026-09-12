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
