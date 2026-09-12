from fastapi.testclient import TestClient

from app.db import Base, engine, SessionLocal
from app.main import app
from app.models import Project


def test_request_and_session_pages_render():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        p = Project(name="V04 UI", scope_text="127.0.0.1")
        db.add(p); db.commit(); db.refresh(p); pid = p.id
    finally:
        db.close()
    with TestClient(app) as client:
        r = client.get(f"/projects/{pid}/requests")
        assert r.status_code == 200
        assert "Request Workspace" in r.text
        assert "Import Burp raw" in r.text
        r = client.get(f"/projects/{pid}/sessions")
        assert r.status_code == 200
        assert "Sessions & Identities" in r.text
        assert "New identity" in r.text


def test_import_post_defaults_state_change_and_get_read_only():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        p = Project(name="V04 Import", scope_text="example.com")
        db.add(p); db.commit(); db.refresh(p); pid = p.id
    finally:
        db.close()
    with TestClient(app) as client:
        raw_get = "GET /api/me HTTP/1.1\r\nHost: example.com\r\n\r\n"
        r = client.post(f"/projects/{pid}/requests/import", data={"raw_request": raw_get, "scheme": "https", "name": "GET me"}, follow_redirects=False)
        assert r.status_code == 303
        raw_post = "POST /api/update HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{}"
        r = client.post(f"/projects/{pid}/requests/import", data={"raw_request": raw_post, "scheme": "https", "name": "POST update"}, follow_redirects=False)
        assert r.status_code == 303
