import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app.db import Base, engine, SessionLocal
from app.models import Identity, Project, ReplayResult
from app.services.request_workspace import create_stored_request, parse_raw_http_request, replay_request
from app.services.response_diff import compare_responses
from app.services.secret_store import decrypt_json, encrypt_json, masked_cookie_summary, masked_header_summary


def test_parse_burp_raw_request_and_secret_split():
    parsed = parse_raw_http_request(
        "GET /api/user?id=1 HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer secret-token\r\nCookie: sid=abc123\r\nAccept: application/json\r\n\r\n",
        scheme="https",
    )
    assert parsed.method == "GET"
    assert parsed.url == "https://example.com/api/user?id=1"
    assert parsed.headers["Authorization"] == "Bearer secret-token"


def test_secret_encryption_and_masking():
    token = encrypt_json({"Authorization": "Bearer super-secret-token"})
    assert "super-secret-token" not in token
    assert decrypt_json(token)["Authorization"] == "Bearer super-secret-token"
    summary = masked_header_summary(token)
    assert summary[0]["name"] == "Authorization"
    assert "super-secret-token" not in summary[0]["value"]


def test_response_diff_json_and_similarity():
    left = json.dumps({"user": {"id": 1, "name": "A"}, "role": "user"})
    right = json.dumps({"user": {"id": 2, "name": "B"}, "role": "admin", "extra": True})
    result = compare_responses(200, {"Content-Type": "application/json"}, left, 200, {"Content-Type": "application/json", "X-Test": "1"}, right)
    assert result["status"]["same"] is True
    assert result["json"]["detected"] is True
    assert "$.user.id" in result["json"]["changed"]
    assert "$.extra" in result["json"]["added"]
    assert result["headers"]["added"]["x-test"] == "1"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        identity = self.headers.get("X-Test-User", "anonymous")
        body = json.dumps({"viewer": identity, "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "session=should-not-be-rendered; HttpOnly")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def test_safe_replay_identity_and_scope_block():
    Base.metadata.create_all(bind=engine)
    server = HTTPServer(("127.0.0.1", 8944), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    db = SessionLocal()
    try:
        project = Project(name="V04 Replay", scope_text="127.0.0.1")
        db.add(project)
        db.commit(); db.refresh(project)
        identity = Identity(
            project_id=project.id,
            name="User A",
            role="User",
            headers_encrypted=encrypt_json({"X-Test-User": "user-a", "Authorization": "Bearer hidden"}),
            cookies_encrypted=encrypt_json({"sid": "secret-cookie"}),
        )
        db.add(identity); db.commit(); db.refresh(identity)
        stored = create_stored_request(db, project.id, "Profile", "GET", "http://127.0.0.1:8944/profile")
        result = asyncio.run(replay_request(db, ["127.0.0.1"], stored, identity))
        assert result.status_code == 200
        assert '"viewer": "user-a"' in result.response_body
        assert "should-not-be-rendered" not in result.response_headers_json
        assert "Bearer hidden" not in result.request_headers_json
        assert "secret-cookie" not in result.request_headers_json

        from app.services.report_data import request_blocks
        captured=request_blocks(db,project.id,stored.id,result.id)
        assert 'GET /profile HTTP/1.1' in captured['request']
        assert 'HTTP/1.0 200 OK' in captured['response']
        assert 'should-not-be-rendered' not in captured['response']
        stored.url='http://127.0.0.1:8944/edited';db.commit()
        assert request_blocks(db,project.id,stored.id,result.id)['request']==captured['request']

        outside = create_stored_request(db, project.id, "Outside", "GET", "http://example.com/")
        with pytest.raises(ValueError, match="outside authorized scope"):
            asyncio.run(replay_request(db, ["127.0.0.1"], outside, None))
    finally:
        db.close()
        server.shutdown()
