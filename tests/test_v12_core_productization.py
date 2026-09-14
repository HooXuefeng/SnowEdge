import asyncio
import io
import zipfile
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.db import Base, SessionLocal, engine
from app.main import app
from app.models import (
    AuthorizationMatrixRun,
    Endpoint,
    EndpointParameter,
    FindingOccurrence,
    Identity,
    PersistentJob,
    PersistentJobEvent,
    Project,
    StoredRequest,
)
from app.services.authorization_matrix import create_matrix_run, execute_matrix_run
from app.services.finding_service import create_finding
from app.services.job_engine import enqueue_job, recover_orphaned_jobs
from app.services.project_portability import export_project_zip, import_project_manifest, parse_project_zip
from app.services.request_workspace import create_stored_request
from app.services.secret_store import encrypt_json


def test_v12_persistent_job_scope_snapshot_recovery_and_secret_payload_guard():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="V12 Job Recovery", scope_text="app.example.test\n*.api.example.test")
        db.add(project); db.commit(); db.refresh(project)

        job = enqueue_job(
            db,
            project,
            "endpoint_sync",
            target="project:endpoints",
            payload={"reason": "qa"},
            max_attempts=3,
        )
        assert job.status == "queued"
        assert job.scope_hash
        assert json.loads(job.scope_snapshot_json) == ["app.example.test", "*.api.example.test"]
        event = db.query(PersistentJobEvent).filter(PersistentJobEvent.job_id == job.id).one()
        assert event.event_type == "queued"

        job.status = "running"
        db.commit()
        assert recover_orphaned_jobs(db) >= 1
        db.refresh(job)
        assert job.status == "queued"
        recovered = (
            db.query(PersistentJobEvent)
            .filter(PersistentJobEvent.job_id == job.id, PersistentJobEvent.event_type == "recovered")
            .one()
        )
        assert "restart" in recovered.detail.lower()

        with pytest.raises(ValueError):
            enqueue_job(
                db,
                project,
                "endpoint_sync",
                payload={"authorization": "Bearer MUST-NOT-PERSIST"},
            )
    finally:
        db.close()


def test_v12_endpoint_parameter_inventory_redacts_sensitive_values():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="V12 Endpoint Inventory", scope_text="api.example.test")
        db.add(project); db.commit(); db.refresh(project)

        create_stored_request(
            db,
            project.id,
            "Profile query",
            "GET",
            "https://api.example.test/users/10001?lang=zh&token=query-secret&ticket=ticket-secret&userId=10001",
            headers={
                "Accept": "application/json",
                "Authorization": "Bearer header-secret",
                "X-Trace": "trace-123",
            },
            body=json.dumps({
                "profile": {"email": "user@example.test", "password": "body-secret"},
                "page": 1,
            }),
            source="qa",
            explicit_read_only=True,
        )

        endpoint = (
            db.query(Endpoint)
            .join(Endpoint.asset)
            .filter_by(project_id=project.id)
            .order_by(Endpoint.id.desc())
            .first()
        )
        assert endpoint is not None
        assert endpoint.normalized_path.endswith("/users/{id}")
        assert endpoint.fingerprint
        assert endpoint.auth_observed == 1

        params = db.query(EndpointParameter).filter(EndpointParameter.endpoint_id == endpoint.id).all()
        by_name = {p.name: p for p in params}
        assert by_name["lang"].example_redacted == "zh"
        assert by_name["token"].sensitive == 1
        assert by_name["token"].example_redacted == "••••"
        assert by_name["ticket"].sensitive == 1
        assert by_name["ticket"].example_redacted == "••••"
        assert by_name["Authorization"].sensitive == 1
        assert by_name["Authorization"].example_redacted == "••••"
        assert by_name["profile.password"].sensitive == 1
        assert by_name["profile.password"].example_redacted == "••••"

        serialized = json.dumps([
            {"name": p.name, "example": p.example_redacted, "sensitive": p.sensitive}
            for p in params
        ], ensure_ascii=False)
        for secret in ["query-secret", "ticket-secret", "header-secret", "body-secret"]:
            assert secret not in serialized
    finally:
        db.close()


def test_v12_finding_dedupe_taxonomy_and_occurrence_chain():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="V12 Finding Dedupe", scope_text="app.example.test")
        db.add(project); db.commit(); db.refresh(project)

        first = create_finding(
            db=db,
            project_id=project.id,
            title="Potential Horizontal Authorization Gap",
            severity="medium",
            target="https://app.example.test/api/order/10001",
            description="Authorization behavior requires review.",
            recommendation="Enforce object-level authorization.",
            source="authorization_testing",
            evidence_kind="authorization_candidate_summary",
            evidence_content={"case": 1},
        )
        second = create_finding(
            db=db,
            project_id=project.id,
            title="Potential Horizontal Authorization Gap",
            severity="medium",
            target="https://app.example.test/api/order/20002",
            description="Authorization behavior requires review.",
            recommendation="Enforce object-level authorization.",
            source="browser_review",
            evidence_kind="authorization_candidate_summary",
            evidence_content={"case": 2},
        )

        assert first.id == second.id
        assert first.fingerprint
        assert first.cwe_id == "CWE-862"
        assert first.owasp_category == "A01:2021 Broken Access Control"
        assert first.txb02_category == "权限控制"

        occurrences = (
            db.query(FindingOccurrence)
            .filter(FindingOccurrence.finding_id == first.id)
            .order_by(FindingOccurrence.id.asc())
            .all()
        )
        assert len(occurrences) >= 2
        assert occurrences[-1].fingerprint == first.fingerprint
    finally:
        db.close()


def test_v12_authorization_matrix_explicit_identity_boundary(monkeypatch):
    Base.metadata.create_all(bind=engine)

    async def fake_run_case(
        db,
        project_scope,
        case,
        baseline_identity,
        comparison_identity,
        auto_candidate_finding=None,
    ):
        case.status = "done"
        case.classification = (
            "authorization_control_enforced"
            if comparison_identity is not None
            else "potential_unauthenticated_access"
        )
        case.confidence = 96
        case.summary_json = json.dumps({"qa": True})
        db.commit()
        db.refresh(case)
        return case

    monkeypatch.setattr("app.services.authorization_matrix.run_authorization_case", fake_run_case)

    db = SessionLocal()
    try:
        project = Project(name="V12 Authorization Matrix", scope_text="app.example.test")
        db.add(project); db.commit(); db.refresh(project)
        identities = [Identity(project_id=project.id, name=f"User {n}", role="User") for n in ["A", "B", "C"]]
        db.add_all(identities); db.commit()
        for identity in identities:
            db.refresh(identity)

        req = StoredRequest(
            project_id=project.id,
            name="GET order 10001",
            method="GET",
            url="https://app.example.test/api/order/10001",
            headers_json="{}",
            secret_headers_encrypted="",
            body="",
            source="manual",
            policy_class="READ_ONLY",
        )
        db.add(req); db.commit(); db.refresh(req)

        matrix = create_matrix_run(
            db, project, req.id, identities[0].id,
            [identities[1].id, identities[2].id], True,
        )
        asyncio.run(execute_matrix_run(db, project, matrix))
        db.refresh(matrix)

        summary = json.loads(matrix.summary_json)
        assert matrix.status == "done"
        assert len(json.loads(matrix.case_ids_json)) == 3
        assert len(summary["comparisons"]) == 3
        assert summary["enforced_count"] == 2
        assert summary["candidate_count"] == 1

        post_req = StoredRequest(
            project_id=project.id,
            name="POST order",
            method="POST",
            url="https://app.example.test/api/order",
            headers_json="{}",
            secret_headers_encrypted="",
            body="{}",
            source="manual",
            policy_class="STATE_CHANGE",
        )
        db.add(post_req); db.commit(); db.refresh(post_req)
        with pytest.raises(ValueError):
            create_matrix_run(
                db, project, post_req.id, identities[0].id,
                [identities[1].id], False,
            )
    finally:
        db.close()


def test_v12_sanitized_project_export_import_omits_secrets():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(
            name="V12 Portable",
            scope_text="app.example.test",
            client_name="Example Client",
            status="testing",
            authorization_note="Authorized QA.",
        )
        db.add(project); db.commit(); db.refresh(project)
        identity = Identity(
            project_id=project.id,
            name="User A",
            role="User",
            headers_encrypted=encrypt_json({"Authorization": "Bearer IDENTITY-SECRET"}),
            cookies_encrypted=encrypt_json({"sid": "COOKIE-SECRET"}),
            notes="PRIVATE-IDENTITY-NOTE",
        )
        db.add(identity); db.commit(); db.refresh(identity)
        create_stored_request(
            db,
            project.id,
            "Portable Request",
            "GET",
            "https://app.example.test/api/profile?token=URL-SECRET",
            headers={"Authorization": "Bearer REQUEST-SECRET", "Accept": "application/json"},
            body="BODY-SECRET",
            source="manual",
            explicit_read_only=True,
        )
        create_finding(
            db=db,
            project_id=project.id,
            title="Missing security header: strict-transport-security",
            severity="low",
            target="https://app.example.test/",
            description="HSTS absent.",
            recommendation="Enable HSTS.",
            source="headers_check",
            evidence_kind="http_response_headers",
            evidence_content={"Server": "qa"},
        )

        package = export_project_zip(db, project)
        assert package[:2] == b"PK"
        with zipfile.ZipFile(io.BytesIO(package), "r") as zf:
            manifest_text = zf.read("manifest.json").decode("utf-8")
        for secret in [
            "IDENTITY-SECRET", "COOKIE-SECRET", "REQUEST-SECRET",
            "BODY-SECRET", "PRIVATE-IDENTITY-NOTE", "URL-SECRET",
        ]:
            assert secret not in manifest_text

        manifest = parse_project_zip(package)
        assert manifest["security_notice"]["identity_secrets_included"] is False
        assert manifest["security_notice"]["stored_request_bodies_included"] is False
        assert all(x["credentials_omitted"] for x in manifest["identities"])
        assert all(x["body_omitted"] for x in manifest["stored_requests"])

        imported = import_project_manifest(db, manifest)
        assert imported.id != project.id
        assert imported.name.endswith("（导入）")
        imported_identity = db.query(Identity).filter(Identity.project_id == imported.id).one()
        assert imported_identity.headers_encrypted == ""
        assert imported_identity.cookies_encrypted == ""
        imported_request = db.query(StoredRequest).filter(StoredRequest.project_id == imported.id).one()
        assert imported_request.body == ""
        assert imported_request.secret_headers_encrypted == ""
    finally:
        db.close()


def test_v12_legacy_schema_upgrades_to_alembic_head(tmp_path):
    db_path = tmp_path / "legacy_v11.db"
    sql = (
        "CREATE TABLE projects (id INTEGER PRIMARY KEY, name VARCHAR(200), scope_text TEXT, created_at DATETIME);"
        "CREATE TABLE assets (id INTEGER PRIMARY KEY, project_id INTEGER, target VARCHAR(500), kind VARCHAR(50), created_at DATETIME);"
        "CREATE TABLE endpoints (id INTEGER PRIMARY KEY, asset_id INTEGER, url VARCHAR(1000), method VARCHAR(16), status_code INTEGER, created_at DATETIME);"
        "CREATE TABLE findings (id INTEGER PRIMARY KEY, project_id INTEGER, title VARCHAR(300), severity VARCHAR(30), target VARCHAR(1000), description TEXT, recommendation TEXT, source VARCHAR(100), created_at DATETIME);"
        "CREATE TABLE tasks (id INTEGER PRIMARY KEY, project_id INTEGER, action VARCHAR(100), target VARCHAR(1000), policy_class VARCHAR(50), status VARCHAR(50), detail TEXT, created_at DATETIME);"
        "CREATE TABLE evidence (id INTEGER PRIMARY KEY, finding_id INTEGER, kind VARCHAR(100), content TEXT, created_at DATETIME);"
        "CREATE TABLE stored_requests (id INTEGER PRIMARY KEY, project_id INTEGER, name VARCHAR(240), method VARCHAR(16), url VARCHAR(2000), headers_json TEXT, secret_headers_encrypted TEXT, body TEXT, source VARCHAR(80), policy_class VARCHAR(50), created_at DATETIME);"
        "CREATE TABLE identities (id INTEGER PRIMARY KEY, project_id INTEGER, name VARCHAR(120), role VARCHAR(80), headers_encrypted TEXT, cookies_encrypted TEXT, notes TEXT, created_at DATETIME);"
        "INSERT INTO projects(id,name,scope_text) VALUES(1,'Legacy','127.0.0.1');"
    )
    bootstrap = (
        "import sqlite3\n"
        f"db=sqlite3.connect(r'{db_path}')\n"
        f"db.executescript({sql!r})\n"
        "db.commit(); db.close()\n"
    )
    subprocess.run([sys.executable, "-c", bootstrap], check=True)

    env = os.environ.copy()
    env["DATABASE_URL"] = f"sqlite:///{db_path}"
    code = (
        "from sqlalchemy import inspect\n"
        "from app.db import engine\n"
        "from app.schema_migrations import ensure_schema_current\n"
        "result=ensure_schema_current()\n"
        "i=inspect(engine)\n"
        "project_cols={c['name'] for c in i.get_columns('projects')}\n"
        "endpoint_cols={c['name'] for c in i.get_columns('endpoints')}\n"
        "finding_cols={c['name'] for c in i.get_columns('findings')}\n"
        "assert 'client_name' in project_cols\n"
        "assert 'fingerprint' in endpoint_cols\n"
        "assert 'cwe_id' in finding_cols\n"
        "tables=set(i.get_table_names())\n"
        "assert {'persistent_jobs','endpoint_parameters','authorization_matrix_runs','finding_occurrences','alembic_version'} <= tables\n"
        "with engine.connect() as conn: rev=conn.exec_driver_sql('SELECT version_num FROM alembic_version').scalar()\n"
        "assert rev == 'v1_6_2_assetux'\n"
        "print(result, rev)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(Path(__file__).resolve().parents[1]),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "v1_6_2_assetux" in result.stdout


def test_v12_chinese_core_pages_render():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="V12 中文验收", scope_text="app.example.test")
        db.add(project); db.commit(); db.refresh(project)
        pid = project.id
    finally:
        db.close()

    with TestClient(app) as client:
        checks = [
            (f"/projects/{pid}/settings", ["项目设置", "项目与授权信息", "导出脱敏项目包"]),
            (f"/projects/{pid}/jobs", ["任务中心", "持久化队列"]),
            (f"/projects/{pid}/authorization-matrix", ["权限矩阵", "不做对象枚举"]),
            (f"/projects/{pid}/endpoints", ["接口资产与参数模型", "参数记录"]),
            (f"/projects/{pid}/findings", ["漏洞发现", "CWE"]),
        ]
        for url, markers in checks:
            response = client.get(url)
            assert response.status_code == 200
            for marker in markers:
                assert marker in response.text
