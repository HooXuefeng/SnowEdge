import json

from app.db import Base, SessionLocal, engine
from app.models import Asset, Evidence, Finding, Project, Service
from app.services.passive_imports import import_snowforge_json


def test_snowforge_package_imports_scope_filtered_candidates_and_evidence():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="SnowRelay Bridge", scope_text="127.0.0.1")
        db.add(project)
        db.commit()
        db.refresh(project)
        package = {
            "schema": "snowedge-import/1",
            "producer": {"name": "SnowRelay", "version": "0.5.0"},
            "record_count": 2,
            "inputs": [{"name": "scan.csv", "sha256": "a" * 64, "size": 100}],
            "sensitive_fields": {"password_included": False},
            "records": [
                {
                    "asset": "127.0.0.1", "port": "443", "protocol": "tcp", "service": "https",
                    "severity": "高危", "title": "测试证书风险", "description": "需要人工复核。",
                    "evidence": "scanner observation", "recommendation": "更新证书。",
                    "risk_type": "高危漏洞", "credential_status": "未发现凭据",
                    "source": {"platform": "Nessus", "file": "scan.csv", "sheet": "CSV", "row": "2"},
                },
                {
                    "asset": "10.99.99.99", "severity": "高危", "title": "范围外结果",
                    "source": {"file": "scan.csv", "sheet": "CSV", "row": "3"},
                },
            ],
        }
        batch = import_snowforge_json(db, project, "handoff.snowedge.json", json.dumps(package).encode())
        assert batch.status == "done"
        assert batch.records_imported == 1
        assert batch.records_skipped == 1
        asset = db.query(Asset).filter(Asset.project_id == project.id, Asset.target == "127.0.0.1").one()
        assert db.query(Service).filter(Service.asset_id == asset.id, Service.port == 443).count() == 1
        finding = db.query(Finding).filter(Finding.project_id == project.id, Finding.source == "snowrelay_import").one()
        assert finding.finding_state == "candidate"
        evidence = db.query(Evidence).filter(Evidence.finding_id == finding.id).one()
        assert "scanner observation" in evidence.content
        assert "password_included" in evidence.content
    finally:
        db.close()


def test_snowforge_package_rejects_plaintext_password():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="SnowForge Secret Rejection", scope_text="127.0.0.1")
        db.add(project)
        db.commit()
        db.refresh(project)
        package = {
            "schema": "snowedge-import/1",
            "producer": {"name": "SnowForge", "version": "0.3.0"},
            "record_count": 1,
            "records": [{"asset": "127.0.0.1", "password": "secret"}],
        }
        try:
            import_snowforge_json(db, project, "unsafe.snowedge.json", json.dumps(package).encode())
        except ValueError as exc:
            assert "口令明文" in str(exc)
        else:
            raise AssertionError("plaintext password package should be rejected")
    finally:
        db.close()


def test_snowlens_package_imports_candidate_finding_and_evidence():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        project = Project(name="SnowLens Bridge", scope_text="example.test")
        db.add(project)
        db.commit()
        db.refresh(project)
        package = {
            "schema": "snowedge-import/1",
            "producer": {"name": "SnowLens", "version": "1.1.0"},
            "record_count": 1,
            "sensitive_fields": {"password_included": False, "evidence_masked": True},
            "records": [{
                "asset": "example.test",
                "port": "443",
                "protocol": "tcp",
                "service": "https",
                "severity": "high",
                "title": "JWT-like token",
                "description": "SnowLens 前端信息暴露候选。",
                "evidence": "eyJa****************2345",
                "recommendation": "人工确认并轮换真实凭据。",
                "risk_type": "secret",
                "match_reason": "rule=secret.jwt; confidence=high",
                "credential_status": "未执行凭据测试",
                "source": {"platform": "SnowLens", "file": "app.js.map", "sheet": "Finding", "row": "17"},
            }],
        }
        batch = import_snowforge_json(
            db,
            project,
            "snowlens-results.snowedge.json",
            json.dumps(package, ensure_ascii=False).encode("utf-8"),
        )
        assert batch.status == "done"
        finding = db.query(Finding).filter_by(project_id=project.id, source="snowlens_import").one()
        assert finding.finding_state == "candidate"
        evidence = db.query(Evidence).filter_by(finding_id=finding.id, kind="snowlens_exposure_signal").one()
        assert "secret.jwt" in evidence.content
    finally:
        db.close()
