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
