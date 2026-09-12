from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, text

from .db import Base, engine


BASE_DIR = Path(__file__).resolve().parent.parent


def _config() -> Config:
    cfg = Config(str(BASE_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BASE_DIR / "migrations"))
    return cfg


def _legacy_evidence_patch() -> None:
    if engine.dialect.name != "sqlite":
        return
    inspector = inspect(engine)
    if "evidence" not in inspector.get_table_names():
        return
    columns = {c["name"] for c in inspector.get_columns("evidence")}
    if "task_id" not in columns:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE evidence ADD COLUMN task_id INTEGER REFERENCES tasks(id)"))


def ensure_schema_current() -> dict:
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    cfg = _config()

    user_tables = tables - {"alembic_version"}
    if not user_tables:
        Base.metadata.create_all(bind=engine)
        command.stamp(cfg, "head", purge=True)
        return {"mode": "fresh", "revision": "head"}

    _legacy_evidence_patch()
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())

    project_columns = {c["name"] for c in inspector.get_columns("projects")} if "projects" in tables else set()
    endpoint_columns = {c["name"] for c in inspector.get_columns("endpoints")} if "endpoints" in tables else set()
    finding_columns = {c["name"] for c in inspector.get_columns("findings")} if "findings" in tables else set()
    job_columns = {c["name"] for c in inspector.get_columns("persistent_jobs")} if "persistent_jobs" in tables else set()
    evidence_columns = {c["name"] for c in inspector.get_columns("evidence")} if "evidence" in tables else set()

    looks_v12 = (
        "client_name" in project_columns
        and "fingerprint" in endpoint_columns
        and "cwe_id" in finding_columns
        and "persistent_jobs" in tables
        and "endpoint_parameters" in tables
        and "authorization_matrix_runs" in tables
        and "finding_occurrences" in tables
    )
    looks_v13 = (
        looks_v12
        and "worker_id" in job_columns
        and "integrity_sha256" in evidence_columns
        and "finding_state" in finding_columns
        and "job_workers" in tables
        and "evidence_provenance" in tables
        and "import_batches" in tables
        and "import_records" in tables
    )

    looks_v14 = (
        looks_v13
        and "template_slug" in project_columns
        and "app_preferences" in tables
        and "evidence_attachments" in tables
        and "backup_records" in tables
    )

    attachment_columns = {c["name"] for c in inspector.get_columns("evidence_attachments")} if "evidence_attachments" in tables else set()
    looks_v15 = (
        looks_v14
        and "stored_request_revisions" in tables
        and "annotation_json" in attachment_columns
        and "sort_order" in attachment_columns
    )

    identity_columns = {c["name"] for c in inspector.get_columns("identities")} if "identities" in tables else set()
    backup_columns = {c["name"] for c in inspector.get_columns("backup_records")} if "backup_records" in tables else set()
    looks_v16 = (looks_v15 and "secret_vault_items" in tables and "workspace_drafts" in tables and "recovery_events" in tables and "vault_item_id" in identity_columns and "detail_json" in backup_columns)
    looks_v162 = (looks_v16 and "technology_fingerprints" in tables and "fingerprint_rules" in tables and "scan_profiles" in tables and "network_route_profiles" in tables and "batch_assessments" in tables and "batch_assessment_items" in tables and "scan_profile_id" in project_columns and "network_route_profile_id" in project_columns)
    if looks_v162:
        command.stamp(cfg, "head", purge=True)
        return {"mode": "current-schema-adopted", "revision": "head"}

    if "alembic_version" not in tables:
        if looks_v16:
            command.stamp(cfg, "v1_6_reliability", purge=True)
        elif looks_v15:
            command.stamp(cfg, "v1_5_workflow2", purge=True)
        elif looks_v14:
            command.stamp(cfg, "v1_4_personal", purge=True)
        elif looks_v13:
            command.stamp(cfg, "v1_3_enterprise", purge=True)
        elif looks_v12:
            command.stamp(cfg, "v1_2_core", purge=True)
        else:
            command.stamp(cfg, "v1_1_legacy", purge=True)
    else:
        with engine.begin() as conn:
            current = conn.execute(text("SELECT version_num FROM alembic_version LIMIT 1")).scalar()
        if current not in {"v1_1_legacy", "v1_2_core", "v1_3_enterprise", "v1_4_personal", "v1_5_workflow2", "v1_6_reliability", "v1_6_2_assetux"}:
            if looks_v16:
                command.stamp(cfg, "v1_6_reliability", purge=True)
            elif looks_v15:
                command.stamp(cfg, "v1_5_workflow2", purge=True)
            elif looks_v14:
                command.stamp(cfg, "v1_4_personal", purge=True)
            elif looks_v13:
                command.stamp(cfg, "v1_3_enterprise", purge=True)
            elif looks_v12:
                command.stamp(cfg, "v1_2_core", purge=True)
            else:
                command.stamp(cfg, "v1_1_legacy", purge=True)

    command.upgrade(cfg, "head")
    Base.metadata.create_all(bind=engine)
    return {"mode": "upgrade", "revision": "head"}
