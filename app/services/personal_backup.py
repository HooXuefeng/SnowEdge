from __future__ import annotations

import hashlib
import re
from datetime import timedelta
from pathlib import Path

from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import BackupRecord, Project, _utcnow
from .personal_settings import get_personal_settings, resolved_backup_dir
from .project_portability import export_project_zip


def _safe_name(value: str) -> str:
    value = re.sub(r"[^\w\-.]+", "_", value or "", flags=re.UNICODE).strip("._")
    return value[:80] or "project"


def create_project_backup(db: Session, project: Project, backup_type: str = "sanitized_auto") -> BackupRecord:
    directory = resolved_backup_dir(db)
    directory.mkdir(parents=True, exist_ok=True)
    payload = export_project_zip(db, project)
    stamp = _utcnow().strftime("%Y%m%d_%H%M%S_%f")
    path = directory / f"{_safe_name(project.name)}_{project.id}_{stamp}.zip"
    path.write_bytes(payload)
    row = BackupRecord(project_id=project.id, backup_type=backup_type[:60], file_path=str(path), file_sha256=hashlib.sha256(payload).hexdigest(), size_bytes=len(payload), status="done")
    db.add(row); db.commit(); db.refresh(row)
    prune_project_backups(db, project.id)
    return row


def prune_project_backups(db: Session, project_id: int) -> int:
    prefs = get_personal_settings(db)
    keep = max(1, min(int(prefs.get("backup_retention", 7) or 7), 100))
    rows = db.query(BackupRecord).filter(BackupRecord.project_id == project_id, BackupRecord.status == "done").order_by(BackupRecord.id.desc()).all()
    removed=0
    for row in rows[keep:]:
        try: Path(row.file_path).unlink(missing_ok=True)
        except Exception: pass
        db.delete(row); removed += 1
    if removed: db.commit()
    return removed


def backup_due(db: Session, project: Project) -> bool:
    prefs=get_personal_settings(db)
    if not prefs.get("backup_enabled", True): return False
    interval=max(1,min(int(prefs.get("backup_interval_hours",24) or 24),720))
    latest=db.query(BackupRecord).filter(BackupRecord.project_id==project.id, BackupRecord.status=="done").order_by(BackupRecord.id.desc()).first()
    if not latest: return True
    return latest.created_at <= _utcnow() - timedelta(hours=interval)


def run_due_backups_once() -> dict:
    db=SessionLocal(); created=[]; errors=[]
    try:
        prefs=get_personal_settings(db)
        if not prefs.get("backup_enabled",True): return {"created":[],"errors":[],"enabled":False}
        for project in db.query(Project).order_by(Project.id.asc()).all():
            if not backup_due(db,project): continue
            try: created.append(create_project_backup(db,project).id)
            except Exception as exc:
                db.rollback()
                errors.append({"project_id":project.id,"error":type(exc).__name__})
                db.add(BackupRecord(project_id=project.id, backup_type="sanitized_auto", file_path="", file_sha256="", size_bytes=0, status="error"))
                db.commit()
        return {"created":created,"errors":errors,"enabled":True}
    finally: db.close()
