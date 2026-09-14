from __future__ import annotations

import json
from sqlalchemy.orm import Session

from ..models import (
    Evidence,
    _evidence_hash_material,
    EvidenceProvenance,
    Finding,
    PersistentJob,
    Project,
    Task,
)


def _project_id_for_evidence(db: Session, evidence: Evidence) -> int | None:
    if evidence.project_id:
        return evidence.project_id
    if evidence.finding_id:
        finding = db.get(Finding, evidence.finding_id)
        if finding:
            return finding.project_id
    if evidence.task_id:
        task = db.get(Task, evidence.task_id)
        if task:
            return task.project_id
    if evidence.job_id:
        job = db.get(PersistentJob, evidence.job_id)
        if job:
            return job.project_id
    return None


def _ensure_link(
    db: Session,
    project_id: int,
    evidence_id: int,
    relation: str,
    entity_type: str,
    entity_id: int | None,
    entity_ref: str = "",
    metadata: dict | None = None,
) -> EvidenceProvenance:
    row = (
        db.query(EvidenceProvenance)
        .filter(
            EvidenceProvenance.evidence_id == evidence_id,
            EvidenceProvenance.relation == relation,
            EvidenceProvenance.entity_type == entity_type,
            EvidenceProvenance.entity_id == entity_id,
        )
        .first()
    )
    if row:
        return row
    row = EvidenceProvenance(
        project_id=project_id,
        evidence_id=evidence_id,
        relation=relation[:80],
        entity_type=entity_type[:80],
        entity_id=entity_id,
        entity_ref=entity_ref[:500],
        metadata_json=json.dumps(metadata or {}, ensure_ascii=False),
    )
    db.add(row)
    return row


def ensure_evidence_integrity(db: Session, evidence: Evidence) -> Evidence:
    project_id = _project_id_for_evidence(db, evidence)
    changed = False
    if project_id and evidence.project_id != project_id:
        evidence.project_id = project_id
        changed = True

    if not evidence.content_sha256 or not evidence.integrity_sha256:
        evidence.content_sha256, evidence.integrity_sha256 = _evidence_hash_material(evidence)
        changed = True

    if changed:
        db.add(evidence)
        db.flush()

    if project_id:
        if evidence.finding_id:
            _ensure_link(db, project_id, evidence.id, "SUPPORTS", "Finding", evidence.finding_id)
        if evidence.task_id:
            _ensure_link(db, project_id, evidence.id, "CAPTURED_BY", "Task", evidence.task_id)
        if evidence.job_id:
            _ensure_link(db, project_id, evidence.id, "CAPTURED_BY", "PersistentJob", evidence.job_id)
        if evidence.parent_evidence_id:
            _ensure_link(db, project_id, evidence.id, "DERIVED_FROM", "Evidence", evidence.parent_evidence_id)
        if evidence.source_type:
            _ensure_link(
                db,
                project_id,
                evidence.id,
                "OBSERVED_FROM",
                evidence.source_type,
                evidence.source_id,
            )
    db.commit()
    db.refresh(evidence)
    return evidence


def backfill_project_evidence(db: Session, project_id: int) -> dict:
    finding_ids = [x[0] for x in db.query(Finding.id).filter(Finding.project_id == project_id).all()]
    task_ids = [x[0] for x in db.query(Task.id).filter(Task.project_id == project_id).all()]
    job_ids = [x[0] for x in db.query(PersistentJob.id).filter(PersistentJob.project_id == project_id).all()]

    evidence = (
        db.query(Evidence)
        .filter(
            (Evidence.project_id == project_id)
            | (Evidence.finding_id.in_(finding_ids or [-1]))
            | (Evidence.task_id.in_(task_ids or [-1]))
            | (Evidence.job_id.in_(job_ids or [-1]))
        )
        .order_by(Evidence.id.asc())
        .all()
    )
    hashed = 0
    for row in evidence:
        before = (row.content_sha256, row.integrity_sha256, row.project_id)
        ensure_evidence_integrity(db, row)
        after = (row.content_sha256, row.integrity_sha256, row.project_id)
        if before != after:
            hashed += 1
    return {
        "count": len(evidence),
        "hashed_or_backfilled": hashed,
        "provenance_links": db.query(EvidenceProvenance).filter(EvidenceProvenance.project_id == project_id).count(),
    }


def evidence_chain_payload(db: Session, evidence: Evidence) -> dict:
    ensure_evidence_integrity(db, evidence)
    links = (
        db.query(EvidenceProvenance)
        .filter(EvidenceProvenance.evidence_id == evidence.id)
        .order_by(EvidenceProvenance.id.asc())
        .all()
    )
    return {
        "id": evidence.id,
        "kind": evidence.kind,
        "content_sha256": evidence.content_sha256,
        "integrity_sha256": evidence.integrity_sha256,
        "redaction_state": evidence.redaction_state,
        "captured_at": evidence.captured_at,
        "links": [
            {
                "relation": x.relation,
                "entity_type": x.entity_type,
                "entity_id": x.entity_id,
                "entity_ref": x.entity_ref,
            }
            for x in links
        ],
    }


def project_evidence_summary(db: Session, project_id: int) -> dict:
    backfill_project_evidence(db, project_id)
    rows = db.query(Evidence).filter(Evidence.project_id == project_id).all()
    return {
        "count": len(rows),
        "hashed": sum(1 for x in rows if len(x.content_sha256 or "") == 64),
        "integrity_ready": sum(1 for x in rows if len(x.integrity_sha256 or "") == 64),
        "redacted": sum(1 for x in rows if x.redaction_state == "redacted"),
        "links": db.query(EvidenceProvenance).filter(EvidenceProvenance.project_id == project_id).count(),
    }
