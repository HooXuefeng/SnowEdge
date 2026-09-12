from __future__ import annotations

from datetime import UTC, datetime
from sqlalchemy.orm import Session

def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


from ..models import (
    Finding,
    FindingLifecycle,
    Project,
    ProofCapsule,
    RemediationEvent,
    RetestRun,
)
from .proof_capsule import get_or_create_capsule, run_retest


VALID_STATUSES = {
    "open",
    "triaged",
    "remediation",
    "retest_ready",
    "resolved",
    "accepted_risk",
    "false_positive",
}

VALID_PRIORITIES = {"low", "normal", "high", "urgent"}


def ensure_lifecycle(db: Session, finding: Finding) -> FindingLifecycle:
    row = (
        db.query(FindingLifecycle)
        .filter(FindingLifecycle.finding_id == finding.id)
        .first()
    )
    if row:
        return row
    priority = "high" if finding.severity == "high" else "normal"
    row = FindingLifecycle(
        project_id=finding.project_id,
        finding_id=finding.id,
        status="open",
        priority=priority,
        retest_status="not_queued",
    )
    db.add(row)
    db.flush()
    db.add(RemediationEvent(
        project_id=finding.project_id,
        finding_id=finding.id,
        lifecycle_id=row.id,
        event_type="created",
        from_status="",
        to_status="open",
        detail="Finding entered remediation workflow.",
        source="system",
    ))
    db.commit()
    db.refresh(row)
    return row


def ensure_project_lifecycles(db: Session, project_id: int) -> list[FindingLifecycle]:
    findings = db.query(Finding).filter(Finding.project_id == project_id).order_by(Finding.id.asc()).all()
    rows = [ensure_lifecycle(db, finding) for finding in findings]
    return rows


def update_lifecycle(
    db: Session,
    lifecycle: FindingLifecycle,
    *,
    status: str | None = None,
    owner: str | None = None,
    priority: str | None = None,
    remediation_note: str | None = None,
    source: str = "analyst",
) -> FindingLifecycle:
    old_status = lifecycle.status
    changed = []

    if status is not None:
        if status not in VALID_STATUSES:
            raise ValueError("Invalid lifecycle status.")
        lifecycle.status = status
        if status != old_status:
            changed.append(f"status {old_status} → {status}")
    if owner is not None:
        lifecycle.owner = owner.strip()[:180]
        changed.append("owner updated")
    if priority is not None:
        if priority not in VALID_PRIORITIES:
            raise ValueError("Invalid priority.")
        lifecycle.priority = priority
        changed.append(f"priority → {priority}")
    if remediation_note is not None:
        lifecycle.remediation_note = remediation_note.strip()[:8000]
        changed.append("remediation note updated")

    lifecycle.updated_at = _utcnow()
    if changed:
        db.add(RemediationEvent(
            project_id=lifecycle.project_id,
            finding_id=lifecycle.finding_id,
            lifecycle_id=lifecycle.id,
            event_type="workflow_update",
            from_status=old_status,
            to_status=lifecycle.status,
            detail="; ".join(changed),
            source=source,
        ))
    db.commit()
    db.refresh(lifecycle)
    return lifecycle


async def retest_lifecycle(
    db: Session,
    project: Project,
    lifecycle: FindingLifecycle,
) -> RetestRun:
    finding = db.get(Finding, lifecycle.finding_id)
    if not finding or finding.project_id != project.id:
        raise ValueError("Finding is unavailable.")

    capsule = get_or_create_capsule(db, finding)
    previous_status = lifecycle.status
    lifecycle.proof_capsule_id = capsule.id
    lifecycle.retest_status = "running"
    lifecycle.status = "retest_ready"
    lifecycle.updated_at = _utcnow()
    db.add(RemediationEvent(
        project_id=project.id,
        finding_id=finding.id,
        lifecycle_id=lifecycle.id,
        event_type="retest_started",
        from_status=previous_status,
        to_status="retest_ready",
        detail=f"Retest started with verifier '{capsule.verifier_type}'.",
        source="proof_capsule",
    ))
    db.commit()

    run = await run_retest(db, project, finding, capsule)
    lifecycle.last_retest_run_id = run.id
    lifecycle.retest_status = run.status
    finding.verification_state = run.status if run.status in {"resolved", "reproduced", "needs_review", "error"} else finding.verification_state
    if run.status in {"resolved", "reproduced"} and finding.finding_state == "candidate":
        finding.finding_state = "confirmed"
    old_status = lifecycle.status

    if run.status == "resolved":
        lifecycle.status = "resolved"
    elif run.status == "reproduced":
        lifecycle.status = "remediation"
    elif run.status == "needs_review":
        lifecycle.status = "retest_ready"
    elif run.status == "error":
        lifecycle.status = "retest_ready"

    lifecycle.updated_at = _utcnow()
    db.add(RemediationEvent(
        project_id=project.id,
        finding_id=finding.id,
        lifecycle_id=lifecycle.id,
        event_type="retest_completed",
        from_status=old_status,
        to_status=lifecycle.status,
        detail=f"Proof Capsule retest #{run.id}: {run.status}. {run.detail}",
        source="proof_capsule",
    ))
    db.commit()
    db.refresh(lifecycle)
    return run


def remediation_summary(db: Session, project_id: int) -> dict:
    rows = ensure_project_lifecycles(db, project_id)
    by_status = {}
    by_priority = {}
    for row in rows:
        by_status[row.status] = by_status.get(row.status, 0) + 1
        by_priority[row.priority] = by_priority.get(row.priority, 0) + 1
    return {
        "count": len(rows),
        "open": sum(1 for r in rows if r.status not in {"resolved", "accepted_risk", "false_positive"}),
        "resolved": by_status.get("resolved", 0),
        "retest_ready": by_status.get("retest_ready", 0),
        "remediation": by_status.get("remediation", 0),
        "by_status": dict(sorted(by_status.items())),
        "by_priority": dict(sorted(by_priority.items())),
    }
