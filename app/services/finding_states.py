from __future__ import annotations

from sqlalchemy.orm import Session

from ..models import Finding, FindingLifecycle, RemediationEvent
from .remediation import ensure_lifecycle

FINDING_STATES = {"candidate", "confirmed", "false_positive"}
VERIFICATION_STATES = {"unverified", "reproduced", "resolved", "needs_review", "error"}
REMEDIATION_STATES = {
    "open", "triaged", "remediation", "retest_ready",
    "resolved", "accepted_risk", "false_positive",
}


def update_finding_states(
    db: Session,
    finding: Finding,
    *,
    finding_state: str | None = None,
    remediation_state: str | None = None,
    verification_state: str | None = None,
    source: str = "analyst",
) -> tuple[Finding, FindingLifecycle]:
    lifecycle = ensure_lifecycle(db, finding)
    changes = []

    if finding_state is not None:
        if finding_state not in FINDING_STATES:
            raise ValueError("Invalid finding state.")
        if finding.finding_state != finding_state:
            changes.append(f"finding_state {finding.finding_state} → {finding_state}")
            finding.finding_state = finding_state

    if verification_state is not None:
        if verification_state not in VERIFICATION_STATES:
            raise ValueError("Invalid verification state.")
        if finding.verification_state != verification_state:
            if finding.verification_state == "resolved" and verification_state == "reproduced":
                finding.reopened_count += 1
                changes.append("finding reopened")
            changes.append(f"verification {finding.verification_state} → {verification_state}")
            finding.verification_state = verification_state

    old_lifecycle = lifecycle.status
    if remediation_state is not None:
        if remediation_state not in REMEDIATION_STATES:
            raise ValueError("Invalid remediation state.")
        lifecycle.status = remediation_state
        if old_lifecycle != remediation_state:
            changes.append(f"remediation {old_lifecycle} → {remediation_state}")

    if finding.finding_state == "false_positive":
        lifecycle.status = "false_positive"
    if finding.verification_state == "resolved" and lifecycle.status not in {"accepted_risk", "false_positive"}:
        lifecycle.status = "resolved"
    if finding.verification_state == "reproduced" and lifecycle.status == "resolved":
        lifecycle.status = "remediation"

    if changes:
        db.add(RemediationEvent(
            project_id=finding.project_id,
            finding_id=finding.id,
            lifecycle_id=lifecycle.id,
            event_type="finding_state_update",
            from_status=old_lifecycle,
            to_status=lifecycle.status,
            detail="; ".join(changes),
            source=source,
        ))
    db.commit()
    db.refresh(finding)
    db.refresh(lifecycle)
    return finding, lifecycle
