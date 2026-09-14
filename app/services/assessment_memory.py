from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from sqlalchemy.orm import Session

def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


from .browser_workspace import redact_url

from ..models import (
    AssessmentMemory,
    AuthorizationCase,
    BrowserSession,
    Finding,
    FindingLifecycle,
    Project,
    ProofCapsule,
    ReplayResult,
    ResponseDiff,
    StoredRequest,
    Task,
)


def _json(data) -> str:
    return json.dumps(data, ensure_ascii=False, default=str)

def _loads(raw: str, default):
    try:
        return json.loads(raw or "")
    except Exception:
        return default


def _fingerprint(*parts) -> str:
    raw = "\x1f".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:48]


def _add(
    db: Session,
    project_id: int,
    memory_type: str,
    subject: str,
    outcome: str,
    confidence: int,
    repeat_guidance: str,
    source_type: str,
    source_id: int | None,
    summary: str,
    metadata: dict | None = None,
    fingerprint_parts: tuple | None = None,
) -> AssessmentMemory:
    fp = _fingerprint(*(fingerprint_parts or (memory_type, subject, source_type, source_id)))
    row = AssessmentMemory(
        project_id=project_id,
        fingerprint=fp,
        memory_type=memory_type[:80],
        subject=subject[:1200],
        outcome=outcome[:120],
        confidence=max(0, min(100, int(confidence or 0))),
        repeat_guidance=repeat_guidance[:80],
        source_type=source_type[:80],
        source_id=source_id,
        summary=summary[:5000],
        metadata_json=_json(metadata or {}),
        last_seen_at=_utcnow(),
    )
    db.add(row)
    return row


def refresh_assessment_memory(db: Session, project_id: int) -> dict:
    project = db.get(Project, project_id)
    if not project:
        raise ValueError("Project not found.")

    # Preserve future analyst-authored/manual memories.
    (
        db.query(AssessmentMemory)
        .filter(
            AssessmentMemory.project_id == project_id,
            AssessmentMemory.source_type != "manual",
        )
        .delete(synchronize_session=False)
    )
    db.flush()

    stored_map = {
        r.id: r
        for r in db.query(StoredRequest).filter(StoredRequest.project_id == project_id).all()
    }

    for case in db.query(AuthorizationCase).filter(AuthorizationCase.project_id == project_id).all():
        stored = stored_map.get(case.stored_request_id)
        subject = redact_url(stored.url) if stored else f"stored_request:{case.stored_request_id}"
        if "enforced" in (case.classification or "") and case.confidence >= 80:
            guidance = "avoid_repeat"
        elif (case.classification or "").startswith("potential_"):
            guidance = "confirm_or_retest"
        else:
            guidance = "review"
        _add(
            db, project_id,
            "authorization_test",
            subject,
            case.classification,
            case.confidence,
            guidance,
            "authorization_case",
            case.id,
            (
                f"{case.test_type} authorization comparison for {subject} ended as "
                f"{case.classification} ({case.confidence}%)."
            ),
            {
                "stored_request_id": case.stored_request_id,
                "test_type": case.test_type,
                "baseline_identity_id": case.baseline_identity_id,
                "comparison_identity_id": case.comparison_identity_id,
                "expected_owner_identity_id": case.expected_owner_identity_id,
                "object_label": case.object_label,
            },
            (
                "authorization_test",
                case.stored_request_id,
                case.test_type,
                case.baseline_identity_id,
                case.comparison_identity_id,
                case.expected_owner_identity_id,
            ),
        )

    for capsule in db.query(ProofCapsule).filter(ProofCapsule.project_id == project_id).all():
        finding = db.get(Finding, capsule.finding_id)
        subject = redact_url(finding.target) if finding else f"finding:{capsule.finding_id}"
        if capsule.status == "resolved":
            guidance = "avoid_repeat"
        elif capsule.status == "reproduced":
            guidance = "retest_after_fix"
        elif capsule.status == "needs_review":
            guidance = "review"
        else:
            guidance = "retest_if_changed"
        _add(
            db, project_id,
            "finding_verification",
            subject,
            capsule.status,
            100 if capsule.status in {"resolved", "reproduced"} else 70,
            guidance,
            "proof_capsule",
            capsule.id,
            (
                f"Finding #{capsule.finding_id} verification via {capsule.verifier_type} "
                f"is {capsule.status}; retests={capsule.retest_count}."
            ),
            {
                "finding_id": capsule.finding_id,
                "verifier_type": capsule.verifier_type,
                "retest_count": capsule.retest_count,
            },
            ("finding_verification", capsule.finding_id, capsule.verifier_type),
        )

    for session in db.query(BrowserSession).filter(BrowserSession.project_id == project_id).all():
        try:
            summary = json.loads(session.summary_json or "{}")
        except Exception:
            summary = {}
        guidance = "avoid_repeat_recent" if session.status == "done" else "review"
        _add(
            db, project_id,
            "browser_observation",
            redact_url(session.target_url),
            session.status,
            90 if session.status == "done" else 50,
            guidance,
            "browser_session",
            session.id,
            (
                f"Browser observation for {redact_url(session.target_url)}: {session.status}; "
                f"requests={summary.get('requests', 0)}, xhr/fetch={summary.get('xhr_fetch', 0)}, "
                f"blocked={summary.get('blocked_out_of_scope', 0)}."
            ),
            {
                "identity_id": session.identity_id,
                "final_url": session.final_url,
                "requests": summary.get("requests", 0),
                "xhr_fetch": summary.get("xhr_fetch", 0),
                "forms": summary.get("forms", 0),
                "scripts": summary.get("scripts", 0),
                "blocked_out_of_scope": summary.get("blocked_out_of_scope", 0),
            },
            ("browser_observation", redact_url(session.target_url), session.identity_id),
        )

    for diff in db.query(ResponseDiff).filter(ResponseDiff.project_id == project_id).all():
        left = db.get(ReplayResult, diff.left_replay_id)
        right = db.get(ReplayResult, diff.right_replay_id)
        stored_id = left.stored_request_id if left else (right.stored_request_id if right else None)
        stored = stored_map.get(stored_id)
        subject = redact_url(stored.url) if stored else f"response_diff:{diff.id}"
        try:
            summary = json.loads(diff.summary_json or "{}")
        except Exception:
            summary = {}
        similarity = summary.get("text_similarity")
        _add(
            db, project_id,
            "response_diff",
            subject,
            "compared",
            90,
            "avoid_repeat_recent",
            "response_diff",
            diff.id,
            f"Response comparison recorded for {subject}; text_similarity={similarity}.",
            {
                "left_replay_id": diff.left_replay_id,
                "right_replay_id": diff.right_replay_id,
                "text_similarity": similarity,
                "status_equal": summary.get("status_equal"),
            },
            ("response_diff", stored_id, left.identity_id if left else None, right.identity_id if right else None),
        )

    for finding in db.query(Finding).filter(Finding.project_id == project_id).all():
        _add(
            db, project_id,
            "finding",
            redact_url(finding.target),
            "active",
            85,
            "review_or_retest",
            "finding",
            finding.id,
            f"[{finding.severity.upper()}] {finding.title} on {redact_url(finding.target)}.",
            {
                "severity": finding.severity,
                "source": finding.source,
                "title": finding.title,
            },
            ("finding", finding.source, redact_url(finding.target), finding.title),
        )

    for lifecycle in db.query(FindingLifecycle).filter(FindingLifecycle.project_id == project_id).all():
        finding = db.get(Finding, lifecycle.finding_id)
        subject = redact_url(finding.target) if finding else f"finding:{lifecycle.finding_id}"
        if lifecycle.status == "resolved":
            guidance = "avoid_repeat"
        elif lifecycle.status == "remediation":
            guidance = "retest_after_fix"
        elif lifecycle.status == "retest_ready":
            guidance = "review_or_retest"
        elif lifecycle.status in {"accepted_risk", "false_positive"}:
            guidance = "avoid_repeat"
        else:
            guidance = "review"
        _add(
            db, project_id,
            "remediation_state",
            subject,
            lifecycle.status,
            95,
            guidance,
            "finding_lifecycle",
            lifecycle.id,
            (
                f"Finding #{lifecycle.finding_id} remediation state is {lifecycle.status}; "
                f"retest_status={lifecycle.retest_status}; priority={lifecycle.priority}."
            ),
            {
                "finding_id": lifecycle.finding_id,
                "priority": lifecycle.priority,
                "retest_status": lifecycle.retest_status,
                "proof_capsule_id": lifecycle.proof_capsule_id,
                "last_retest_run_id": lifecycle.last_retest_run_id,
                "owner_present": bool(lifecycle.owner),
                "remediation_note_in_memory": False,
            },
            ("remediation_state", lifecycle.finding_id),
        )

    repeatable_actions = {
        "port_scan",
        "http_probe",
        "headers_check",
        "tls_check",
        "web_discovery",
        "browser_observe",
    }
    for task in (
        db.query(Task)
        .filter(Task.project_id == project_id, Task.action.in_(repeatable_actions))
        .order_by(Task.id.asc())
        .all()
    ):
        guidance = "avoid_repeat_recent" if task.status == "done" else "review"
        _add(
            db, project_id,
            "coverage_action",
            redact_url(task.target),
            task.status,
            90 if task.status == "done" else 50,
            guidance,
            "task",
            task.id,
            f"{task.action} against {redact_url(task.target)}: {task.status}.",
            {"action": task.action, "policy_class": task.policy_class},
            ("coverage_action", task.action, redact_url(task.target)),
        )

    db.commit()
    return memory_summary(db, project_id)


def memory_summary(db: Session, project_id: int) -> dict:
    rows = db.query(AssessmentMemory).filter(AssessmentMemory.project_id == project_id).all()
    guidance = {}
    types = {}
    for row in rows:
        guidance[row.repeat_guidance] = guidance.get(row.repeat_guidance, 0) + 1
        types[row.memory_type] = types.get(row.memory_type, 0) + 1
    return {
        "count": len(rows),
        "by_type": dict(sorted(types.items())),
        "by_guidance": dict(sorted(guidance.items())),
        "avoid_repeat": sum(1 for r in rows if r.repeat_guidance.startswith("avoid_repeat")),
        "needs_review": sum(1 for r in rows if r.repeat_guidance in {"review", "review_or_retest", "confirm_or_retest"}),
    }


def memory_hints(db: Session, project_id: int, limit: int = 80) -> list[dict]:
    rows = (
        db.query(AssessmentMemory)
        .filter(AssessmentMemory.project_id == project_id)
        .order_by(AssessmentMemory.id.desc())
        .limit(max(1, min(limit, 300)))
        .all()
    )
    return [
        {
            "id": row.id,
            "type": row.memory_type,
            "subject": row.subject,
            "outcome": row.outcome,
            "confidence": row.confidence,
            "repeat_guidance": row.repeat_guidance,
            "summary": row.summary,
            "metadata": _loads(row.metadata_json, {}),
        }
        for row in rows
    ]


def find_repeat_candidates(
    db: Session,
    project_id: int,
    subject: str,
    memory_type: str | None = None,
    limit: int = 20,
) -> list[AssessmentMemory]:
    query = db.query(AssessmentMemory).filter(
        AssessmentMemory.project_id == project_id,
        AssessmentMemory.subject == subject,
    )
    if memory_type:
        query = query.filter(AssessmentMemory.memory_type == memory_type)
    return query.order_by(AssessmentMemory.id.desc()).limit(max(1, min(limit, 100))).all()
