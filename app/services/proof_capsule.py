from __future__ import annotations

import json
from datetime import UTC, datetime
from sqlalchemy.orm import Session

def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


from ..config import settings
from ..models import (
    AuthorizationCase, Evidence, Finding, Identity, Project, ProofCapsule, RetestRun
)
from ..scanners.http_probe import probe_http
from ..scope import target_in_scope
from .authorization_testing import run_authorization_case


def _loads(raw: str, default):
    try:
        return json.loads(raw or "")
    except Exception:
        return default


def _evidence_ids(db: Session, finding_id: int) -> list[int]:
    return [
        row.id
        for row in db.query(Evidence)
        .filter(Evidence.finding_id == finding_id)
        .order_by(Evidence.id.asc())
        .all()
    ]


def _initial_observation(db: Session, finding: Finding) -> dict:
    evidence = (
        db.query(Evidence)
        .filter(Evidence.finding_id == finding.id)
        .order_by(Evidence.id.asc())
        .all()
    )
    return {
        "finding_source": finding.source,
        "evidence_kinds": [e.kind for e in evidence],
        "evidence_count": len(evidence),
        "captured_from_existing_evidence": True,
    }


def capsule_spec(db: Session, finding: Finding) -> dict:
    title = (finding.title or "").strip()
    source = (finding.source or "").strip()

    if source == "headers_check" and title.lower().startswith("missing security header:"):
        header = title.split(":", 1)[1].strip().lower()
        return {
            "verifier_type": "http_header_absence",
            "status": "ready",
            "expected": {"header": header, "condition": "absent", "reproduced_when": "header remains absent"},
        }

    if source == "headers_check" and title.lower() == "server header disclosed":
        return {
            "verifier_type": "http_header_presence",
            "status": "ready",
            "expected": {"header": "server", "condition": "present", "reproduced_when": "header remains present"},
        }

    if source == "authorization_testing":
        case = (
            db.query(AuthorizationCase)
            .filter(AuthorizationCase.finding_id == finding.id)
            .order_by(AuthorizationCase.id.desc())
            .first()
        )
        if case:
            return {
                "verifier_type": "authorization_case_replay",
                "status": "ready",
                "expected": {
                    "authorization_case_id": case.id,
                    "original_classification": case.classification,
                    "safe_methods": ["GET", "HEAD"],
                    "reproduced_when": "classification remains a potential authorization gap",
                },
            }

    return {
        "verifier_type": "evidence_snapshot",
        "status": "needs_review",
        "expected": {
            "condition": "manual_verification_required",
            "reason": "No deterministic read-only verifier is registered for this finding source.",
        },
    }


def get_or_create_capsule(db: Session, finding: Finding) -> ProofCapsule:
    existing = (
        db.query(ProofCapsule)
        .filter(ProofCapsule.finding_id == finding.id)
        .order_by(ProofCapsule.id.desc())
        .first()
    )
    if existing:
        return existing

    spec = capsule_spec(db, finding)
    row = ProofCapsule(
        project_id=finding.project_id,
        finding_id=finding.id,
        verifier_type=spec["verifier_type"],
        status=spec["status"],
        expected_json=json.dumps(spec["expected"], ensure_ascii=False),
        observed_json=json.dumps(_initial_observation(db, finding), ensure_ascii=False),
        source_evidence_ids_json=json.dumps(_evidence_ids(db, finding.id), ensure_ascii=False),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def capsule_payload(capsule: ProofCapsule) -> dict:
    return {
        "id": capsule.id,
        "finding_id": capsule.finding_id,
        "verifier_type": capsule.verifier_type,
        "status": capsule.status,
        "expected": _loads(capsule.expected_json, {}),
        "observed": _loads(capsule.observed_json, {}),
        "source_evidence_ids": _loads(capsule.source_evidence_ids_json, []),
        "retest_count": capsule.retest_count,
        "last_retest_at": capsule.last_retest_at,
    }


def _record_retest_evidence(db: Session, finding: Finding, payload: dict) -> Evidence:
    evidence = Evidence(
        finding_id=finding.id,
        kind="proof_capsule_retest",
        content=json.dumps(payload, ensure_ascii=False, indent=2, default=str),
    )
    db.add(evidence)
    db.flush()
    return evidence


async def run_retest(
    db: Session,
    project: Project,
    finding: Finding,
    capsule: ProofCapsule,
) -> RetestRun:
    expected = _loads(capsule.expected_json, {})
    run = RetestRun(
        project_id=project.id,
        finding_id=finding.id,
        proof_capsule_id=capsule.id,
        verifier_type=capsule.verifier_type,
        status="running",
        expected_json=json.dumps(expected, ensure_ascii=False),
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    rules = [x.strip() for x in project.scope_text.splitlines() if x.strip()]
    observed: dict = {}
    detail = ""

    try:
        if capsule.verifier_type in {"http_header_absence", "http_header_presence"}:
            if not target_in_scope(finding.target, rules):
                raise ValueError("Finding target is outside the project's current authorized scope.")

            result = await probe_http(
                finding.target,
                settings.request_timeout_seconds,
                settings.max_response_body_bytes,
                rules,
            )
            if not result.get("ok"):
                raise ValueError(result.get("error") or "HTTP verification failed.")

            headers = {str(k).lower(): str(v) for k, v in (result.get("headers") or {}).items()}
            header = str(expected.get("header", "")).lower()
            present = header in headers
            condition = expected.get("condition")
            reproduced = (condition == "absent" and not present) or (condition == "present" and present)
            observed = {
                "target": finding.target,
                "status_code": result.get("status_code"),
                "final_url": result.get("final_url", finding.target),
                "header": header,
                "present": present,
                "value": headers.get(header),
                "reproduced": reproduced,
            }
            run.status = "reproduced" if reproduced else "resolved"
            detail = (
                f"Verifier condition still holds for '{header}'."
                if reproduced
                else f"Verifier condition no longer holds for '{header}'."
            )

        elif capsule.verifier_type == "authorization_case_replay":
            case_id = int(expected.get("authorization_case_id") or 0)
            case = db.get(AuthorizationCase, case_id)
            if not case or case.project_id != project.id or case.finding_id != finding.id:
                raise ValueError("Linked Authorization Case is unavailable.")

            baseline_identity = db.get(Identity, case.baseline_identity_id) if case.baseline_identity_id else None
            comparison_identity = db.get(Identity, case.comparison_identity_id) if case.comparison_identity_id else None

            await run_authorization_case(
                db,
                rules,
                case,
                baseline_identity,
                comparison_identity,
                auto_candidate_finding=False,
            )
            classification = case.classification
            if classification.startswith("potential_"):
                status = "reproduced"
            elif "enforced" in classification:
                status = "resolved"
            else:
                status = "needs_review"
            run.status = status
            observed = {
                "authorization_case_id": case.id,
                "classification": classification,
                "confidence": case.confidence,
                "summary": _loads(case.summary_json, {}),
                "reproduced": status == "reproduced",
            }
            detail = f"Authorization Case #{case.id} retested as '{classification}'."

        else:
            run.status = "needs_review"
            observed = {
                "manual_verification_required": True,
                "reason": "This capsule is an evidence snapshot and has no registered deterministic network verifier.",
            }
            detail = "No automatic verifier is registered for this finding type."

        evidence = _record_retest_evidence(
            db,
            finding,
            {
                "proof_capsule_id": capsule.id,
                "verifier_type": capsule.verifier_type,
                "status": run.status,
                "expected": expected,
                "observed": observed,
                "detail": detail,
            },
        )
        run.evidence_id = evidence.id
        run.observed_json = json.dumps(observed, ensure_ascii=False, default=str)
        run.detail = detail

        capsule.status = run.status
        capsule.observed_json = json.dumps(observed, ensure_ascii=False, default=str)
        capsule.retest_count = int(capsule.retest_count or 0) + 1
        capsule.last_retest_at = _utcnow()

        db.commit()
        db.refresh(run)
        db.refresh(capsule)
        return run

    except Exception as exc:
        run.status = "error"
        run.detail = f"{type(exc).__name__}: {exc}"
        run.observed_json = json.dumps({"error": run.detail}, ensure_ascii=False)
        capsule.status = "error"
        capsule.observed_json = run.observed_json
        capsule.retest_count = int(capsule.retest_count or 0) + 1
        capsule.last_retest_at = _utcnow()
        db.commit()
        db.refresh(run)
        return run
