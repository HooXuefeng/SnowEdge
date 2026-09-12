from __future__ import annotations

import json
from sqlalchemy.orm import Session

from ..models import AuthorizationCase, AuthorizationMatrixRun, Identity, Project, StoredRequest
from ..policy import PolicyClass
from ..scope import target_in_scope
from .authorization_testing import run_authorization_case
from .evidence_safety import redact_object, redact_url

MAX_MATRIX_IDENTITIES = 6


def _scope_rules(project: Project) -> list[str]:
    return [x.strip() for x in project.scope_text.splitlines() if x.strip()]


def create_matrix_run(
    db: Session,
    project: Project,
    stored_request_id: int,
    baseline_identity_id: int,
    selected_identity_ids: list[int],
    include_anonymous: bool,
) -> AuthorizationMatrixRun:
    stored = db.get(StoredRequest, stored_request_id)
    if not stored or stored.project_id != project.id:
        raise ValueError("Stored request does not belong to this project.")
    if stored.method.upper() not in {"GET", "HEAD"} or stored.policy_class != PolicyClass.READ_ONLY.value:
        raise ValueError("Authorization Matrix only supports READ_ONLY GET/HEAD requests.")
    if not target_in_scope(stored.url, _scope_rules(project)):
        raise ValueError("Stored request target is outside the project's current authorized scope.")

    baseline = db.get(Identity, baseline_identity_id)
    if not baseline or baseline.project_id != project.id:
        raise ValueError("Baseline identity does not belong to this project.")

    unique_ids = []
    for identity_id in selected_identity_ids:
        if identity_id == baseline_identity_id or identity_id in unique_ids:
            continue
        identity = db.get(Identity, identity_id)
        if not identity or identity.project_id != project.id:
            raise ValueError("One or more comparison identities do not belong to this project.")
        unique_ids.append(identity_id)

    if len(unique_ids) > MAX_MATRIX_IDENTITIES:
        raise ValueError(f"Authorization Matrix is limited to {MAX_MATRIX_IDENTITIES} comparison identities per run.")
    if not unique_ids and not include_anonymous:
        raise ValueError("Select at least one comparison identity or Anonymous.")

    row = AuthorizationMatrixRun(
        project_id=project.id,
        stored_request_id=stored.id,
        baseline_identity_id=baseline.id,
        selected_identity_ids_json=json.dumps(unique_ids),
        include_anonymous=1 if include_anonymous else 0,
        status="queued",
        case_ids_json="[]",
        summary_json="{}",
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


async def execute_matrix_run(
    db: Session,
    project: Project,
    matrix: AuthorizationMatrixRun,
) -> AuthorizationMatrixRun:
    if matrix.project_id != project.id:
        raise ValueError("Authorization Matrix run does not belong to this project.")

    stored = db.get(StoredRequest, matrix.stored_request_id)
    baseline = db.get(Identity, matrix.baseline_identity_id) if matrix.baseline_identity_id else None
    if not stored or not baseline:
        raise ValueError("Stored request or baseline identity is unavailable.")
    if stored.method.upper() not in {"GET", "HEAD"} or stored.policy_class != PolicyClass.READ_ONLY.value:
        raise ValueError("Authorization Matrix execution is limited to READ_ONLY GET/HEAD requests.")
    if not target_in_scope(stored.url, _scope_rules(project)):
        raise ValueError("Authorization Matrix target is outside current project scope.")

    try:
        identity_ids = json.loads(matrix.selected_identity_ids_json or "[]")
    except Exception:
        identity_ids = []
    if len(identity_ids) > MAX_MATRIX_IDENTITIES:
        raise ValueError("Matrix identity limit exceeded.")

    comparisons: list[tuple[str, Identity | None]] = []
    for identity_id in identity_ids:
        identity = db.get(Identity, int(identity_id))
        if not identity or identity.project_id != project.id:
            raise ValueError("Comparison identity is unavailable.")
        comparisons.append(("horizontal", identity))
    if matrix.include_anonymous:
        comparisons.append(("unauthenticated", None))

    matrix.status = "running"
    db.commit()

    case_ids = []
    results = []
    try:
        for test_type, comparison in comparisons:
            case = AuthorizationCase(
                project_id=project.id,
                stored_request_id=stored.id,
                test_type=test_type,
                baseline_identity_id=baseline.id,
                comparison_identity_id=comparison.id if comparison else None,
                expected_owner_identity_id=baseline.id,
                status="queued",
                classification="pending",
                object_label=stored.name[:300],
            )
            db.add(case)
            db.commit()
            db.refresh(case)

            await run_authorization_case(
                db,
                _scope_rules(project),
                case,
                baseline,
                comparison,
            )
            case_ids.append(case.id)
            results.append({
                "case_id": case.id,
                "comparison_identity_id": comparison.id if comparison else None,
                "comparison_name": comparison.name if comparison else "Anonymous",
                "test_type": case.test_type,
                "classification": case.classification,
                "confidence": case.confidence,
                "finding_id": case.finding_id,
            })

        matrix.status = "done"
        matrix.case_ids_json = json.dumps(case_ids)
        matrix.summary_json = json.dumps({
            "stored_request_id": stored.id,
            "method": stored.method,
            "url": redact_url(stored.url),
            "baseline_identity_id": baseline.id,
            "baseline_name": baseline.name,
            "comparisons": results,
            "candidate_count": sum(1 for x in results if str(x["classification"]).startswith("potential_")),
            "enforced_count": sum(1 for x in results if "enforced" in str(x["classification"])),
            "review_count": sum(1 for x in results if "review" in str(x["classification"])),
        }, ensure_ascii=False)
        db.commit()
        db.refresh(matrix)
        return matrix
    except Exception as exc:
        matrix.status = "error"
        matrix.case_ids_json = json.dumps(case_ids)
        matrix.summary_json = json.dumps({
            "error": f"{type(exc).__name__}: {exc}",
            "partial_case_ids": case_ids,
            "comparisons": results,
        }, ensure_ascii=False)
        db.commit()
        raise


def matrix_view(db: Session, project_id: int) -> dict:
    identities = db.query(Identity).filter(Identity.project_id == project_id).order_by(Identity.id.asc()).all()
    requests = (
        db.query(StoredRequest)
        .filter(
            StoredRequest.project_id == project_id,
            StoredRequest.method.in_(["GET", "HEAD"]),
            StoredRequest.policy_class == PolicyClass.READ_ONLY.value,
        )
        .order_by(StoredRequest.id.desc())
        .all()
    )
    cases = (
        db.query(AuthorizationCase)
        .filter(AuthorizationCase.project_id == project_id, AuthorizationCase.status == "done")
        .order_by(AuthorizationCase.id.desc())
        .all()
    )

    latest: dict[tuple[int, int | None, int | None], AuthorizationCase] = {}
    for case in cases:
        key = (case.stored_request_id, case.baseline_identity_id, case.comparison_identity_id)
        if key not in latest:
            latest[key] = case

    rows = []
    for stored in requests:
        cells = {}
        for identity in identities:
            matching = [
                case for (request_id, baseline_id, comparison_id), case in latest.items()
                if request_id == stored.id and comparison_id == identity.id
            ]
            cells[str(identity.id)] = matching[0] if matching else None
        anonymous = [
            case for (request_id, baseline_id, comparison_id), case in latest.items()
            if request_id == stored.id and comparison_id is None and case.test_type == "unauthenticated"
        ]
        rows.append({
            "request": stored,
            "cells": cells,
            "anonymous": anonymous[0] if anonymous else None,
        })
    return {
        "identities": identities,
        "requests": requests,
        "rows": rows,
    }


def matrix_run_payload(matrix: AuthorizationMatrixRun) -> dict:
    try:
        summary = json.loads(matrix.summary_json or "{}")
    except Exception:
        summary = {}
    summary, _ = redact_object(summary)
    try:
        case_ids = json.loads(matrix.case_ids_json or "[]")
    except Exception:
        case_ids = []
    return {
        "id": matrix.id,
        "status": matrix.status,
        "stored_request_id": matrix.stored_request_id,
        "baseline_identity_id": matrix.baseline_identity_id,
        "case_ids": case_ids,
        "summary": summary,
        "created_at": matrix.created_at,
    }


def compare_matrix_runs(left: AuthorizationMatrixRun | None, right: AuthorizationMatrixRun | None) -> dict | None:
    if not left or not right or left.project_id != right.project_id:
        return None
    left_payload = matrix_run_payload(left); right_payload = matrix_run_payload(right); left_summary=left_payload["summary"]; right_summary=right_payload["summary"]
    if left_summary.get("stored_request_id") != right_summary.get("stored_request_id"):
        return {"compatible":False,"reason":"只能比较同一个 Stored Request 的矩阵结果。","left_id":left.id,"right_id":right.id,"rows":[]}
    def cells(summary):
        out={}
        for item in summary.get("comparisons",[]) or []: out[str(item.get("comparison_identity_id") or "anonymous")]=item
        return out
    lmap,rmap=cells(left_summary),cells(right_summary); keys=sorted(set(lmap)|set(rmap));rows=[];improved=regressed=changed=0
    for key in keys:
        before=lmap.get(key) or {}; after=rmap.get(key) or {};bc=str(before.get("classification") or "未执行");ac=str(after.get("classification") or "未执行");delta="same"
        if bc != ac:
            changed+=1;before_risk=bc.startswith("potential_") or "review" in bc;after_risk=ac.startswith("potential_") or "review" in ac
            if before_risk and "enforced" in ac:delta="improved";improved+=1
            elif "enforced" in bc and after_risk:delta="regressed";regressed+=1
            else:delta="changed"
        rows.append({"identity_key":key,"name":after.get("comparison_name") or before.get("comparison_name") or "Anonymous","before":bc,"before_confidence":before.get("confidence"),"after":ac,"after_confidence":after.get("confidence"),"delta":delta})
    return {"compatible":True,"left_id":left.id,"right_id":right.id,"request_id":left_summary.get("stored_request_id"),"rows":rows,"changed":changed,"improved":improved,"regressed":regressed}
