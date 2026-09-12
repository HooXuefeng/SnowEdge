from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from ..ai.factory import get_ai_provider
from ..config import settings
from ..models import (
    AgentEvent,
    AgentRun,
    AuthorizationCase,
    Evidence,
    Finding,
    Identity,
    ReplayResult,
    ResponseDiff,
    StoredRequest,
    Task,
)
from ..policy import PolicyClass
from ..skills.runtime import finish_skill_run, start_skill_run
from .request_workspace import replay_request
from .finding_service import create_finding, ensure_finding_metadata
from .response_diff import compare_responses

SAFE_AUTHZ_METHODS = {"GET", "HEAD"}

SENSITIVE_KEYWORDS = {
    "phone", "mobile", "telephone", "email", "mail",
    "idcard", "id_card", "identity", "ssn", "passport",
    "bank", "cardno", "card_no", "bankcard", "bank_card",
    "address", "token", "access_token", "refresh_token",
    "secret", "password", "credential",
}


def _latest_agent(db: Session, project_id: int):
    return (
        db.query(AgentRun)
        .filter(AgentRun.project_id == project_id)
        .order_by(AgentRun.id.desc())
        .first()
    )


def _identity_label(identity: Identity | None) -> str:
    if not identity:
        return "Anonymous"
    return f"{identity.name} ({identity.role})"


def _is_success(status: int | None) -> bool:
    return status is not None and 200 <= status < 300


def _sensitive_paths(body: str) -> list[str]:
    try:
        value = json.loads(body or "")
    except Exception:
        return []

    found: set[str] = set()

    def walk(obj: Any, path: str = "$"):
        if isinstance(obj, dict):
            for key, child in obj.items():
                key_text = str(key)
                normalized = key_text.lower().replace("-", "_")
                if any(word in normalized for word in SENSITIVE_KEYWORDS):
                    found.add(f"{path}.{key_text}")
                walk(child, f"{path}.{key_text}")
        elif isinstance(obj, list):
            for index, child in enumerate(obj[:50]):
                walk(child, f"{path}[{index}]")

    walk(value)
    return sorted(found)[:100]


def analyze_authorization(
    test_type: str,
    baseline: ReplayResult,
    comparison: ReplayResult,
    diff_summary: dict,
    baseline_identity: Identity | None,
    comparison_identity: Identity | None,
    expected_owner_identity_id: int | None,
) -> dict:
    baseline_ok = _is_success(baseline.status_code)
    comparison_ok = _is_success(comparison.status_code)
    similarity = float(diff_summary.get("text_similarity") or 0)
    baseline_len = len(baseline.response_body or "")
    comparison_len = len(comparison.response_body or "")
    body_size = max(baseline_len, comparison_len)
    json_info = diff_summary.get("json") or {}
    json_changed = len(json_info.get("changed") or {})
    json_added = len(json_info.get("added") or {})
    json_removed = len(json_info.get("removed") or {})
    sensitive_baseline = _sensitive_paths(baseline.response_body)
    sensitive_comparison = _sensitive_paths(comparison.response_body)

    classification = "needs_review"
    confidence = 45
    rationale: list[str] = []

    if not baseline_ok:
        classification = "inconclusive"
        confidence = 25
        rationale.append("Baseline identity did not receive a successful 2xx response.")
    elif comparison.status_code in {401, 403}:
        classification = "authorization_control_enforced"
        confidence = 94
        rationale.append("Comparison identity was rejected with an authorization status.")
    elif not comparison_ok:
        classification = "authorization_control_likely_enforced"
        confidence = 82
        rationale.append(f"Comparison identity received HTTP {comparison.status_code}, while baseline received HTTP {baseline.status_code}.")
    elif body_size < 40:
        classification = "inconclusive"
        confidence = 35
        rationale.append("Responses are too small to support a reliable authorization conclusion.")
    else:
        if test_type == "unauthenticated":
            if comparison_identity is not None:
                rationale.append("Unauthenticated test expected Anonymous as comparison identity.")
                confidence -= 15
            if comparison_ok and similarity >= 0.92:
                classification = "potential_unauthenticated_access"
                confidence = 90
                rationale.append("Anonymous response is successful and highly similar to the authenticated baseline.")
            elif comparison_ok and similarity >= 0.75:
                classification = "potential_unauthenticated_access"
                confidence = 72
                rationale.append("Anonymous response is successful and materially similar to the authenticated baseline.")
            else:
                classification = "needs_review"
                confidence = 55
                rationale.append("Anonymous access succeeded, but response content differs substantially from the baseline.")

        elif test_type == "horizontal":
            same_role = (
                baseline_identity is not None
                and comparison_identity is not None
                and baseline_identity.role.strip().lower() == comparison_identity.role.strip().lower()
            )
            owner_matches_baseline = (
                expected_owner_identity_id is not None
                and baseline_identity is not None
                and expected_owner_identity_id == baseline_identity.id
            )
            if same_role and owner_matches_baseline and comparison_ok and similarity >= 0.90:
                classification = "potential_horizontal_authorization_gap"
                confidence = 91
                rationale.append("A peer identity received a highly similar successful response for a resource marked as owned by the baseline identity.")
            elif same_role and owner_matches_baseline and comparison_ok and similarity >= 0.72:
                classification = "potential_horizontal_authorization_gap"
                confidence = 76
                rationale.append("A peer identity received a successful response for a resource marked as owned by the baseline identity.")
            elif comparison_ok and similarity >= 0.90:
                classification = "horizontal_access_needs_review"
                confidence = 64
                rationale.append("Peer response is highly similar, but explicit ownership evidence is missing.")
            else:
                classification = "needs_review"
                confidence = 48
                rationale.append("The peer response differs enough that manual ownership review is required.")

        elif test_type == "vertical":
            roles_differ = (
                baseline_identity is not None
                and comparison_identity is not None
                and baseline_identity.role.strip().lower() != comparison_identity.role.strip().lower()
            )
            if roles_differ and comparison_ok and similarity >= 0.90:
                classification = "potential_vertical_authorization_gap"
                confidence = 88
                rationale.append("A different-role identity received a highly similar successful response to the privileged baseline.")
            elif roles_differ and comparison_ok and similarity >= 0.72:
                classification = "potential_vertical_authorization_gap"
                confidence = 73
                rationale.append("A different-role identity received a successful response with substantial content overlap.")
            elif comparison_ok:
                classification = "vertical_access_needs_review"
                confidence = 58
                rationale.append("Lower/different-role access succeeded, but response semantics differ.")
            else:
                classification = "authorization_control_likely_enforced"
                confidence = 80
                rationale.append("Different-role identity did not receive a successful response.")

    if sensitive_comparison and comparison_ok:
        rationale.append(f"Comparison response contains {len(sensitive_comparison)} sensitive-looking JSON field path(s).")
        if classification.startswith("potential_"):
            confidence = min(96, confidence + 3)

    return {
        "test_type": test_type,
        "classification": classification,
        "confidence": max(0, min(100, confidence)),
        "baseline": {
            "identity": _identity_label(baseline_identity),
            "status_code": baseline.status_code,
            "length": baseline_len,
            "sensitive_paths": sensitive_baseline,
        },
        "comparison": {
            "identity": _identity_label(comparison_identity),
            "status_code": comparison.status_code,
            "length": comparison_len,
            "sensitive_paths": sensitive_comparison,
        },
        "similarity": similarity,
        "json_changes": {
            "changed": json_changed,
            "added": json_added,
            "removed": json_removed,
        },
        "rationale": rationale,
        "manual_confirmation_required": classification.startswith("potential_") or classification.endswith("needs_review"),
    }


def _candidate_finding_text(case: AuthorizationCase, analysis: dict, stored: StoredRequest) -> tuple[str, str, str]:
    names = {
        "potential_unauthenticated_access": "Potential Unauthenticated Access (Review Required)",
        "potential_horizontal_authorization_gap": "Potential Horizontal Authorization Gap (Review Required)",
        "potential_vertical_authorization_gap": "Potential Vertical Authorization Gap (Review Required)",
    }
    title = names.get(analysis["classification"], "Potential Authorization Issue (Review Required)")
    severity = "medium"
    rationale = " ".join(analysis.get("rationale") or [])
    description = (
        f"Automated read-only differential testing identified a potential authorization issue on {stored.method} {stored.url}. "
        f"Classification: {analysis['classification']}; confidence: {analysis['confidence']}%. "
        f"{rationale} This is a candidate finding and requires manual confirmation before being treated as a confirmed vulnerability."
    )
    return title, severity, description


async def run_authorization_case(
    db: Session,
    project_scope: list[str],
    case: AuthorizationCase,
    baseline_identity: Identity | None,
    comparison_identity: Identity | None,
    auto_candidate_finding: bool | None = None,
) -> AuthorizationCase:
    if auto_candidate_finding is None:
        auto_candidate_finding = settings.authorization_auto_candidate_findings

    stored = db.get(StoredRequest, case.stored_request_id)
    if not stored:
        raise ValueError("Stored request not found.")
    if stored.method.upper() not in SAFE_AUTHZ_METHODS:
        raise ValueError("Authorization automation is limited to GET/HEAD requests.")
    if stored.policy_class != PolicyClass.READ_ONLY.value:
        raise ValueError("Authorization automation requires a READ_ONLY request.")

    agent_for_skill = _latest_agent(db, case.project_id)
    auth_skill_run = start_skill_run(
        db, case.project_id, "authorization_lab", stored.url, agent_for_skill, "authorization_testing"
    )

    task = Task(
        project_id=case.project_id,
        action="authorization_test",
        target=stored.url,
        policy_class=PolicyClass.READ_ONLY.value,
        status="running",
        detail=f"Authorization case #{case.id}: {case.test_type}",
    )
    db.add(task)
    case.status = "running"
    db.commit()
    db.refresh(task)

    try:
        baseline = await replay_request(db, project_scope, stored, baseline_identity)
        comparison = await replay_request(db, project_scope, stored, comparison_identity)

        summary = compare_responses(
            baseline.status_code,
            json.loads(baseline.response_headers_json or "{}"),
            baseline.response_body,
            comparison.status_code,
            json.loads(comparison.response_headers_json or "{}"),
            comparison.response_body,
        )
        diff = ResponseDiff(
            project_id=case.project_id,
            left_replay_id=baseline.id,
            right_replay_id=comparison.id,
            summary_json=json.dumps(summary, ensure_ascii=False),
        )
        db.add(diff)
        db.flush()

        analysis = analyze_authorization(
            case.test_type,
            baseline,
            comparison,
            summary,
            baseline_identity,
            comparison_identity,
            case.expected_owner_identity_id,
        )

        case.baseline_replay_id = baseline.id
        case.comparison_replay_id = comparison.id
        case.response_diff_id = diff.id
        case.classification = analysis["classification"]
        case.confidence = analysis["confidence"]
        case.summary_json = json.dumps(analysis, ensure_ascii=False)

        ai_review_context = {
            "test_type": case.test_type,
            "classification": analysis["classification"],
            "confidence": analysis["confidence"],
            "request": {"method": stored.method, "url": stored.url},
            "baseline": {
                "identity": analysis["baseline"]["identity"],
                "status_code": analysis["baseline"]["status_code"],
                "length": analysis["baseline"]["length"],
                "sensitive_paths": analysis["baseline"]["sensitive_paths"],
            },
            "comparison": {
                "identity": analysis["comparison"]["identity"],
                "status_code": analysis["comparison"]["status_code"],
                "length": analysis["comparison"]["length"],
                "sensitive_paths": analysis["comparison"]["sensitive_paths"],
            },
            "similarity": analysis["similarity"],
            "json_changes": analysis["json_changes"],
            "rationale": analysis["rationale"],
            "expected_owner_identity_id": case.expected_owner_identity_id,
        }
        try:
            provider = get_ai_provider()
            ai_review = await provider.review_authorization(ai_review_context)
            if not isinstance(ai_review, dict):
                ai_review = {}
        except Exception as exc:
            ai_review = {
                "assessment": f"AI second opinion unavailable: {type(exc).__name__}.",
                "risk": "review",
                "confidence_adjustment": 0,
                "manual_checks": [],
            }
        case.ai_review_json = json.dumps(ai_review, ensure_ascii=False)
        case.status = "done"

        task.status = "done"
        task.detail = f"{analysis['classification']} ({analysis['confidence']}%)"

        evidence_payload = {
            "authorization_case_id": case.id,
            "stored_request_id": stored.id,
            "method": stored.method,
            "url": stored.url,
            "test_type": case.test_type,
            "baseline_replay_id": baseline.id,
            "comparison_replay_id": comparison.id,
            "response_diff_id": diff.id,
            "analysis": analysis,
        }
        db.add(Evidence(
            task_id=task.id,
            kind="authorization_analysis",
            content=json.dumps(evidence_payload, ensure_ascii=False, indent=2),
        ))

        agent = _latest_agent(db, case.project_id)
        if agent:
            db.add(AgentEvent(
                agent_run_id=agent.id,
                event_type="analysis",
                stage="authorization_testing",
                title=f"Authorization case #{case.id}: {analysis['classification']}",
                detail=f"{stored.method} {stored.url} compared {_identity_label(baseline_identity)} vs {_identity_label(comparison_identity)}. Confidence {analysis['confidence']}%.",
                policy_class=PolicyClass.READ_ONLY.value,
                status="done",
            ))

            if ai_review:
                db.add(AgentEvent(
                    agent_run_id=agent.id,
                    event_type="ai_review",
                    stage="authorization_testing",
                    title=f"AI authorization second opinion #{case.id}",
                    detail=str(ai_review.get("assessment", "AI review completed."))[:1200],
                    policy_class=PolicyClass.READ_ONLY.value,
                    status="done",
                ))

        if (
            auto_candidate_finding
            and analysis["classification"].startswith("potential_")
            and analysis["confidence"] >= settings.authorization_auto_candidate_min_confidence
            and case.finding_id is None
        ):
            title, severity, description = _candidate_finding_text(case, analysis, stored)
            finding = create_finding(
                db=db,
                project_id=case.project_id,
                title=title,
                severity=severity,
                target=stored.url,
                description=description,
                recommendation=(
                    "Manually confirm resource ownership and intended role permissions. "
                    "If unauthorized access is confirmed, enforce object-level and function-level authorization on the server for every request."
                ),
                source="authorization_testing",
                evidence_kind="authorization_candidate_summary",
                evidence_content=evidence_payload,
                vuln_type="Authorization Control",
                cwe_id="CWE-862",
                owasp_category="A01:2021 Broken Access Control",
                txb02_category="权限控制",
            )
            case.finding_id = finding.id

        finish_skill_run(db, auth_skill_run, "done", {
            "authorization_case_id": case.id,
            "classification": analysis["classification"],
            "confidence": analysis["confidence"],
            "response_diff_id": diff.id,
            "finding_id": case.finding_id,
        }, agent_for_skill)
        db.commit()
        db.refresh(case)
        return case

    except Exception as exc:
        case.status = "error"
        case.classification = "error"
        case.summary_json = json.dumps({"error": f"{type(exc).__name__}: {exc}"}, ensure_ascii=False)
        finish_skill_run(db, auth_skill_run, "error", {"error": f"{type(exc).__name__}: {exc}"}, agent_for_skill)
        task.status = "error"
        task.detail = f"{type(exc).__name__}: {exc}"
        db.commit()
        raise


def promote_authorization_case(db: Session, case: AuthorizationCase) -> Finding:
    if case.finding_id:
        existing = db.get(Finding, case.finding_id)
        if existing:
            return existing

    stored = db.get(StoredRequest, case.stored_request_id)
    if not stored:
        raise ValueError("Stored request not found.")

    analysis = json.loads(case.summary_json or "{}")
    ai_review = json.loads(case.ai_review_json or "{}")
    classification = case.classification or "needs_review"

    if "enforced" in classification or classification in {"inconclusive", "error", "pending"}:
        raise ValueError("This case does not represent a candidate authorization issue.")

    title_map = {
        "potential_unauthenticated_access": "Potential Unauthenticated Access (Review Required)",
        "potential_horizontal_authorization_gap": "Potential Horizontal Authorization Gap (Review Required)",
        "potential_vertical_authorization_gap": "Potential Vertical Authorization Gap (Review Required)",
        "horizontal_access_needs_review": "Horizontal Authorization Behavior Requires Review",
        "vertical_access_needs_review": "Vertical Authorization Behavior Requires Review",
        "needs_review": "Authorization Behavior Requires Review",
    }
    finding = create_finding(
        db=db,
        project_id=case.project_id,
        title=title_map.get(classification, "Authorization Behavior Requires Review"),
        severity="medium" if classification.startswith("potential_") else "low",
        target=stored.url,
        description=(
            f"Authorization case #{case.id} was manually promoted for security review. "
            f"Deterministic classification: {classification}; confidence: {case.confidence}%. "
            "This remains a review candidate until resource ownership and intended permissions are manually confirmed."
        ),
        recommendation=(
            "Confirm intended access rules and resource ownership. If unauthorized access is confirmed, "
            "enforce server-side object-level and function-level authorization on every request."
        ),
        source="authorization_testing",
        evidence_kind="authorization_manual_promotion",
        evidence_content={
            "authorization_case_id": case.id,
            "classification": classification,
            "confidence": case.confidence,
            "analysis": analysis,
            "ai_second_opinion": ai_review,
        },
        vuln_type="Authorization Control",
        cwe_id="CWE-862",
        owasp_category="A01:2021 Broken Access Control",
        txb02_category="权限控制",
    )
    case.finding_id = finding.id
    db.commit()
    db.refresh(finding)
    return finding
