from __future__ import annotations

import json
from sqlalchemy.orm import Session

from ..ai.factory import get_ai_provider
from ..models import (
    AgentEvent,
    AgentHandoff,
    AgentRun,
    AssessmentMemory,
    KnowledgeEdge,
    KnowledgeNode,
    Project,
    SpecialistAgentRun,
)
from ..skills.registry import enabled_skills
from .assessment_memory import memory_hints, memory_summary, refresh_assessment_memory
from .knowledge_graph import graph_summary, rebuild_knowledge_graph


ROLE_DEFINITIONS = {
    "planner": {
        "slug": "planner",
        "name": "Planner Agent",
        "purpose": "Coordinate evidence review and prevent redundant assessment work.",
        "allowed_skills": [
            "agent-tool-guardrails",
            "pentest-coverage-judge",
            "evidence-ai-triage",
        ],
        "allowed_capabilities": ["coverage_judge", "ai_analyze"],
        "visible_node_types": [
            "project", "asset", "service", "endpoint", "route", "finding",
            "authorization_case", "proof_capsule", "finding_lifecycle", "coverage_snapshot", "browser_session", "skill_plan",
            "execution_node", "agent_run", "skill_run",
        ],
        "visible_memory_types": [
            "coverage_action", "authorization_test", "browser_observation",
            "response_diff", "finding_verification", "remediation_state", "finding",
        ],
        "handoff_targets": [
            "recon_analyst", "web_analyst", "authorization_analyst",
            "evidence_reviewer", "reporter",
        ],
        "risk_ceiling": "LOW_RISK_VALIDATE",
    },
    "recon_analyst": {
        "slug": "recon_analyst",
        "name": "Recon Analyst",
        "purpose": "Review existing host/service/transport evidence before any repeated reconnaissance.",
        "allowed_skills": ["safe-reconnaissance", "transport-security-review"],
        "allowed_capabilities": ["port_scan", "tls_check", "headers_check"],
        "visible_node_types": ["project", "asset", "service", "endpoint", "task", "skill_run"],
        "visible_memory_types": ["coverage_action", "finding", "finding_verification"],
        "handoff_targets": ["web_analyst", "evidence_reviewer"],
        "risk_ceiling": "LOW_RISK_VALIDATE",
    },
    "web_analyst": {
        "slug": "web_analyst",
        "name": "Web Analyst",
        "purpose": "Correlate static web discovery, browser observations, routes and stored requests.",
        "allowed_skills": [
            "web-attack-surface-mapping",
            "javascript-api-mapper",
            "browser-observation-workspace",
            "request-response-diff",
        ],
        "allowed_capabilities": [
            "http_probe", "web_discovery", "js_static_analysis",
            "browser_workspace", "request_workspace", "response_diff",
        ],
        "visible_node_types": [
            "asset", "endpoint", "web_artifact", "route", "browser_session",
            "browser_event", "request", "finding", "proof_capsule",
        ],
        "visible_memory_types": [
            "browser_observation", "response_diff", "coverage_action",
            "finding", "finding_verification",
        ],
        "handoff_targets": ["authorization_analyst", "evidence_reviewer"],
        "risk_ceiling": "READ_ONLY",
    },
    "authorization_analyst": {
        "slug": "authorization_analyst",
        "name": "Authorization Analyst",
        "purpose": "Review read-only identity/object comparisons and avoid repeating already-enforced controls.",
        "allowed_skills": ["request-response-diff", "authorization-differential-review"],
        "allowed_capabilities": ["request_workspace", "response_diff", "authorization_lab"],
        "visible_node_types": [
            "request", "identity", "authorization_case", "finding",
            "proof_capsule", "browser_event", "evidence",
        ],
        "visible_memory_types": [
            "authorization_test", "response_diff", "finding_verification", "finding",
        ],
        "handoff_targets": ["evidence_reviewer", "reporter"],
        "risk_ceiling": "READ_ONLY",
    },
    "evidence_reviewer": {
        "slug": "evidence_reviewer",
        "name": "Evidence Reviewer",
        "purpose": "Judge whether conclusions are backed by deterministic evidence and verification state.",
        "allowed_skills": [
            "evidence-ai-triage", "pentest-coverage-judge", "reporting-evidence-pack",
        ],
        "allowed_capabilities": ["ai_analyze", "coverage_judge", "reporting"],
        "visible_node_types": [
            "finding", "evidence", "proof_capsule", "finding_lifecycle", "authorization_case",
            "task", "skill_run", "execution_node",
        ],
        "visible_memory_types": [
            "finding_verification", "remediation_state", "finding", "authorization_test",
            "coverage_action", "response_diff",
        ],
        "handoff_targets": ["reporter"],
        "risk_ceiling": "READ_ONLY",
    },
    "reporter": {
        "slug": "reporter",
        "name": "Reporter Agent",
        "purpose": "Prepare verification-aware reporting from existing evidence only.",
        "allowed_skills": ["reporting-evidence-pack"],
        "allowed_capabilities": ["reporting"],
        "visible_node_types": [
            "finding", "proof_capsule", "finding_lifecycle", "coverage_snapshot", "authorization_case", "skill_plan",
            "execution_node", "browser_session", "agent_run",
        ],
        "visible_memory_types": [
            "finding_verification", "remediation_state", "finding", "authorization_test",
            "browser_observation",
        ],
        "handoff_targets": [],
        "risk_ceiling": "READ_ONLY",
    },
}

ROLE_ORDER = [
    "planner",
    "recon_analyst",
    "web_analyst",
    "authorization_analyst",
    "evidence_reviewer",
    "reporter",
]


def _loads(raw: str, default):
    try:
        return json.loads(raw or "")
    except Exception:
        return default


def _intent_contract(project: Project, role: dict, enabled_skill_slugs: list[str]) -> dict:
    allowed_skills = [
        slug for slug in role["allowed_skills"]
        if slug in enabled_skill_slugs
    ]
    return {
        "analysis_only": True,
        "tool_invocation": False,
        "scope_rules": [x.strip() for x in project.scope_text.splitlines() if x.strip()],
        "role_slug": role["slug"],
        "role_name": role["name"],
        "purpose": role["purpose"],
        "allowed_skills": allowed_skills,
        "allowed_capabilities": role["allowed_capabilities"],
        "visible_node_types": role["visible_node_types"],
        "visible_memory_types": role["visible_memory_types"],
        "handoff_targets": role["handoff_targets"],
        "risk_ceiling": role["risk_ceiling"],
        "unknown_action_policy": "DENY",
    }


def _specialist_context(db: Session, project_id: int, role: dict) -> dict:
    nodes = (
        db.query(KnowledgeNode)
        .filter(
            KnowledgeNode.project_id == project_id,
            KnowledgeNode.node_type.in_(role["visible_node_types"]),
        )
        .order_by(KnowledgeNode.id.desc())
        .limit(120)
        .all()
    )
    node_ids = {n.id for n in nodes}
    edges = (
        db.query(KnowledgeEdge)
        .filter(
            KnowledgeEdge.project_id == project_id,
            KnowledgeEdge.source_node_id.in_(node_ids or {-1}),
            KnowledgeEdge.target_node_id.in_(node_ids or {-1}),
        )
        .order_by(KnowledgeEdge.id.desc())
        .limit(180)
        .all()
    )
    memories = (
        db.query(AssessmentMemory)
        .filter(
            AssessmentMemory.project_id == project_id,
            AssessmentMemory.memory_type.in_(role["visible_memory_types"]),
        )
        .order_by(AssessmentMemory.id.desc())
        .limit(80)
        .all()
    )
    return {
        "graph_summary": graph_summary(db, project_id),
        "graph_nodes": [
            {
                "key": n.node_key,
                "type": n.node_type,
                "label": n.label,
                "risk": n.risk_level,
                "summary": _loads(n.summary_json, {}),
            }
            for n in nodes
        ],
        "graph_edges": [
            {
                "source": next((n.node_key for n in nodes if n.id == e.source_node_id), f"node:{e.source_node_id}"),
                "target": next((n.node_key for n in nodes if n.id == e.target_node_id), f"node:{e.target_node_id}"),
                "relation": e.relation,
                "strength": e.strength,
            }
            for e in edges
        ],
        "memory_summary": memory_summary(db, project_id),
        "memories": [
            {
                "type": m.memory_type,
                "subject": m.subject,
                "outcome": m.outcome,
                "confidence": m.confidence,
                "repeat_guidance": m.repeat_guidance,
                "summary": m.summary,
            }
            for m in memories
        ],
        "project_profile": {
            "project_id": project_id,
            "knowledge_node_count": db.query(KnowledgeNode).filter(KnowledgeNode.project_id == project_id).count(),
            "memory_count": db.query(AssessmentMemory).filter(AssessmentMemory.project_id == project_id).count(),
        },
    }


def _sanitize_output(raw: dict, role: dict) -> tuple[dict, int]:
    if not isinstance(raw, dict):
        raw = {}
    drift = 0
    for unexpected in ("tool_calls", "tool_requests", "commands", "shell", "payloads"):
        value = raw.get(unexpected)
        if value:
            drift += len(value) if isinstance(value, list) else 1

    observations = []
    for item in raw.get("observations", [])[:12]:
        if not isinstance(item, dict):
            continue
        try:
            confidence = int(item.get("confidence", 0))
        except Exception:
            confidence = 0
        observations.append({
            "subject_key": str(item.get("subject_key", ""))[:240],
            "observation": str(item.get("observation", ""))[:1600],
            "confidence": max(0, min(100, confidence)),
        })

    handoffs = []
    allowed_targets = set(role["handoff_targets"])
    for item in raw.get("handoffs", [])[:6]:
        if not isinstance(item, dict):
            continue
        target = str(item.get("to_role", ""))
        if target not in allowed_targets:
            drift += 1
            continue
        subjects = item.get("subject_keys", [])
        handoffs.append({
            "to_role": target,
            "reason": str(item.get("reason", ""))[:1200],
            "subject_keys": [str(x)[:240] for x in subjects[:12]] if isinstance(subjects, list) else [],
        })

    checks = raw.get("next_checks", [])
    clean = {
        "summary": str(raw.get("summary", ""))[:3000],
        "observations": observations,
        "handoffs": handoffs,
        "next_checks": [str(x)[:1000] for x in checks[:10]] if isinstance(checks, list) else [],
        "analysis_only": True,
    }
    return clean, drift


async def run_specialist_team(
    db: Session,
    project: Project,
    *,
    parent_agent_run_id: int | None = None,
) -> AgentRun:
    rebuild_knowledge_graph(db, project.id)
    refresh_assessment_memory(db, project.id)

    parent = db.get(AgentRun, parent_agent_run_id) if parent_agent_run_id else None
    if parent and parent.project_id != project.id:
        parent = None
    if parent is None:
        parent = AgentRun(
            project_id=project.id,
            target=f"project:{project.id}",
            mission=(
                "Run an analysis-only specialist team over the redacted Knowledge Graph "
                "and Assessment Memory. No specialist may invoke network tools."
            ),
            stage="multi_agent_review",
            status="running",
        )
        db.add(parent)
        db.commit()
        db.refresh(parent)
    else:
        parent.stage = "multi_agent_review"
        parent.status = "running"
        db.commit()

    enabled = [s.slug for s in enabled_skills(db, project.id)]
    provider = get_ai_provider()
    completed = 0
    failed = 0
    total_drift = 0

    for role_slug in ROLE_ORDER:
        role = ROLE_DEFINITIONS[role_slug]
        contract = _intent_contract(project, role, enabled)
        context = _specialist_context(db, project.id, role)
        specialist = SpecialistAgentRun(
            project_id=project.id,
            parent_agent_run_id=parent.id,
            role_slug=role_slug,
            role_name=role["name"],
            status="running",
            intent_contract_json=json.dumps(contract, ensure_ascii=False),
            input_snapshot_json=json.dumps({
                "graph_summary": context["graph_summary"],
                "memory_summary": context["memory_summary"],
                "visible_node_count": len(context["graph_nodes"]),
                "visible_memory_count": len(context["memories"]),
            }, ensure_ascii=False),
        )
        db.add(specialist)
        db.commit()
        db.refresh(specialist)

        try:
            raw = await provider.specialist_review(
                {
                    "slug": role["slug"],
                    "name": role["name"],
                    "purpose": role["purpose"],
                    "allowed_skills": contract["allowed_skills"],
                    "allowed_capabilities": role["allowed_capabilities"],
                    "risk_ceiling": role["risk_ceiling"],
                },
                context,
                role["handoff_targets"],
            )
            clean, drift = _sanitize_output(raw, role)
            specialist.output_json = json.dumps(clean, ensure_ascii=False)
            specialist.drift_count = drift
            specialist.status = "done"
            total_drift += drift
            completed += 1

            for handoff in clean["handoffs"]:
                db.add(AgentHandoff(
                    project_id=project.id,
                    from_specialist_run_id=specialist.id,
                    to_role_slug=handoff["to_role"],
                    handoff_type="analysis",
                    reason=handoff["reason"],
                    subject_keys_json=json.dumps(handoff["subject_keys"], ensure_ascii=False),
                    status="recorded",
                ))

            db.add(AgentEvent(
                agent_run_id=parent.id,
                event_type="specialist",
                stage="multi_agent_review",
                title=f"{role['name']} completed",
                detail=clean["summary"] or f"{role['name']} completed an analysis-only review.",
                policy_class="READ_ONLY",
                status="done",
            ))
        except Exception as exc:
            specialist.status = "error"
            specialist.output_json = json.dumps(
                {"error": f"{type(exc).__name__}: {exc}", "analysis_only": True},
                ensure_ascii=False,
            )
            failed += 1
            db.add(AgentEvent(
                agent_run_id=parent.id,
                event_type="specialist",
                stage="multi_agent_review",
                title=f"{role['name']} failed",
                detail=f"{type(exc).__name__}: {exc}",
                policy_class="READ_ONLY",
                status="error",
            ))
        db.commit()

    parent.status = "done" if completed else "error"
    parent.stage = "complete"
    parent.summary = (
        f"Specialist team review completed: {completed}/{len(ROLE_ORDER)} specialists done, "
        f"{failed} failed, {total_drift} intent-drift item(s) blocked."
    )
    db.commit()
    db.refresh(parent)
    return parent


def team_summary(db: Session, project_id: int, parent_agent_run_id: int | None = None) -> dict:
    query = db.query(SpecialistAgentRun).filter(SpecialistAgentRun.project_id == project_id)
    if parent_agent_run_id:
        query = query.filter(SpecialistAgentRun.parent_agent_run_id == parent_agent_run_id)
    runs = query.order_by(SpecialistAgentRun.id.desc()).limit(60).all()
    run_ids = [r.id for r in runs] or [-1]
    handoffs = (
        db.query(AgentHandoff)
        .filter(AgentHandoff.project_id == project_id, AgentHandoff.from_specialist_run_id.in_(run_ids))
        .order_by(AgentHandoff.id.desc())
        .limit(100)
        .all()
    )
    return {
        "runs": runs,
        "handoffs": handoffs,
        "completed": sum(1 for r in runs if r.status == "done"),
        "errors": sum(1 for r in runs if r.status == "error"),
        "drift_blocked": sum(int(r.drift_count or 0) for r in runs),
    }
