from __future__ import annotations

import json
from collections import defaultdict
from sqlalchemy.orm import Session

from ..models import ExecutionGraphNode, SkillDefinition, SkillPlan, SkillRun

STAGE_ORDER = {
    "guardrails": 0,
    "recon": 10,
    "discovery": 20,
    "configuration": 30,
    "validation": 40,
    "analysis": 50,
    "quality": 60,
    "reporting": 70,
}

SKILL_STAGE = {
    "agent-tool-guardrails": "guardrails",
    "safe-reconnaissance": "recon",
    "browser-observation-workspace": "discovery",
    "web-attack-surface-mapping": "discovery",
    "javascript-api-mapper": "discovery",
    "transport-security-review": "configuration",
    "request-response-diff": "validation",
    "authorization-differential-review": "validation",
    "evidence-ai-triage": "analysis",
    "pentest-coverage-judge": "quality",
    "reporting-evidence-pack": "reporting",
}

DEPENDENCIES = {
    "browser-observation-workspace": ["web-attack-surface-mapping"],
    "javascript-api-mapper": ["web-attack-surface-mapping"],
    "transport-security-review": ["web-attack-surface-mapping"],
    "authorization-differential-review": ["request-response-diff"],
    "evidence-ai-triage": [
        "safe-reconnaissance",
        "web-attack-surface-mapping",
        "javascript-api-mapper",
        "transport-security-review",
        "request-response-diff",
        "authorization-differential-review",
    ],
    "pentest-coverage-judge": [
        "safe-reconnaissance",
        "web-attack-surface-mapping",
        "request-response-diff",
        "authorization-differential-review",
        "evidence-ai-triage",
    ],
    "reporting-evidence-pack": [
        "evidence-ai-triage",
        "pentest-coverage-judge",
        "authorization-differential-review",
    ],
}

def _loads(raw: str, default):
    try:
        return json.loads(raw or "")
    except Exception:
        return default

def _recommendation_map(plan: SkillPlan) -> dict[str, dict]:
    return {
        str(item.get("slug")): item
        for item in _loads(plan.recommendations_json, [])
        if isinstance(item, dict) and item.get("slug")
    }

def build_execution_graph(db: Session, plan: SkillPlan) -> list[ExecutionGraphNode]:
    existing = (
        db.query(ExecutionGraphNode)
        .filter(ExecutionGraphNode.skill_plan_id == plan.id)
        .all()
    )
    for row in existing:
        db.delete(row)
    db.flush()

    recommendations = _loads(plan.recommendations_json, [])
    rec_map = _recommendation_map(plan)
    slugs = [str(x.get("slug")) for x in recommendations if isinstance(x, dict) and x.get("slug")]
    selected = set(slugs)

    skills = {
        skill.slug: skill
        for skill in db.query(SkillDefinition).filter(SkillDefinition.slug.in_(slugs or ["__none__"])).all()
    }

    rows = []
    for idx, slug in enumerate(slugs):
        skill = skills.get(slug)
        if not skill:
            continue
        stage = SKILL_STAGE.get(slug, "analysis")
        deps = [dep for dep in DEPENDENCIES.get(slug, []) if dep in selected]
        try:
            caps = json.loads(skill.capabilities_json or "[]")
        except Exception:
            caps = []
        rec = rec_map.get(slug, {})
        rationale = str(rec.get("reason") or skill.description or "")
        if rec.get("ai_reason"):
            rationale = f"{rationale} AI: {rec.get('ai_reason')}"
        row = ExecutionGraphNode(
            project_id=plan.project_id,
            skill_plan_id=plan.id,
            skill_slug=slug,
            label=skill.name,
            stage=stage,
            execution_mode=skill.execution_mode,
            status="planned",
            order_index=STAGE_ORDER.get(stage, 50) * 100 + idx,
            depends_on_json=json.dumps(deps, ensure_ascii=False),
            capabilities_json=json.dumps(caps, ensure_ascii=False),
            rationale=rationale[:4000],
        )
        db.add(row)
        rows.append(row)

    db.commit()
    return graph_nodes(db, plan.id)

def graph_nodes(db: Session, plan_id: int) -> list[ExecutionGraphNode]:
    return (
        db.query(ExecutionGraphNode)
        .filter(ExecutionGraphNode.skill_plan_id == plan_id)
        .order_by(ExecutionGraphNode.order_index.asc(), ExecutionGraphNode.id.asc())
        .all()
    )

def mark_graph_approved(db: Session, plan: SkillPlan, approved_slugs: list[str]) -> None:
    approved = set(approved_slugs)
    nodes = graph_nodes(db, plan.id)
    if not nodes:
        nodes = build_execution_graph(db, plan)
    for node in nodes:
        if node.skill_slug not in approved:
            node.status = "disabled"
        elif node.execution_mode == "MANUAL_WORKSPACE":
            node.status = "manual_ready"
        else:
            node.status = "approved"
    db.commit()

def sync_graph_from_agent_run(db: Session, plan: SkillPlan, agent_run_id: int | None) -> None:
    nodes = graph_nodes(db, plan.id)
    approved = set(_loads(plan.approved_skills_json, []))
    runs = []
    if agent_run_id:
        runs = (
            db.query(SkillRun, SkillDefinition)
            .join(SkillDefinition, SkillDefinition.id == SkillRun.skill_id)
            .filter(SkillRun.agent_run_id == agent_run_id)
            .all()
        )
    by_slug: dict[str, list[SkillRun]] = defaultdict(list)
    for run, skill in runs:
        by_slug[skill.slug].append(run)

    for node in nodes:
        if node.skill_slug not in approved:
            node.status = "disabled"
            continue
        if node.execution_mode == "MANUAL_WORKSPACE":
            node.status = "manual_ready"
            continue
        skill_runs = by_slug.get(node.skill_slug, [])
        if skill_runs:
            latest = sorted(skill_runs, key=lambda r: r.id)[-1]
            node.skill_run_id = latest.id
            node.status = latest.status
        elif plan.status in {"executed", "error"}:
            node.status = "skipped"
        else:
            node.status = "approved"
    db.commit()

def graph_payload(db: Session, plan_id: int) -> dict:
    nodes = graph_nodes(db, plan_id)
    stages: dict[str, list[dict]] = defaultdict(list)
    for node in nodes:
        deps = _loads(node.depends_on_json, [])
        caps = _loads(node.capabilities_json, [])
        stages[node.stage].append({
            "id": node.id,
            "slug": node.skill_slug,
            "label": node.label,
            "stage": node.stage,
            "execution_mode": node.execution_mode,
            "status": node.status,
            "order_index": node.order_index,
            "depends_on": deps,
            "capabilities": caps,
            "rationale": node.rationale,
            "skill_run_id": node.skill_run_id,
        })
    ordered = [
        {"stage": stage, "nodes": stages[stage]}
        for stage in sorted(stages, key=lambda x: STAGE_ORDER.get(x, 50))
    ]
    return {
        "plan_id": plan_id,
        "node_count": len(nodes),
        "stages": ordered,
        "status_counts": {
            status: sum(1 for n in nodes if n.status == status)
            for status in sorted({n.status for n in nodes})
        },
    }
