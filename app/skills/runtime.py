from __future__ import annotations

import json
from sqlalchemy.orm import Session
from ..models import AgentEvent, AgentRun, ProjectSkill, SkillDefinition, SkillRun
from .registry import enabled_skills

def skill_for_capability(db: Session, project_id: int, capability: str) -> SkillDefinition | None:
    for skill in enabled_skills(db, project_id):
        try:
            caps = json.loads(skill.capabilities_json or "[]")
        except Exception:
            caps = []
        if capability in caps:
            return skill
    return None

def capability_enabled(db: Session, project_id: int, capability: str) -> bool:
    return skill_for_capability(db, project_id, capability) is not None

def start_skill_run(
    db: Session,
    project_id: int,
    capability: str,
    target: str,
    agent_run: AgentRun | None,
    stage: str,
) -> SkillRun | None:
    skill = skill_for_capability(db, project_id, capability)
    if not skill:
        return None
    row = SkillRun(
        project_id=project_id,
        skill_id=skill.id,
        agent_run_id=agent_run.id if agent_run else None,
        target=target,
        status="running",
        stage=stage,
        output_summary_json=json.dumps({"capability": capability}, ensure_ascii=False),
    )
    db.add(row)
    if agent_run:
        db.add(AgentEvent(
            agent_run_id=agent_run.id,
            event_type="skill_start",
            stage=stage,
            title=f"Skill started: {skill.name}",
            detail=f"{skill.slug} mapped capability '{capability}' to deterministic Workspace execution.",
            policy_class="READ_ONLY",
            status="running",
        ))
    db.commit()
    db.refresh(row)
    return row

def finish_skill_run(
    db: Session,
    row: SkillRun | None,
    status: str,
    summary: dict | str,
    agent_run: AgentRun | None = None,
):
    if not row:
        return
    row.status = status
    if isinstance(summary, str):
        payload = {"summary": summary}
    else:
        payload = summary
    row.output_summary_json = json.dumps(payload, ensure_ascii=False, default=str)
    skill = db.get(SkillDefinition, row.skill_id)
    if agent_run and skill:
        db.add(AgentEvent(
            agent_run_id=agent_run.id,
            event_type="skill_result",
            stage=row.stage,
            title=f"Skill {status}: {skill.name}",
            detail=json.dumps(payload, ensure_ascii=False, default=str)[:1200],
            policy_class="READ_ONLY",
            status=status,
        ))
    db.commit()
