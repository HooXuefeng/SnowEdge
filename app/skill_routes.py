from __future__ import annotations

import json
from pathlib import Path
from fastapi import APIRouter, BackgroundTasks, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.requests import Request

from .config import settings
from .ui_i18n import configure_templates
from .db import SessionLocal, get_db
from .models import AgentRun, Project, SkillDefinition, SkillPlan, SkillRun, ProjectSkill, Task
from .skills.analysis import coverage_snapshot, guardrail_snapshot
from .orchestrator import run_authorized_scan
from .policy import classify_action
from .scope import target_in_scope
from .services.skill_planner import approve_skill_plan, generate_skill_plan, plan_payload
from .services.execution_graph import graph_payload, sync_graph_from_agent_run
from .skills.registry import (
    import_external_skill, seed_builtin_skills, ensure_project_skill_rows,
    selected_skill_state, set_project_skill
)

BASE_DIR = Path(__file__).resolve().parent
templates = configure_templates(Jinja2Templates(directory=BASE_DIR / "templates"))
router = APIRouter()

SKILL_PACKS = {
    "analysis-only": {
        "name": "Analysis Only",
        "description": "No automatic network discovery. Local coverage, guardrail, reporting and bounded AI methodology only.",
        "skills": {"evidence-ai-triage", "pentest-coverage-judge", "reporting-evidence-pack", "agent-tool-guardrails"},
    },
    "passive-web": {
        "name": "Passive Web / API",
        "description": "Read-only HTTP, HTML/JS discovery, TLS/header review and evidence triage. No port reconnaissance.",
        "skills": {"web-attack-surface-mapping", "javascript-api-mapper", "transport-security-review", "evidence-ai-triage", "pentest-coverage-judge", "reporting-evidence-pack", "agent-tool-guardrails"},
    },
    "web-authz": {
        "name": "Web + Authorization",
        "description": "Passive Web/API discovery plus Request Workspace and Authorization Lab methodologies.",
        "skills": {"web-attack-surface-mapping", "javascript-api-mapper", "transport-security-review", "request-response-diff", "authorization-differential-review", "evidence-ai-triage", "pentest-coverage-judge", "reporting-evidence-pack", "agent-tool-guardrails"},
    },
    "full-safe": {
        "name": "Full Safe Workspace",
        "description": "All built-in V1.4 safe/low-risk skills, including constrained port reconnaissance.",
        "skills": set(),
    },
}

REFERENCE_LIBRARIES = [
    {
        "name": "AboutSecurity",
        "url": "https://github.com/wgpsec/AboutSecurity",
        "note": "Large pentest methodology knowledge base with SKILL.md organization.",
        "mode": "reference / paste import",
    },
    {
        "name": "Anthropic Cybersecurity Skills (community)",
        "url": "https://github.com/mukul975/Anthropic-Cybersecurity-Skills",
        "note": "Large agentskills.io-style cybersecurity skill library.",
        "mode": "reference / paste import",
    },
    {
        "name": "CAI",
        "url": "https://github.com/Owami/cai-cybersecurity",
        "note": "Agent, tools, handoffs, tracing, HITL and cybersecurity orchestration patterns.",
        "mode": "architecture reference",
    },
    {
        "name": "PentestGPT",
        "url": "https://github.com/GreyDGL/PentestGPT",
        "note": "Staged agent pipeline with deterministic scope/evidence/trace boundaries.",
        "mode": "architecture reference",
    },
    {
        "name": "第三方渗透测试技能参考（Erfix404）",
        "url": "https://github.com/Erfix404/ai-pentest-agent",
        "note": "Example SKILL.md/SKILL.yaml autonomous pentest packaging. Imported content remains knowledge-only here.",
        "mode": "reference only",
    },
]

def _context(db: Session, project: Project, active_nav: str = "skills"):
    from .main import _project_context
    return _project_context(db, project, active_nav)

@router.get("/projects/{project_id}/skills", response_class=HTMLResponse)
def skill_hub(project_id: int, request: Request, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    seed_builtin_skills(db)
    ensure_project_skill_rows(db, project_id)
    state = selected_skill_state(db, project_id)
    runs = db.query(SkillRun).filter(SkillRun.project_id == project_id).order_by(SkillRun.id.desc()).limit(50).all()
    context = _context(db, project)
    context.update({
        "skill_state": state,
        "skill_runs": runs,
        "skill_run_map": {skill.id: skill for skill in db.query(SkillDefinition).all()},
        "coverage": coverage_snapshot(db, project_id),
        "guardrails": guardrail_snapshot(),
        "reference_libraries": REFERENCE_LIBRARIES,
        "skill_packs": SKILL_PACKS,
    })
    return templates.TemplateResponse(request=request, name="skills.html", context=context)

@router.post("/projects/{project_id}/skills/{skill_id:int}/toggle")
def toggle_skill(project_id: int, skill_id: int, enabled: int = Form(0), db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    skill = db.get(SkillDefinition, skill_id)
    if not project or not skill:
        raise HTTPException(404)
    set_project_skill(db, project_id, skill_id, bool(enabled))
    return RedirectResponse(f"/projects/{project_id}/skills", status_code=303)

@router.post("/projects/{project_id}/skills/import")
def import_skill(
    project_id: int,
    raw_markdown: str = Form(...),
    source_url: str = Form(""),
    source_name: str = Form("External SKILL.md"),
    enable_after_import: int = Form(0),
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    if len(raw_markdown) > 200000:
        raise HTTPException(400, "SKILL.md is too large.")
    skill = import_external_skill(db, raw_markdown, source_url, source_name)
    ensure_project_skill_rows(db, project_id)
    if enable_after_import:
        set_project_skill(db, project_id, skill.id, True)
    return RedirectResponse(f"/projects/{project_id}/skills#imported", status_code=303)

@router.post("/projects/{project_id}/skills/reset-defaults")
def reset_defaults(project_id: int, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    seed_builtin_skills(db)
    ensure_project_skill_rows(db, project_id)
    rows = (
        db.query(ProjectSkill, SkillDefinition)
        .join(SkillDefinition, SkillDefinition.id == ProjectSkill.skill_id)
        .filter(ProjectSkill.project_id == project_id)
        .all()
    )
    for row, skill in rows:
        row.enabled = 1 if skill.enabled_by_default else 0
    db.commit()
    return RedirectResponse(f"/projects/{project_id}/skills", status_code=303)

@router.get("/projects/{project_id}/skills/{skill_id:int}", response_class=HTMLResponse)
def skill_detail(project_id: int, skill_id: int, request: Request, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    skill = db.get(SkillDefinition, skill_id)
    if not project or not skill:
        raise HTTPException(404)
    ensure_project_skill_rows(db, project_id)
    ps = db.query(ProjectSkill).filter(ProjectSkill.project_id == project_id, ProjectSkill.skill_id == skill_id).first()
    context = _context(db, project)
    context.update({
        "skill": skill,
        "enabled": bool(ps.enabled) if ps else False,
        "tags": json.loads(skill.tags_json or "[]"),
        "capabilities": json.loads(skill.capabilities_json or "[]"),
    })
    return templates.TemplateResponse(request=request, name="skill_detail.html", context=context)

@router.post("/projects/{project_id}/skills/apply-pack")
def apply_skill_pack(project_id: int, pack: str = Form(...), db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    if pack not in SKILL_PACKS:
        raise HTTPException(400, "Unknown Skill Pack.")
    seed_builtin_skills(db)
    ensure_project_skill_rows(db, project_id)
    skills = db.query(SkillDefinition).all()
    selected = SKILL_PACKS[pack]["skills"]
    if pack == "full-safe":
        selected = {skill.slug for skill in skills if skill.builtin and skill.enabled_by_default}
    rows = {
        row.skill_id: row
        for row in db.query(ProjectSkill).filter(ProjectSkill.project_id == project_id).all()
    }
    for skill in skills:
        row = rows.get(skill.id)
        if not row:
            continue
        # External skills are never silently enabled by a pack.
        row.enabled = 1 if (skill.builtin and skill.slug in selected) else 0
    db.commit()
    return RedirectResponse(f"/projects/{project_id}/skills?pack={pack}", status_code=303)


async def _run_skill_plan_background(project_id: int, target: str, parent_task_id: int, plan_id: int):
    db = SessionLocal()
    try:
        project = db.get(Project, project_id)
        parent = db.get(Task, parent_task_id)
        plan = db.get(SkillPlan, plan_id)
        if not project or not parent or not plan:
            return
        before = (
            db.query(AgentRun.id)
            .filter(AgentRun.project_id == project_id)
            .order_by(AgentRun.id.desc())
            .first()
        )
        before_id = before[0] if before else 0
        parent.status = "running"
        plan.status = "running"
        db.commit()
        try:
            await run_authorized_scan(db, project, target)
            latest = (
                db.query(AgentRun)
                .filter(AgentRun.project_id == project_id, AgentRun.id > before_id)
                .order_by(AgentRun.id.desc())
                .first()
            )
            parent.status = "done"
            parent.detail = f"Approved Skill Plan #{plan.id} completed."
            plan.status = "executed"
            if latest:
                plan.executed_agent_run_id = latest.id
            db.commit()
            sync_graph_from_agent_run(db, plan, latest.id if latest else None)
        except Exception as exc:
            parent.status = "error"
            parent.detail = f"{type(exc).__name__}: {exc}"
            plan.status = "error"
        db.commit()
    finally:
        db.close()


@router.get("/projects/{project_id}/skills/planner", response_class=HTMLResponse)
def skill_planner_page(
    project_id: int,
    request: Request,
    plan: int | None = None,
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    seed_builtin_skills(db)
    ensure_project_skill_rows(db, project_id)
    plans = (
        db.query(SkillPlan)
        .filter(SkillPlan.project_id == project_id)
        .order_by(SkillPlan.id.desc())
        .limit(30)
        .all()
    )
    selected = db.get(SkillPlan, plan) if plan else (plans[0] if plans else None)
    if selected and selected.project_id != project_id:
        selected = None
    payload = plan_payload(selected) if selected else {"profile": {}, "recommendations": [], "approved_skills": []}
    skill_map = {s.slug: s for s in db.query(SkillDefinition).filter(SkillDefinition.builtin == 1).all()}
    context = _context(db, project)
    context.update({
        "plans": plans,
        "selected_plan": selected,
        "plan_payload": payload,
        "planner_skill_map": skill_map,
    })
    return templates.TemplateResponse(request=request, name="skill_planner.html", context=context)




@router.get("/projects/{project_id}/execution-graph", response_class=HTMLResponse)
def execution_graph_page(
    project_id: int,
    request: Request,
    plan: int | None = None,
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    plans = (
        db.query(SkillPlan)
        .filter(SkillPlan.project_id == project_id)
        .order_by(SkillPlan.id.desc())
        .limit(30)
        .all()
    )
    selected = db.get(SkillPlan, plan) if plan else (plans[0] if plans else None)
    if selected and selected.project_id != project_id:
        selected = None
    context = _context(db, project, "execution_graph")
    context.update({
        "plans": plans,
        "selected_plan": selected,
        "graph": graph_payload(db, selected.id) if selected else {"stages": [], "node_count": 0, "status_counts": {}},
        "plan_payload": plan_payload(selected) if selected else {"profile": {}, "recommendations": [], "approved_skills": []},
    })
    return templates.TemplateResponse(request=request, name="execution_graph.html", context=context)


@router.post("/projects/{project_id}/skills/planner/generate")
async def generate_skill_plan_route(
    project_id: int,
    target: str = Form(""),
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    target = (target or "").strip()
    if target and not target_in_scope(target, [x.strip() for x in project.scope_text.splitlines() if x.strip()]):
        raise HTTPException(400, "Target is outside the project's authorized scope.")
    plan = await generate_skill_plan(db, project, target)
    return RedirectResponse(f"/projects/{project_id}/skills/planner?plan={plan.id}", status_code=303)


@router.post("/projects/{project_id}/skills/planner/{plan_id}/approve")
def approve_skill_plan_route(
    project_id: int,
    plan_id: int,
    selected_slugs: list[str] = Form(...),
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    try:
        plan = approve_skill_plan(db, project_id, plan_id, selected_slugs)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return RedirectResponse(f"/projects/{project_id}/skills/planner?plan={plan.id}&approved=1", status_code=303)


@router.post("/projects/{project_id}/skills/planner/{plan_id}/execute")
def execute_skill_plan_route(
    project_id: int,
    plan_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    plan = db.get(SkillPlan, plan_id)
    if not project or not plan or plan.project_id != project_id:
        raise HTTPException(404)
    if plan.status not in {"approved", "executed", "error"}:
        raise HTTPException(400, "Approve the Skill Plan before execution.")
    target = (plan.target or "").strip()
    if not target:
        raise HTTPException(400, "This Skill Plan has no target. Generate a plan with an in-scope target before execution.")
    if not target_in_scope(target, [x.strip() for x in project.scope_text.splitlines() if x.strip()]):
        raise HTTPException(400, "Target is outside the project's authorized scope.")

    payload = plan_payload(plan)
    approved = payload.get("approved_skills", [])
    if not approved:
        raise HTTPException(400, "The Skill Plan has no approved Skills.")
    # Re-apply the exact approved built-in selection immediately before execution.
    approve_skill_plan(db, project_id, plan_id, approved)

    parent = Task(
        project_id=project_id,
        action="project_scan",
        target=target,
        policy_class=classify_action("project_scan").value,
        status="queued",
        detail=f"Queued from approved Skill Plan #{plan_id}.",
    )
    db.add(parent)
    plan.status = "queued"
    db.commit()
    db.refresh(parent)

    background_tasks.add_task(_run_skill_plan_background, project_id, target, parent.id, plan_id)
    return RedirectResponse(f"/projects/{project_id}/skills/planner?plan={plan_id}&execution=queued", status_code=303)
