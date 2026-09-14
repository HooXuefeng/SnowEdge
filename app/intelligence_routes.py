from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.requests import Request

from .db import SessionLocal, get_db
from .ui_i18n import configure_templates
from .models import (
    AgentHandoff,
    AgentRun,
    AssessmentMemory,
    KnowledgeNode,
    Project,
    SpecialistAgentRun,
)
from .services.assessment_memory import memory_hints, memory_summary, refresh_assessment_memory
from .services.knowledge_graph import graph_payload, graph_summary, rebuild_knowledge_graph, related_nodes
from .services.multi_agent import ROLE_DEFINITIONS, ROLE_ORDER, run_specialist_team, team_summary
from .services.job_engine import enqueue_job, run_job_now

BASE_DIR = Path(__file__).resolve().parent
templates = configure_templates(Jinja2Templates(directory=BASE_DIR / "templates"))
router = APIRouter()


def _context(db: Session, project: Project, active_nav: str) -> dict:
    from .main import _project_context
    return _project_context(db, project, active_nav)


def _loads(raw: str, default):
    try:
        return json.loads(raw or "")
    except Exception:
        return default




async def _run_agent_team_background(project_id: int, parent_agent_run_id: int):
    db = SessionLocal()
    try:
        project = db.get(Project, project_id)
        if not project:
            return
        await run_specialist_team(db, project, parent_agent_run_id=parent_agent_run_id)
    finally:
        db.close()


@router.get("/projects/{project_id}/knowledge-graph", response_class=HTMLResponse)
def knowledge_graph_page(
    project_id: int,
    request: Request,
    selected: int | None = None,
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)

    if db.query(KnowledgeNode).filter(KnowledgeNode.project_id == project_id).count() == 0:
        rebuild_knowledge_graph(db, project_id)

    graph = graph_payload(db, project_id, limit=350)
    selected_data = None
    if selected:
        try:
            selected_data = related_nodes(db, project_id, selected)
        except ValueError:
            selected_data = None

    context = _context(db, project, "knowledge_graph")
    context.update({
        "graph": graph,
        "graph_summary": graph["summary"],
        "selected_graph_node": selected_data,
        "node_types": sorted(graph["summary"].get("node_counts", {}).items(), key=lambda x: (-x[1], x[0])),
        "relation_types": sorted(graph["summary"].get("relation_counts", {}).items(), key=lambda x: (-x[1], x[0]))[:20],
    })
    return templates.TemplateResponse(request=request, name="knowledge_graph.html", context=context)


@router.post("/projects/{project_id}/knowledge-graph/refresh")
def refresh_knowledge_graph(project_id: int, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    rebuild_knowledge_graph(db, project_id)
    return RedirectResponse(f"/projects/{project_id}/knowledge-graph?refreshed=1", status_code=303)


@router.get("/api/projects/{project_id}/knowledge-graph")
def knowledge_graph_api(project_id: int, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    if db.query(KnowledgeNode).filter(KnowledgeNode.project_id == project_id).count() == 0:
        rebuild_knowledge_graph(db, project_id)
    return graph_payload(db, project_id, limit=500)


@router.get("/projects/{project_id}/memory", response_class=HTMLResponse)
def assessment_memory_page(
    project_id: int,
    request: Request,
    memory_type: str = "",
    guidance: str = "",
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)

    if db.query(AssessmentMemory).filter(AssessmentMemory.project_id == project_id).count() == 0:
        refresh_assessment_memory(db, project_id)

    query = db.query(AssessmentMemory).filter(AssessmentMemory.project_id == project_id)
    if memory_type:
        query = query.filter(AssessmentMemory.memory_type == memory_type)
    if guidance:
        query = query.filter(AssessmentMemory.repeat_guidance == guidance)
    rows = query.order_by(AssessmentMemory.id.desc()).limit(500).all()

    summary = memory_summary(db, project_id)
    context = _context(db, project, "memory")
    context.update({
        "memories": rows,
        "memory_summary": summary,
        "memory_types": sorted(summary.get("by_type", {}).items()),
        "guidance_types": sorted(summary.get("by_guidance", {}).items()),
        "selected_memory_type": memory_type,
        "selected_guidance": guidance,
    })
    return templates.TemplateResponse(request=request, name="memory.html", context=context)


@router.post("/projects/{project_id}/memory/refresh")
def refresh_memory(project_id: int, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    refresh_assessment_memory(db, project_id)
    return RedirectResponse(f"/projects/{project_id}/memory?refreshed=1", status_code=303)


@router.get("/projects/{project_id}/agent-team", response_class=HTMLResponse)
def agent_team_page(
    project_id: int,
    request: Request,
    run: int | None = None,
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)

    if db.query(KnowledgeNode).filter(KnowledgeNode.project_id == project_id).count() == 0:
        rebuild_knowledge_graph(db, project_id)
    if db.query(AssessmentMemory).filter(AssessmentMemory.project_id == project_id).count() == 0:
        refresh_assessment_memory(db, project_id)

    parent = db.get(AgentRun, run) if run else None
    if parent and parent.project_id != project_id:
        parent = None
    if parent is None:
        latest_specialist = (
            db.query(SpecialistAgentRun)
            .filter(SpecialistAgentRun.project_id == project_id)
            .order_by(SpecialistAgentRun.id.desc())
            .first()
        )
        if latest_specialist and latest_specialist.parent_agent_run_id:
            parent = db.get(AgentRun, latest_specialist.parent_agent_run_id)

    team = team_summary(db, project_id, parent.id if parent else None)
    run_rows = []
    for specialist in sorted(team["runs"], key=lambda x: x.id):
        run_rows.append({
            "run": specialist,
            "contract": _loads(specialist.intent_contract_json, {}),
            "input": _loads(specialist.input_snapshot_json, {}),
            "output": _loads(specialist.output_json, {}),
            "role": ROLE_DEFINITIONS.get(specialist.role_slug, {
                "slug": specialist.role_slug,
                "name": specialist.role_name,
                "purpose": "",
                "allowed_skills": [],
                "allowed_capabilities": [],
                "handoff_targets": [],
            }),
        })

    recent_parents = (
        db.query(AgentRun)
        .filter(AgentRun.project_id == project_id, AgentRun.mission.like("Run an analysis-only specialist team%"))
        .order_by(AgentRun.id.desc())
        .limit(20)
        .all()
    )

    context = _context(db, project, "agent_team")
    context.update({
        "team_parent": parent,
        "specialist_rows": run_rows,
        "handoffs": team["handoffs"],
        "team_summary": team,
        "role_definitions": [ROLE_DEFINITIONS[slug] for slug in ROLE_ORDER],
        "recent_team_runs": recent_parents,
        "knowledge_summary": graph_summary(db, project_id),
        "memory_summary": memory_summary(db, project_id),
    })
    return templates.TemplateResponse(request=request, name="agent_team.html", context=context)


@router.post("/projects/{project_id}/agent-team/run")
def run_agent_team_route(
    project_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)

    parent = AgentRun(
        project_id=project.id,
        target=f"project:{project.id}",
        mission=(
            "Run an analysis-only specialist team over the redacted Knowledge Graph "
            "and Assessment Memory. No specialist may invoke network tools."
        ),
        stage="multi_agent_review",
        status="queued",
        summary="Specialist review queued.",
    )
    db.add(parent)
    db.commit()
    db.refresh(parent)

    job = enqueue_job(
        db,
        project,
        "agent_team",
        target=f"project:{project.id}",
        payload={"parent_agent_run_id": parent.id},
        priority=80,
        timeout_seconds=300,
        max_attempts=2,
    )
    background_tasks.add_task(run_job_now, job.id)
    return RedirectResponse(
        f"/projects/{project_id}/agent-team?run={parent.id}&job={job.id}",
        status_code=303,
    )


@router.get("/api/projects/{project_id}/agent-team/{run_id}")
def agent_team_status(project_id: int, run_id: int, db: Session = Depends(get_db)):
    parent = db.get(AgentRun, run_id)
    if not parent or parent.project_id != project_id:
        raise HTTPException(404)
    summary = team_summary(db, project_id, run_id)
    return {
        "id": parent.id,
        "status": parent.status,
        "stage": parent.stage,
        "summary": parent.summary,
        "completed": summary["completed"],
        "errors": summary["errors"],
        "drift_blocked": summary["drift_blocked"],
        "specialist_runs": len(summary["runs"]),
        "handoffs": len(summary["handoffs"]),
    }
