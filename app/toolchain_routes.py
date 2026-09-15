from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from starlette.requests import Request

from .db import get_db
from .models import Project, ToolchainRun, ToolchainStep
from .services.job_engine import enqueue_job
from .services.scan_engine import DEFAULT_PORTS, parse_ports, parse_targets
from .services.toolchain import CATALOG_BY_ID, PLANS, catalog_status, resolve_executable, save_configured_path
from .services.toolchain_workflow import create_toolchain_run, retry_toolchain_step, run_payload
from .ui_i18n import configure_templates


router = APIRouter()
templates = configure_templates(Jinja2Templates(directory=Path(__file__).parent / "templates"))


def _project(db: Session, project_id: int) -> Project:
    row = db.get(Project, project_id)
    if not row:
        raise HTTPException(404, "项目不存在。")
    return row


@router.get("/projects/{project_id}/toolchain")
def toolchain_page(project_id: int, request: Request, db: Session = Depends(get_db)):
    from .main import _project_context
    project = _project(db, project_id)
    context = _project_context(db, project, "toolchain")
    context.update(default_ports=DEFAULT_PORTS, toolchain_plans=PLANS)
    return templates.TemplateResponse(request=request, name="toolchain.html", context=context)


@router.get("/api/projects/{project_id}/toolchain")
def toolchain_status(project_id: int, db: Session = Depends(get_db)):
    _project(db, project_id)
    return catalog_status(db)


class ToolPathInput(BaseModel):
    path: str = Field(default="", max_length=2000)


@router.post("/api/projects/{project_id}/toolchain/{tool_id}/path")
def configure_tool_path(project_id: int, tool_id: str, data: ToolPathInput, db: Session = Depends(get_db)):
    _project(db, project_id)
    try:
        save_configured_path(db, tool_id, data.path)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True}


class ToolRunInput(BaseModel):
    target: str = Field(min_length=1, max_length=1200)
    ports: str = Field(default=DEFAULT_PORTS, max_length=6000)


@router.post("/api/projects/{project_id}/toolchain/{tool_id}/run")
def start_tool(project_id: int, tool_id: str, data: ToolRunInput, db: Session = Depends(get_db)):
    project = _project(db, project_id)
    tool = CATALOG_BY_ID.get(tool_id)
    if not tool:
        raise HTTPException(404, "未知工具。")
    if not resolve_executable(db, tool_id):
        raise HTTPException(400, f"未找到 {tool.name}，请先配置可执行文件路径。")
    try:
        targets = parse_targets(data.target, project.scope_text.splitlines())
        if len(targets) != 1:
            raise ValueError("单个工具任务只接受一个目标；批量目标请分别创建任务。")
        target = targets[0]
        if tool.needs_url and "://" not in target:
            target = f"https://{target}"
        ports = parse_ports(data.ports) if tool.accepts_ports else []
        job = enqueue_job(db, project, "external_tool", target=target, payload={"tool_id": tool_id, "ports": ports}, timeout_seconds=900)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"id": job.id, "status": job.status, "tool": tool_id, "target": target}


@router.post("/api/projects/{project_id}/toolchain-plans/{plan_id}/run")
def start_plan(project_id: int, plan_id: str, data: ToolRunInput, db: Session = Depends(get_db)):
    project = _project(db, project_id)
    plan = PLANS.get(plan_id)
    if not plan:
        raise HTTPException(404, "未知工具链方案。")
    try:
        targets = parse_targets(data.target, project.scope_text.splitlines())
        if len(targets) != 1:
            raise ValueError("工具链方案一次只接受一个目标。")
        source_target = targets[0]
        ports = parse_ports(data.ports)
        run, skipped = create_toolchain_run(db, project, plan_id, source_target, ports)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    payload = run_payload(db, run)
    payload.update(plan=plan_id, skipped=skipped)
    return payload


@router.get("/api/projects/{project_id}/toolchain-runs")
def list_toolchain_runs(project_id: int, db: Session = Depends(get_db)):
    _project(db, project_id)
    rows = db.query(ToolchainRun).filter_by(project_id=project_id).order_by(ToolchainRun.id.desc()).limit(30).all()
    return [run_payload(db, row) for row in rows]


@router.get("/api/projects/{project_id}/toolchain-runs/{run_id}")
def get_toolchain_run(project_id: int, run_id: int, db: Session = Depends(get_db)):
    run = db.get(ToolchainRun, run_id)
    if not run or run.project_id != project_id:
        raise HTTPException(404, "工具链运行不存在。")
    return run_payload(db, run)


@router.post("/api/projects/{project_id}/toolchain-runs/{run_id}/steps/{step_id}/retry")
def retry_toolchain_run_step(project_id: int, run_id: int, step_id: int, db: Session = Depends(get_db)):
    run, step = db.get(ToolchainRun, run_id), db.get(ToolchainStep, step_id)
    if not run or run.project_id != project_id or not step or step.run_id != run.id:
        raise HTTPException(404, "工具链步骤不存在。")
    try:
        retry_toolchain_step(db, run, step)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return run_payload(db, run)
