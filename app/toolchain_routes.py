from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from starlette.requests import Request

from .db import get_db
from .models import Project
from .services.job_engine import enqueue_job
from .services.scan_engine import DEFAULT_PORTS, parse_ports, parse_targets
from .services.toolchain import CATALOG_BY_ID, PLANS, catalog_status, resolve_executable, save_configured_path
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
        jobs = []
        skipped = []
        for tool_id in plan["tools"]:
            tool = CATALOG_BY_ID[tool_id]
            if not resolve_executable(db, tool_id):
                skipped.append({"tool": tool_id, "reason": "未安装或未配置路径"})
                continue
            target = f"https://{source_target}" if tool.needs_url and "://" not in source_target else source_target
            payload = {"tool_id": tool_id, "ports": ports if tool.accepts_ports else [], "plan_id": plan_id}
            job = enqueue_job(db, project, "external_tool", target=target, payload=payload, timeout_seconds=900)
            jobs.append({"id": job.id, "tool": tool_id, "target": target})
        if not jobs:
            raise ValueError("该方案所需工具均未安装，请先配置至少一个工具。")
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"plan": plan_id, "name": plan["name"], "jobs": jobs, "skipped": skipped}
