from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.requests import Request

from .db import get_db
from .ui_i18n import configure_templates
from .models import BatchAssessment, BatchAssessmentItem, PersistentJob, PersistentJobEvent, Project
from .services.job_engine import cancel_job, job_payload, resource_gate_snapshot, retry_job, worker_snapshot

BASE_DIR = Path(__file__).resolve().parent
templates = configure_templates(Jinja2Templates(directory=BASE_DIR / "templates"))
router = APIRouter()

STATUS_ZH = {
    "paused": "已暂停",
    "pause_requested": "暂停中",
    "queued": "等待执行",
    "running": "执行中",
    "retry_wait": "等待重试",
    "cancel_requested": "取消中",
    "cancelled": "已取消",
    "done": "已完成",
    "error": "失败",
}
JOB_KIND_ZH = {
    "scan_engine": "统一扫描",
    "project_scan": "项目安全评估",
    "browser_observe": "浏览器观察",
    "copilot_query": "AI 安全助手",
    "agent_team": "AI 专家团队",
    "proof_retest": "漏洞复测",
    "endpoint_sync": "接口参数同步",
    "knowledge_refresh": "知识/记忆刷新",
    "authorization_matrix": "权限矩阵验证",
    "batch_scan": "批量安全评估",
}

templates.env.filters["status_zh"] = lambda value: STATUS_ZH.get(str(value), str(value))
templates.env.filters["job_kind_zh"] = lambda value: JOB_KIND_ZH.get(str(value), str(value))



def _context(db: Session, project: Project, active_nav: str) -> dict:
    from .main import _project_context
    return _project_context(db, project, active_nav)


@router.get("/projects/{project_id}/jobs", response_class=HTMLResponse)
def jobs_page(
    project_id: int,
    request: Request,
    selected: int | None = None,
    status: str = "",
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)

    query = db.query(PersistentJob).filter(PersistentJob.project_id == project_id)
    if status:
        query = query.filter(PersistentJob.status == status)
    jobs = query.order_by(PersistentJob.id.desc()).limit(300).all()

    selected_job = db.get(PersistentJob, selected) if selected else (jobs[0] if jobs else None)
    if selected_job and selected_job.project_id != project_id:
        selected_job = None
    events = []
    if selected_job:
        events = (
            db.query(PersistentJobEvent)
            .filter(PersistentJobEvent.job_id == selected_job.id)
            .order_by(PersistentJobEvent.id.desc())
            .limit(100)
            .all()
        )

    counts = {}
    for row in db.query(PersistentJob.status).filter(PersistentJob.project_id == project_id).all():
        counts[row[0]] = counts.get(row[0], 0) + 1

    context = _context(db, project, "jobs")
    context.update({
        "jobs": jobs,
        "selected_job": selected_job,
        "selected_payload": job_payload(selected_job) if selected_job else None,
        "job_events": events,
        "job_counts": counts,
        "selected_status": status,
        "job_workers": worker_snapshot(db),
        "resource_gates": resource_gate_snapshot(db),
        "batch_runs": db.query(BatchAssessment).filter(BatchAssessment.project_id == project_id).order_by(BatchAssessment.id.desc()).limit(30).all(),
    })
    return templates.TemplateResponse(request=request, name="jobs.html", context=context)


@router.post("/projects/{project_id}/jobs/{job_id}/cancel")
def cancel_job_route(project_id: int, job_id: int, db: Session = Depends(get_db)):
    job = db.get(PersistentJob, job_id)
    if not job or job.project_id != project_id:
        raise HTTPException(404)
    cancel_job(db, job)
    return RedirectResponse(f"/projects/{project_id}/jobs?selected={job_id}", status_code=303)


@router.post("/projects/{project_id}/jobs/{job_id}/retry")
def retry_job_route(project_id: int, job_id: int, db: Session = Depends(get_db)):
    job = db.get(PersistentJob, job_id)
    if not job or job.project_id != project_id:
        raise HTTPException(404)
    try:
        retry_job(db, job)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return RedirectResponse(f"/projects/{project_id}/jobs?selected={job_id}", status_code=303)


@router.get("/api/projects/{project_id}/jobs/{job_id}")
def job_status_api(project_id: int, job_id: int, db: Session = Depends(get_db)):
    job = db.get(PersistentJob, job_id)
    if not job or job.project_id != project_id:
        raise HTTPException(404)
    return job_payload(job)
