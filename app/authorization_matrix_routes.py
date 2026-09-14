from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.requests import Request

from .db import get_db
from .ui_i18n import configure_templates
from .models import AuthorizationMatrixRun, Project
from .services.authorization_matrix import (
    create_matrix_run,
    compare_matrix_runs,
    matrix_run_payload,
    matrix_view,
)
from .services.job_engine import enqueue_job, run_job_now

BASE_DIR = Path(__file__).resolve().parent
templates = configure_templates(Jinja2Templates(directory=BASE_DIR / "templates"))
router = APIRouter()


CLASS_ZH = {
    "authorization_control_enforced": "权限控制已生效",
    "potential_horizontal_authorization_gap": "疑似水平越权",
    "potential_vertical_authorization_gap": "疑似垂直越权",
    "potential_unauthenticated_access": "疑似未授权访问",
    "horizontal_access_needs_review": "水平权限待复核",
    "vertical_access_needs_review": "垂直权限待复核",
    "needs_review": "待人工复核",
    "inconclusive": "结论不足",
    "error": "执行失败",
    "pending": "等待执行",
}


def _context(db: Session, project: Project, active_nav: str) -> dict:
    from .main import _project_context
    return _project_context(db, project, active_nav)


@router.get("/projects/{project_id}/authorization-matrix", response_class=HTMLResponse)
def authorization_matrix_page(
    project_id: int,
    request: Request,
    selected_run: int | None = None,
    compare_to: int | None = None,
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)

    view = matrix_view(db, project_id)
    runs = (
        db.query(AuthorizationMatrixRun)
        .filter(AuthorizationMatrixRun.project_id == project_id)
        .order_by(AuthorizationMatrixRun.id.desc())
        .limit(30)
        .all()
    )
    run = db.get(AuthorizationMatrixRun, selected_run) if selected_run else (runs[0] if runs else None)
    if run and run.project_id != project_id:
        run = None

    compare_run = db.get(AuthorizationMatrixRun, compare_to) if compare_to else None
    if compare_run and compare_run.project_id != project_id:
        compare_run = None
    comparison = compare_matrix_runs(compare_run, run) if compare_run and run else None

    context = _context(db, project, "authorization_matrix")
    context.update({
        **view,
        "matrix_runs": runs,
        "selected_matrix_run": run,
        "selected_matrix_payload": matrix_run_payload(run) if run else None,
        "matrix_comparison": comparison,
        "compare_run": compare_run,
        "class_zh": CLASS_ZH,
    })
    return templates.TemplateResponse(request=request, name="authorization_matrix.html", context=context)


@router.post("/projects/{project_id}/authorization-matrix/run")
def run_authorization_matrix(
    project_id: int,
    background_tasks: BackgroundTasks,
    stored_request_id: int = Form(...),
    baseline_identity_id: int = Form(...),
    comparison_identity_ids: list[int] = Form(default=[]),
    include_anonymous: bool = Form(False),
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    try:
        matrix = create_matrix_run(
            db,
            project,
            stored_request_id,
            baseline_identity_id,
            comparison_identity_ids,
            include_anonymous,
        )
        job = enqueue_job(
            db,
            project,
            "authorization_matrix",
            target=f"stored_request:{stored_request_id}",
            payload={"matrix_run_id": matrix.id},
            priority=45,
            timeout_seconds=300,
            max_attempts=1,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    background_tasks.add_task(run_job_now, job.id)
    return RedirectResponse(
        f"/projects/{project_id}/authorization-matrix?selected_run={matrix.id}&job={job.id}",
        status_code=303,
    )


@router.get("/api/projects/{project_id}/authorization-matrix/{matrix_id}")
def authorization_matrix_status(project_id: int, matrix_id: int, db: Session = Depends(get_db)):
    row = db.get(AuthorizationMatrixRun, matrix_id)
    if not row or row.project_id != project_id:
        raise HTTPException(404)
    return matrix_run_payload(row)
