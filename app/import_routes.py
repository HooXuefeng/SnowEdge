from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.requests import Request

from .db import get_db
from .models import ImportBatch, ImportRecord, Project
from .services.passive_imports import import_passive_file
from .ui_i18n import configure_templates

BASE_DIR = Path(__file__).resolve().parent
templates = configure_templates(Jinja2Templates(directory=BASE_DIR / "templates"))
router = APIRouter()


def _context(db: Session, project: Project, active_nav: str) -> dict:
    from .main import _project_context
    return _project_context(db, project, active_nav)


@router.get("/projects/{project_id}/imports", response_class=HTMLResponse)
def imports_page(
    project_id: int,
    request: Request,
    selected: int | None = None,
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    batches = (
        db.query(ImportBatch)
        .filter(ImportBatch.project_id == project_id)
        .order_by(ImportBatch.id.desc())
        .limit(100)
        .all()
    )
    batch = db.get(ImportBatch, selected) if selected else (batches[0] if batches else None)
    if batch and batch.project_id != project_id:
        batch = None
    records = []
    if batch:
        records = (
            db.query(ImportRecord)
            .filter(ImportRecord.batch_id == batch.id)
            .order_by(ImportRecord.id.desc())
            .limit(200)
            .all()
        )
    context = _context(db, project, "imports")
    context.update({"import_batches": batches, "selected_batch": batch, "import_records": records})
    return templates.TemplateResponse(request=request, name="imports.html", context=context)


@router.post("/projects/{project_id}/imports")
async def upload_import(
    project_id: int,
    import_type: str = Form(...),
    package: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404)
    raw = await package.read(25 * 1024 * 1024 + 1)
    try:
        batch = import_passive_file(db, project, import_type, package.filename or "upload", raw)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(400, f"Import failed: {type(exc).__name__}: {exc}")
    return RedirectResponse(f"/projects/{project_id}/imports?selected={batch.id}", status_code=303)
