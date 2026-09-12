from __future__ import annotations
import json
import secrets
from pathlib import Path
from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.requests import Request
from .db import get_db
from .models import BackupRecord, EvidenceAttachment, Finding, Project, Task
from .policy import classify_action
from .services.evidence_attachments import save_attachment_annotations, save_finding_screenshot
from .services.analyst_copilot import create_copilot_query
from .services.job_engine import enqueue_job, run_job_now
from .services.personal_backup import create_project_backup
from .services.personal_diagnostics import diagnostic_snapshot
from .services.personal_settings import get_personal_settings, save_personal_settings
from .services.project_templates import PROJECT_TEMPLATES, apply_project_template, normalize_quick_target, template_list
from .ui_i18n import configure_templates
BASE_DIR=Path(__file__).resolve().parent; templates=configure_templates(Jinja2Templates(directory=BASE_DIR/"templates")); router=APIRouter()
def _project_context(db,project,active_nav):
    from .main import _project_context as context
    return context(db,project,active_nav)

@router.get("/setup",response_class=HTMLResponse)
def setup_page(request:Request,db:Session=Depends(get_db)):
    prefs=get_personal_settings(db); return templates.TemplateResponse(request=request,name="setup.html",context={"active_nav":"setup","preferences":prefs,"templates_list":template_list()})

@router.post("/setup")
def save_setup(
    default_template:str=Form("web-api"), backup_enabled:str=Form(""),
    backup_interval_hours:int=Form(24), backup_retention:int=Form(7),
    backup_dir:str=Form("./backups"), browser_path:str=Form(""), nmap_path:str=Form(""),
    ai_provider:str=Form("mock"), ai_api_base:str=Form(""), ai_model:str=Form(""),
    ai_api_key:str=Form(""), burp_ingest_token:str=Form(""),
    db:Session=Depends(get_db),
):
    if default_template not in PROJECT_TEMPLATES: raise HTTPException(400,"未知项目模板。")
    if ai_provider not in {"mock","openai_compatible"}: raise HTTPException(400,"未知 AI Provider。")
    save_personal_settings(
        db,
        {"setup_completed":True,"default_template":default_template,"backup_enabled":backup_enabled=="on","backup_interval_hours":max(1,min(int(backup_interval_hours),720)),"backup_retention":max(1,min(int(backup_retention),100)),"backup_dir":backup_dir.strip() or "./backups","browser_path":browser_path.strip(),"nmap_path":nmap_path.strip(),"ai_provider":ai_provider,"ai_api_base":ai_api_base.strip(),"ai_model":ai_model.strip()},
        ai_api_key=ai_api_key if ai_api_key.strip() else None,
        burp_ingest_token=burp_ingest_token if burp_ingest_token.strip() else None,
    )
    return RedirectResponse("/diagnostics?setup=1",status_code=303)

@router.post('/setup/credentials/{kind}/{action}')
def credential_action(kind:str,action:str,request:Request,db:Session=Depends(get_db)):
    if kind=='ai' and action=='clear':save_personal_settings(db,{'ai_provider':'mock'},ai_api_key='')
    elif kind=='burp' and action=='clear':save_personal_settings(db,{},burp_ingest_token='')
    elif kind=='burp' and action=='regenerate':
        token=secrets.token_urlsafe(32);save_personal_settings(db,{},burp_ingest_token=token)
        response=templates.TemplateResponse(request=request,name='credential_token.html',context={'active_nav':'setup','token':token})
        response.headers['Cache-Control']='no-store';return response
    else:raise HTTPException(400,'不支持的凭据操作')
    return RedirectResponse('/setup?cleared=1',status_code=303)

@router.post("/quick-scan")
def quick_scan(background_tasks:BackgroundTasks,target:str=Form(...),template_slug:str=Form("web-api"),project_name:str=Form(""),db:Session=Depends(get_db)):
    try: normalized_target,scope_host=normalize_quick_target(target)
    except ValueError as exc: raise HTTPException(400,str(exc))
    if template_slug not in PROJECT_TEMPLATES: template_slug="web-api"
    project=Project(name=(project_name.strip() or f"快速测试 · {scope_host}")[:200],scope_text=scope_host,template_slug=template_slug,engagement_type=PROJECT_TEMPLATES[template_slug].get("engagement_type","authorized_pentest"),status="testing",authorization_note="由个人 Quick Scan 创建。请确保目标已获得明确测试授权。")
    db.add(project);db.commit();db.refresh(project);apply_project_template(db,project.id,template_slug)
    from .scan_routes import prepare_scan_draft
    return prepare_scan_draft(db,project,normalized_target)

@router.get("/diagnostics",response_class=HTMLResponse)
def diagnostics_page(request:Request,db:Session=Depends(get_db)):
    return templates.TemplateResponse(request=request,name="diagnostics.html",context={"active_nav":"diagnostics","diagnostics":diagnostic_snapshot(db)})

@router.get("/projects/{project_id}/backups",response_class=HTMLResponse)
def backup_page(project_id:int,request:Request,db:Session=Depends(get_db)):
    project=db.get(Project,project_id)
    if not project: raise HTTPException(404)
    records=db.query(BackupRecord).filter(BackupRecord.project_id==project_id).order_by(BackupRecord.id.desc()).limit(100).all(); context=_project_context(db,project,"backups");context.update({"backup_records":records,"preferences":get_personal_settings(db)})
    return templates.TemplateResponse(request=request,name="backups.html",context=context)

@router.post("/projects/{project_id}/backups")
def create_backup_route(project_id:int,db:Session=Depends(get_db)):
    project=db.get(Project,project_id)
    if not project: raise HTTPException(404)
    try: create_project_backup(db,project,backup_type="sanitized_manual")
    except Exception as exc: raise HTTPException(500,f"备份失败：{type(exc).__name__}: {exc}")
    return RedirectResponse(f"/projects/{project_id}/backups?created=1",status_code=303)

@router.get("/projects/{project_id}/backups/{backup_id}/download")
def download_backup(project_id:int,backup_id:int,db:Session=Depends(get_db)):
    row=db.get(BackupRecord,backup_id)
    if not row or row.project_id!=project_id: raise HTTPException(404)
    path=Path(row.file_path)
    if not path.exists() or not path.is_file(): raise HTTPException(404,"备份文件不存在。")
    return FileResponse(path,media_type="application/octet-stream" if path.suffix.lower() in {".snowedgebackup", ".aipwbak"} else "application/zip",filename=path.name)

@router.post("/findings/{finding_id}/screenshots")
async def upload_finding_screenshot(finding_id:int,screenshot:UploadFile=File(...),label:str=Form("漏洞验证截图"),db:Session=Depends(get_db)):
    finding=db.get(Finding,finding_id)
    if not finding: raise HTTPException(404)
    raw=await screenshot.read(8*1024*1024+1)
    try: save_finding_screenshot(db,finding,label,screenshot.content_type or "application/octet-stream",raw)
    except ValueError as exc: raise HTTPException(400,str(exc))
    return RedirectResponse(f"/findings/{finding_id}#screenshots",status_code=303)

@router.get("/attachments/{attachment_id}")
def attachment_file(attachment_id:int,db:Session=Depends(get_db)):
    row=db.get(EvidenceAttachment,attachment_id)
    if not row: raise HTTPException(404)
    path=Path(row.file_path)
    if not path.exists() or not path.is_file(): raise HTTPException(404)
    return FileResponse(path,media_type=row.mime_type)

@router.post("/projects/{project_id}/next-steps/ai")
def ai_next_steps(project_id:int,background_tasks:BackgroundTasks,db:Session=Depends(get_db)):
    project=db.get(Project,project_id)
    if not project: raise HTTPException(404)
    question=("基于当前项目的 Knowledge Graph、Assessment Memory、Coverage、Endpoint、Request、Identity、Authorization Case、Finding 和 Retest 状态，给我按优先级列出下一步最值得人工执行的安全测试。不要生成攻击 Payload，不要要求爆破、对象 ID 枚举、破坏性操作或绕过 Scope。请说明每一步为什么值得做，以及应查看哪个现有工作台。")
    row=create_copilot_query(db,project,question);job=enqueue_job(db,project,"copilot_query",target=f"copilot:{row.id}",payload={"copilot_query_id":row.id},priority=30,timeout_seconds=180,max_attempts=1);background_tasks.add_task(run_job_now,job.id)
    return RedirectResponse(f"/projects/{project_id}/copilot?selected={row.id}",status_code=303)


@router.get("/attachments/{attachment_id}/annotate", response_class=HTMLResponse)
def annotate_attachment_page(
    attachment_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    attachment = db.get(EvidenceAttachment, attachment_id)
    if not attachment:
        raise HTTPException(404)
    finding = db.get(Finding, attachment.finding_id)
    project = db.get(Project, attachment.project_id)
    if not finding or not project:
        raise HTTPException(404)
    try:
        annotations = json.loads(attachment.annotation_json or "[]")
    except Exception:
        annotations = []
    context = _project_context(db, project, "findings")
    context.update({
        "finding": finding,
        "attachment": attachment,
        "annotations": annotations,
    })
    return templates.TemplateResponse(request=request, name="annotate_screenshot.html", context=context)


@router.post("/attachments/{attachment_id}/annotate")
def save_attachment_annotation_route(
    attachment_id: int,
    label: str = Form(...),
    annotation_json: str = Form("[]"),
    sort_order: int = Form(0),
    db: Session = Depends(get_db),
):
    attachment = db.get(EvidenceAttachment, attachment_id)
    if not attachment:
        raise HTTPException(404)
    try:
        save_attachment_annotations(
            db, attachment, label=label,
            annotation_json=annotation_json, sort_order=sort_order,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return RedirectResponse(f"/findings/{attachment.finding_id}#screenshots", status_code=303)
