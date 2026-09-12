from __future__ import annotations

import json
import shutil
import tempfile
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.requests import Request

from .config import settings
from .db import get_db
from .models import BackupRecord, Project, SecretVaultItem, StoredRequest, WorkspaceDraft
from .services.full_backup import create_full_workspace_backup, stage_full_restore
from .services.global_search import global_search
from .services.recovery import dismiss_recovery, recovery_snapshot, resume_safe_recovery
from .services.secret_vault import create_vault_item, item_summary, purge_vault_item, rotate_vault_item
from .services.workspace_drafts import delete_draft, load_draft, save_draft
from .ui_i18n import configure_templates

BASE_DIR=Path(__file__).resolve().parent
templates=configure_templates(Jinja2Templates(directory=BASE_DIR/"templates"))
router=APIRouter()


def _context(db:Session,project:Project|None,active_nav:str)->dict:
    if project:
        from .main import _project_context
        return _project_context(db,project,active_nav)
    from .ai.factory import current_ai_provider_name
    return {"project":None,"active_nav":active_nav,"ai_provider":current_ai_provider_name(),"recovery_count":0}


def _parse_expiry(raw:str):
    raw=(raw or "").strip()
    if not raw:return None
    try:return datetime.fromisoformat(raw)
    except Exception: raise HTTPException(400,"过期时间格式无效。")


def _parse_http_identity(headers_json:str,cookies:str)->dict:
    try:
        headers=json.loads(headers_json or "{}")
        if not isinstance(headers,dict): raise ValueError
    except Exception: raise HTTPException(400,"HTTP Identity Headers 必须是 JSON Object。")
    cookie_map={}
    for part in (cookies or "").split(";"):
        if "=" in part:
            k,v=part.split("=",1);cookie_map[k.strip()]=v.strip()
    return {"headers":headers,"cookies":cookie_map}


@router.get("/vault",response_class=HTMLResponse)
def vault_page(request:Request,project_id:int|None=None,db:Session=Depends(get_db)):
    project=db.get(Project,project_id) if project_id else None
    q=db.query(SecretVaultItem).filter(SecretVaultItem.deleted==0)
    if project_id:q=q.filter((SecretVaultItem.project_id==project_id)|(SecretVaultItem.project_id.is_(None)))
    items=q.order_by(SecretVaultItem.disabled.asc(),SecretVaultItem.id.desc()).all()
    ctx=_context(db,project,"vault");ctx.update({"vault_rows":[item_summary(x) for x in items],"projects":db.query(Project).order_by(Project.id.asc()).all(),"selected_project_id":project_id})
    return templates.TemplateResponse(request=request,name="vault.html",context=ctx)


@router.post("/vault")
def create_vault_route(label:str=Form(...),secret_type:str=Form("http_identity"),project_id:str=Form(""),username:str=Form(""),
    headers_json:str=Form("{}"),cookies:str=Form(""),secret_value:str=Form(""),expires_at:str=Form(""),notes:str=Form(""),db:Session=Depends(get_db)):
    pid=int(project_id) if project_id.strip().isdigit() else None
    if pid and not db.get(Project,pid):raise HTTPException(400,"项目不存在。")
    value=_parse_http_identity(headers_json,cookies) if secret_type=="http_identity" else {"value":secret_value}
    try:create_vault_item(db,label=label,secret_type=secret_type,value=value,project_id=pid,username=username,expires_at=_parse_expiry(expires_at),notes=notes)
    except ValueError as exc:raise HTTPException(400,str(exc))
    return RedirectResponse(f"/vault?project_id={pid or ''}",status_code=303)


@router.post("/vault/{item_id}/rotate")
def rotate_vault_route(item_id:int,headers_json:str=Form("{}"),cookies:str=Form(""),secret_value:str=Form(""),db:Session=Depends(get_db)):
    item=db.get(SecretVaultItem,item_id)
    if not item or item.deleted:raise HTTPException(404)
    value=_parse_http_identity(headers_json,cookies) if item.secret_type=="http_identity" else {"value":secret_value}
    rotate_vault_item(db,item,value);return RedirectResponse(f"/vault?project_id={item.project_id or ''}",status_code=303)


@router.post("/vault/{item_id}/toggle")
def toggle_vault(item_id:int,db:Session=Depends(get_db)):
    item=db.get(SecretVaultItem,item_id)
    if not item or item.deleted:raise HTTPException(404)
    item.disabled=0 if item.disabled else 1;db.commit();return RedirectResponse(f"/vault?project_id={item.project_id or ''}",status_code=303)


@router.post("/vault/{item_id}/purge")
def purge_vault(item_id:int,db:Session=Depends(get_db)):
    item=db.get(SecretVaultItem,item_id)
    if not item:raise HTTPException(404)
    pid=item.project_id;purge_vault_item(db,item);return RedirectResponse(f"/vault?project_id={pid or ''}",status_code=303)


@router.get("/recovery",response_class=HTMLResponse)
def recovery_page(request:Request,db:Session=Depends(get_db)):
    snap=recovery_snapshot(db);return templates.TemplateResponse(request=request,name="recovery.html",context={"active_nav":"recovery","project":None,"ai_provider":"local","recovery":snap})


@router.post("/recovery/resume")
def recovery_resume(db:Session=Depends(get_db)):
    resume_safe_recovery(db);return RedirectResponse("/recovery?resumed=1",status_code=303)


@router.post("/recovery/dismiss")
def recovery_dismiss(db:Session=Depends(get_db)):
    dismiss_recovery(db);return RedirectResponse("/recovery?dismissed=1",status_code=303)


@router.get("/api/global-search")
def search_api(q:str="",project_id:int|None=None,db:Session=Depends(get_db)):
    return {"query":q,"results":global_search(db,q,project_id,40)}


@router.get("/api/projects/{project_id}/requests/{request_id}/draft")
def get_request_draft(project_id:int,request_id:int,db:Session=Depends(get_db)):
    req=db.get(StoredRequest,request_id)
    if not req or req.project_id!=project_id:raise HTTPException(404)
    return {"draft":load_draft(db,project_id,"stored_request",request_id)}


@router.post("/api/projects/{project_id}/requests/{request_id}/draft")
async def save_request_draft(project_id:int,request_id:int,request:Request,db:Session=Depends(get_db)):
    req=db.get(StoredRequest,request_id)
    if not req or req.project_id!=project_id:raise HTTPException(404)
    try:payload=await request.json()
    except Exception:raise HTTPException(400,"JSON body required.")
    allowed={k:str(payload.get(k) or "") for k in ["name","method","url","headers_text","body","change_note"]}
    row=save_draft(db,project_id,"stored_request",request_id,allowed)
    return {"ok":True,"draft_id":row.id,"updated_at":row.updated_at.isoformat() if row.updated_at else ""}


@router.delete("/api/projects/{project_id}/requests/{request_id}/draft")
def delete_request_draft(project_id:int,request_id:int,db:Session=Depends(get_db)):
    req=db.get(StoredRequest,request_id)
    if not req or req.project_id!=project_id:raise HTTPException(404)
    return {"ok":delete_draft(db,project_id,"stored_request",request_id)}


@router.post("/projects/{project_id}/backups/full")
def create_full_backup_route(project_id:int,password:str=Form(...),password_confirm:str=Form(...),db:Session=Depends(get_db)):
    project=db.get(Project,project_id)
    if not project:raise HTTPException(404)
    if password!=password_confirm:raise HTTPException(400,"两次完整备份密码不一致。")
    try:create_full_workspace_backup(db,project,password)
    except Exception as exc:raise HTTPException(400,f"完整备份失败：{exc}")
    return RedirectResponse(f"/projects/{project_id}/backups?full=1",status_code=303)


@router.post("/restore/full")
async def stage_restore_route(backup:UploadFile=File(...),password:str=Form(...),db:Session=Depends(get_db)):
    if not backup.filename or not backup.filename.lower().endswith((".snowedgebackup", ".aipwbak")):raise HTTPException(400,"请选择 SnowEdge 完整备份文件。")
    pending=Path(settings.restore_pending_dir).expanduser()
    if not pending.is_absolute():pending=Path.cwd()/pending
    pending.mkdir(parents=True,exist_ok=True)
    temp=pending/"upload.tmp.snowedgebackup"
    total=0
    with temp.open("wb") as out:
        while True:
            chunk=await backup.read(1024*1024)
            if not chunk:break
            total+=len(chunk)
            if total>4*1024*1024*1024:
                temp.unlink(missing_ok=True);raise HTTPException(400,"完整备份超过 4 GB 限制。")
            out.write(chunk)
    try:stage_full_restore(temp,password)
    except Exception as exc:
        temp.unlink(missing_ok=True);raise HTTPException(400,f"完整备份校验失败：{exc}")
    temp.unlink(missing_ok=True)
    return RedirectResponse("/recovery?restore_staged=1",status_code=303)
