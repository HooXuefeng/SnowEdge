import hashlib
import hmac
import json
import secrets
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.requests import Request
from .config import settings
from .db import get_db
from .models import Project, AppPreference, PersistentJob, _utcnow
from .services.job_engine import add_job_event
from .scope import normalize_scope_rules
from .ui_i18n import configure_templates

router=APIRouter()
templates=configure_templates(Jinja2Templates(directory=Path(__file__).parent/'templates'))
FIELDS=('name','client_name','environment','start_date','end_date','authorization_note','scope_text')
def values(project):return {key:getattr(project,key) for key in FIELDS}
def digest(data):return hashlib.sha256(json.dumps(data,sort_keys=True,ensure_ascii=False).encode()).hexdigest()
def signature(pid,before,data):return hmac.new(settings.app_secret_key.encode(),f'{pid}:{digest(before)}:{digest(data)}'.encode(),hashlib.sha256).hexdigest()
def get_project(db,pid):
    project=db.get(Project,pid)
    if not project:raise HTTPException(404,'项目不存在')
    return project
def view(request,db,project,**extra):
    from .main import _project_context
    history=db.query(AppPreference).filter(AppPreference.key.like(f'project_audit:{project.id}:%')).order_by(AppPreference.id.desc()).limit(30).all()
    ctx=_project_context(db,project,'settings');ctx.update(fields=values(project),review=False,error='',history=history);ctx.update(extra)
    return templates.TemplateResponse(request=request,name='project_edit.html',context=ctx)

@router.get('/projects/{pid}/edit')
def edit_project(pid:int,request:Request,db:Session=Depends(get_db)):
    return view(request,db,get_project(db,pid))

@router.post('/projects/{pid}/edit')
async def preview_project(pid:int,request:Request,db:Session=Depends(get_db)):
    form=await request.form()
    # Serialize scope changes against SQLite queue claims, so a checked queued job
    # cannot become running between the active-job check and cancellation.
    if form.get('confirm')=='yes' and db.bind.dialect.name=='sqlite':
        db.connection().exec_driver_sql('BEGIN IMMEDIATE')
    project=get_project(db,pid)
    data={key:str(form.get(key,'')).strip() for key in FIELDS}
    try:
        limits={'name':200,'client_name':240,'environment':80,'start_date':32,'end_date':32,'authorization_note':20000,'scope_text':32000}
        if not data['name'] or not data['scope_text'] or any(len(data[key])>limit for key,limit in limits.items()):raise ValueError('请填写项目名、授权范围，并检查字段长度。')
        data['scope_text']='\n'.join(normalize_scope_rules(data['scope_text'].splitlines()))
        before=values(project)
        if form.get('confirm')=='yes':
            if not hmac.compare_digest(str(form.get('approval','')),signature(pid,before,data)):raise ValueError('项目或待提交内容已变化，请重新预览修改。')
            if data['scope_text']!=project.scope_text:
                active=db.query(PersistentJob).filter(PersistentJob.project_id==pid,PersistentJob.status.in_(['running','pause_requested','cancel_requested'])).count()
                if active:raise ValueError('请先暂停或取消运行中的任务，并等待停止完成后修改授权范围。')
                for job in db.query(PersistentJob).filter(PersistentJob.project_id==pid,PersistentJob.status.in_(['queued','retry_wait'])).all():
                    job.status='cancelled';job.finished_at=_utcnow();add_job_event(db,job,'scope_changed','授权范围修改，旧排队任务取消。')
            count=db.query(Project).filter(Project.id==pid,*[getattr(Project,key)==value for key,value in before.items()]).update(data,synchronize_session=False)
            if count!=1:db.rollback();raise ValueError('项目已被其他页面修改，请重新打开核对。')
            db.add(AppPreference(key=f'project_audit:{pid}:{secrets.token_hex(12)}',value_json=json.dumps({'at':str(_utcnow()),'before':before,'after':data,'source':'analyst'},ensure_ascii=False)))
            db.commit()
            return RedirectResponse(f'/projects/{pid}/edit?saved=1',status_code=303)
        return view(request,db,project,fields=data,before=before,approval=signature(pid,before,data),review=True)
    except ValueError as exc:return view(request,db,project,fields=data,error=str(exc))
