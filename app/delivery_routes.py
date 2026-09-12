import json
import re
from pathlib import Path
from fastapi import APIRouter,Depends,HTTPException
from fastapi.responses import RedirectResponse,Response
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from sqlalchemy.orm import Session
from .db import get_db
from .models import Project,Finding,AppPreference
from .ui_i18n import configure_templates
from .services.delivery_reports import create_snapshot,load_snapshot,export_snapshot,VARIANTS

router=APIRouter()
templates=configure_templates(Jinja2Templates(directory=Path(__file__).parent/'templates'))

def view(request,db,pid,error=''):
    project=db.get(Project,pid)
    if not project:raise HTTPException(404)
    from .main import _project_context
    ctx=_project_context(db,project,'reports')
    records=db.query(AppPreference).filter(AppPreference.key.like(f'delivery:{pid}:%')).order_by(AppPreference.id.desc()).limit(30).all()
    history=[]
    for record in records:
        value=json.loads(record.value_json);snapshot=value['snapshot']
        history.append({'id':record.key.split(':')[-1],'created_at':snapshot['created_at'],'variant':VARIANTS[snapshot['variant']],'count':len(snapshot['findings']),'sha256':value['sha256'],'warnings':snapshot['warnings']})
    ctx.update(findings=db.query(Finding).filter_by(project_id=pid).order_by(Finding.id.desc()).all(),history=history,error=error,variants=VARIANTS)
    return templates.TemplateResponse(request=request,name='delivery.html',context=ctx)

@router.get('/projects/{pid}/reports/delivery')
def delivery(pid:int,request:Request,db:Session=Depends(get_db)):return view(request,db,pid)

@router.post('/projects/{pid}/reports/delivery')
async def freeze(pid:int,request:Request,db:Session=Depends(get_db)):
    project=db.get(Project,pid)
    if not project:raise HTTPException(404)
    form=await request.form()
    try:
        ids=[int(x) for x in form.getlist('finding_ids')]
        sid=create_snapshot(db,project,ids,str(form.get('variant','client')),form.get('include_images')=='yes')
    except ValueError as exc:return view(request,db,pid,str(exc))
    return RedirectResponse(f'/projects/{pid}/reports/delivery#snapshot-{sid}',status_code=303)

@router.get('/projects/{pid}/reports/delivery/{sid}/{fmt}')
def download(pid:int,sid:str,fmt:str,db:Session=Depends(get_db)):
    if not re.fullmatch('[0-9a-f]{24}',sid) or fmt not in {'md','html','docx'}:raise HTTPException(404)
    try:
        value=load_snapshot(db,pid,sid);content,mime=export_snapshot(value['snapshot'],fmt)
    except ValueError as exc:raise HTTPException(400,str(exc))
    return Response(content,media_type=mime,headers={'Content-Disposition':f'attachment; filename="SnowEdge-{sid}.{fmt}"','Cache-Control':'no-store','X-Snapshot-SHA256':value['sha256']})
