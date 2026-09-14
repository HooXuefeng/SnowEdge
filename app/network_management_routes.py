"""Local proxy profile lifecycle. Never silently disconnect an in-use proxy."""
import json
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from sqlalchemy.orm import Session
from .db import get_db
from .models import NetworkRouteProfile, Project, AppPreference
from .ui_i18n import configure_templates
from .services.network_routes import select_route, proxy_url_for_route
from .services.scan_engine import http_probe
from .services.scan_integrations import pref

router=APIRouter()
templates=configure_templates(Jinja2Templates(directory=Path(__file__).parent/'templates'))

def references(db, rid):
    names=[p.name for p in db.query(Project).filter_by(network_route_profile_id=rid)]
    global_row=db.query(AppPreference).filter_by(key='global_network_route').first()
    if global_row and json.loads(global_row.value_json).get('route_id')==rid:names.insert(0,'全局默认')
    return names

def page(request,db,project,message=''):
    from .main import _project_context
    rows=db.query(NetworkRouteProfile).order_by(NetworkRouteProfile.id.desc()).all()
    ctx=_project_context(db,project,'settings')
    usage={}
    for row in rows:
        item=db.query(AppPreference).filter_by(key=f'route_usage:{row.id}').first()
        usage[row.id]=json.loads(item.value_json or '{}') if item else {}
    ctx.update(routes=rows,refs={r.id:references(db,r.id) for r in rows},usage=usage,message=message)
    return templates.TemplateResponse(request=request,name='network_management.html',context=ctx)

@router.get('/projects/{pid}/network-routes/manage')
def manage(pid:int,request:Request,db:Session=Depends(get_db)):
    project=db.get(Project,pid)
    if not project:raise HTTPException(404)
    return page(request,db,project)

@router.post('/projects/{pid}/network-routes/{rid}/manage')
async def change(pid:int,rid:int,request:Request,db:Session=Depends(get_db)):
    project=db.get(Project,pid);row=db.get(NetworkRouteProfile,rid)
    if not project or not row:raise HTTPException(404)
    form=await request.form();action=str(form.get('action',''))
    try:
        if action in {'disable','delete'}:
            if references(db,rid):raise ValueError('该配置仍被项目或全局默认使用，请先切换所用配置，再禁用或删除。')
            if action=='delete':
                usage=db.query(AppPreference).filter_by(key=f'route_usage:{rid}').first()
                if usage:db.delete(usage)
                db.delete(row)
            else:row.enabled=False
            db.commit()
        elif action=='enable':row.enabled=True;db.commit()
        elif action=='select':select_route(db,project,rid)
        elif action=='test':
            if not row.enabled:raise ValueError('请先启用配置。')
            target=str(form.get('target','')).strip()
            result=await http_probe(target,project.scope_text.splitlines(),proxy_url_for_route(row),method='HEAD')
            from .models import _utcnow
            pref(db,f'route_usage:{rid}').value_json=json.dumps({'last_used':str(_utcnow()),'last_result':'连接成功' if result.get('ok') else '连接失败'})
            db.commit()
            message=f"连接成功，HTTP 状态 {result.get('status_code')}。" if result.get('ok') else '连接失败，请核对地址、授权范围和代理服务。'
            return page(request,db,project,message)
        else:raise ValueError('未知操作。')
    except ValueError as exc:return page(request,db,project,str(exc))
    return RedirectResponse(f'/projects/{pid}/network-routes/manage',status_code=303)
