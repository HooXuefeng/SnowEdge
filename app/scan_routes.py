from pathlib import Path
from datetime import datetime, timezone, timedelta
import hashlib
import json
import secrets
import time
from urllib.parse import urlsplit, quote
from fastapi import APIRouter, Depends, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.responses import Response, RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from starlette.requests import Request
from .db import get_db
from .models import Project, PersistentJob, AppPreference, Evidence, NetworkRouteProfile
from .scope import target_in_scope
from .ui_i18n import configure_templates
from .services.scan_engine import parse_targets, parse_ports, STAGES, DEFAULT_PORTS, http_probe
from .services.scan_rules import import_rules, project_rules
from .services.scan_integrations import mapping_search, secret_config, save_config, pref, PROVIDERS
from .services.auto_decode import decode
from .services.job_engine import enqueue_job, add_job_event, cancel_job, retry_job
from .services.evidence_chain import ensure_evidence_integrity
from .services.finding_service import create_finding
from .services.network_routes import httpx_proxy_url, create_route_profile, active_route, route_payload
from .services.utility_tools import parse_target
from .services.evidence_safety import redact_url

router=APIRouter()
templates=configure_templates(Jinja2Templates(directory=Path(__file__).parent/'templates'))

def project_for(db,pid):
    project=db.get(Project,pid)
    if not project:raise HTTPException(404,'项目不存在')
    return project

def prepare_scan_draft(db,project,targets):
    try:normalized=parse_targets(targets,project.scope_text.splitlines())
    except ValueError as exc:raise HTTPException(400,str(exc))
    pref(db,f'scan_draft:{project.id}').value_json=json.dumps({'targets':normalized},ensure_ascii=False);db.commit()
    return RedirectResponse(f'/projects/{project.id}/scan-center',status_code=303)

@router.get('/decoder')
def decoder_page(request:Request,project_id:int|None=None,db:Session=Depends(get_db)):
    context={'active_nav':'decoder'}
    if project_id:
        from .main import _project_context
        context=_project_context(db,project_for(db,project_id),'decoder')
    return templates.TemplateResponse(request=request,name='decoder.html',context=context)

class DecodeInput(BaseModel):
    value:str=Field(min_length=1,max_length=32000)
    layers:int=Field(default=1,ge=1,le=5)

@router.post('/api/decoder')
def decoder_api(data:DecodeInput):
    return decode(data.value,data.layers)

@router.get('/projects/{pid}/scan-center')
def scan_page(pid:int,request:Request,db:Session=Depends(get_db)):
    from .main import _project_context
    project=project_for(db,pid)
    context=_project_context(db,project,'scan_center')
    draft=db.query(AppPreference).filter_by(key=f'scan_draft:{pid}').first()
    context.update(default_ports=DEFAULT_PORTS,default_targets='\n'.join(json.loads(draft.value_json).get('targets',[])) if draft else '')
    return templates.TemplateResponse(request=request,name='scan_center.html',context=context)

class ScanInput(BaseModel):
    targets:str=Field(min_length=1,max_length=32000)
    ports:str=Field(default=DEFAULT_PORTS,max_length=6000)
    stages:list[str]=Field(default=['ports','http','rules'],max_length=6)
    paths:str=Field(default='/robots.txt\n/sitemap.xml\n/api/\n/swagger.json',max_length=5000)
    prefixes:str=Field(default='www\napi\nadmin\ndev\ntest',max_length=5000)

@router.post('/api/projects/{pid}/scans')
def start_scan(pid:int,data:ScanInput,db:Session=Depends(get_db)):
    project=project_for(db,pid)
    try:
        rules=[rule.strip() for rule in project.scope_text.splitlines() if rule.strip()]
        if not rules:raise ValueError('项目尚未设置授权范围，请先到项目设置中添加范围。')
        targets=parse_targets(data.targets,rules);ports=parse_ports(data.ports)
        if not data.stages or set(data.stages)-STAGES:raise ValueError('请选择支持的扫描阶段。')
        if 'subdomains' in data.stages and httpx_proxy_url(db,pid):raise ValueError('当前项目使用代理，系统 DNS 不会静默直连。请取消子域名解析阶段或选择直连。')
        if len(targets)*len(ports)>8192:raise ValueError('单次目标与端口组合最多 8192 项，请拆分任务。')
        paths=[p.strip() for p in data.paths.splitlines() if p.strip()]
        if len(paths)>40 or any(not p.startswith('/') or p.startswith('//') or '\\' in p or '..' in p for p in paths):raise ValueError('目录路径无效或超过 40 项。')
        import re
        prefixes=[p.strip() for p in data.prefixes.splitlines() if p.strip()]
        if len(prefixes)>100 or any(not re.fullmatch('[A-Za-z0-9-]{1,63}',p) for p in prefixes):raise ValueError('子域名前缀无效或超过 100 项。')
        job=enqueue_job(db,project,'scan_engine',target=targets[0],payload={'targets':targets,'ports':ports,'stages':data.stages,'paths':paths,'prefixes':prefixes},timeout_seconds=3600)
        return {'id':job.id,'status':job.status}
    except ValueError as exc:raise HTTPException(400,str(exc))

@router.get('/api/projects/{pid}/scans')
def scans(pid:int,db:Session=Depends(get_db)):
    project_for(db,pid)
    jobs=db.query(PersistentJob).filter_by(project_id=pid,kind='scan_engine').order_by(PersistentJob.id.desc()).limit(50).all()
    return [{'id':j.id,'status':j.status,'attempts':j.attempts,'error':j.error,'result':json.loads(j.result_json),'total':len(json.loads(j.payload_json).get('targets',[]))} for j in jobs]

@router.post('/api/projects/{pid}/scans/{jid}/{action}')
def control_scan(pid:int,jid:int,action:str,db:Session=Depends(get_db)):
    project=project_for(db,pid);job=db.get(PersistentJob,jid)
    if not job or job.project_id!=pid or job.kind!='scan_engine':raise HTTPException(404,'扫描任务不存在')
    try:
        if action=='pause':
            if job.status in {'queued','retry_wait'}:job.status='paused'
            elif job.status=='running':job.status='pause_requested'
            else:raise ValueError('当前状态不能暂停')
            add_job_event(db,job,'pause_requested','用户请求暂停');db.commit()
        elif action=='resume':
            if job.status!='paused':raise ValueError('任务尚未暂停完成')
            job.status='queued';job.worker_id='';job.lease_token='';job.lease_expires_at=None;job.finished_at=None;job.next_run_at=None
            add_job_event(db,job,'resumed','从最近完成的目标继续');db.commit()
        elif action=='cancel':cancel_job(db,job)
        elif action=='retry':retry_job(db,job)
        elif action=='retry-unreachable':
            if job.status not in {'done','error','cancelled'}:raise ValueError('请等待任务结束后重试未响应目标')
            targets=[i['target'] for i in json.loads(job.result_json).get('items',[]) if i.get('status')=='unreachable']
            if not targets:raise ValueError('没有未响应目标')
            payload=json.loads(job.payload_json);payload['targets']=targets
            job=enqueue_job(db,project,'scan_engine',target=targets[0],payload=payload,timeout_seconds=3600)
        else:raise ValueError('未知操作')
        return {'id':job.id,'status':job.status}
    except ValueError as exc:raise HTTPException(409,str(exc))

class RulesInput(BaseModel):
    text:str=Field(max_length=100000)

@router.post('/api/projects/{pid}/scan-rules')
def rules_save(pid:int,data:RulesInput,db:Session=Depends(get_db)):
    project_for(db,pid)
    try:rules=import_rules(data.text)
    except Exception as exc:raise HTTPException(400,'规则导入失败：'+str(exc)[:300])
    row=pref(db,f'scan_rules:{pid}');row.value_json=json.dumps(rules,ensure_ascii=False);db.commit()
    return {'count':len(rules),'note':'已替换项目自定义规则，内置规则保留。'}

@router.get('/api/projects/{pid}/scan-rules')
def rules_get(pid:int,db:Session=Depends(get_db)):
    project_for(db,pid);return project_rules(db,pid)

class MappingConfig(BaseModel):
    api_key:str=Field(max_length=1000)
    email:str=Field(default='',max_length=300)

@router.post('/api/scan-integrations/{provider}')
def mapping_config(provider:str,data:MappingConfig,db:Session=Depends(get_db)):
    if provider not in PROVIDERS:raise HTTPException(400,'未知平台')
    save_config(db,'mapping:'+provider,data.model_dump());return {'configured':bool(data.api_key)}

@router.get('/api/scan-integrations')
def mapping_status(db:Session=Depends(get_db)):
    return {name:bool(secret_config(db,'mapping:'+name).get('api_key')) for name in PROVIDERS}

class MappingQuery(BaseModel):
    provider:str
    query:str=Field(min_length=1,max_length=2000)
    page:int=Field(default=1,ge=1,le=20)

@router.post('/api/projects/{pid}/mapping-search')
async def mapping_query(pid:int,data:MappingQuery,db:Session=Depends(get_db)):
    try:return await mapping_search(db,project_for(db,pid),data.provider,data.query,data.page)
    except ValueError as exc:raise HTTPException(400,str(exc))

class ProxyInput(BaseModel):
    route_type:str
    host:str=Field(default='',max_length=240)
    port:int=Field(default=0,ge=0,le=65535)
    username:str=Field(default='',max_length=200)
    password:str=Field(default='',max_length=200)
    scope:str='project'

@router.get('/api/projects/{pid}/scan-proxy')
def proxy_status(pid:int,db:Session=Depends(get_db)):
    project=project_for(db,pid)
    return {'inherited':project.network_route_profile_id is None,'effective':route_payload(active_route(db,pid))}

@router.post('/api/projects/{pid}/scan-proxy')
def proxy_config(pid:int,data:ProxyInput,db:Session=Depends(get_db)):
    project=project_for(db,pid)
    if data.scope not in {'global','project'}:raise HTTPException(400,'代理作用范围无效')
    if data.route_type=='inherit':
        if data.scope!='project':raise HTTPException(400,'只有项目可以继承全局代理')
        project.network_route_profile_id=None;db.commit();return {'mode':'inherit'}
    try:
        row=create_route_profile(db,name=f'SnowEdge-{data.scope}-{secrets.token_hex(4)}',route_type=data.route_type,host=data.host,port=data.port,username=data.username,password=data.password)
        if data.scope=='global':pref(db,'global_network_route').value_json=json.dumps({'route_id':row.id})
        else:project.network_route_profile_id=row.id
        db.commit();return {'mode':data.scope,'route_id':row.id}
    except ValueError as exc:raise HTTPException(400,str(exc))

class CredentialInput(BaseModel):
    url:str=Field(max_length=1000)
    username:str=Field(max_length=200)
    password:str=Field(min_length=1,max_length=500)

@router.post('/api/projects/{pid}/credential-check')
async def credential_check(pid:int,data:CredentialInput,db:Session=Depends(get_db)):
    project=project_for(db,pid)
    try:parse_target(data.url)
    except ValueError as exc:raise HTTPException(400,str(exc))
    if urlsplit(data.url).query or urlsplit(data.url).fragment:raise HTTPException(400,'凭据验证地址不能包含查询参数或片段。')
    if urlsplit(data.url).scheme!='https' or not target_in_scope(data.url,project.scope_text.splitlines()):raise HTTPException(400,'凭据检查仅接受授权范围内的 HTTPS 地址。')
    proxy=httpx_proxy_url(db,pid)
    baseline=await http_probe(data.url,project.scope_text.splitlines(),proxy)
    import httpx
    result=await http_probe(data.url,project.scope_text.splitlines(),proxy,auth=httpx.BasicAuth(data.username,data.password))
    weak=len(data.password)<12 or data.password.lower() in {'password','password123','admin123','12345678'} or data.password.casefold()==data.username.casefold()
    report={'target':redact_url(data.url),'baseline_status':baseline.get('status_code'),'authenticated_status':result.get('status_code'),'connection_error':result.get('error'),
            'credential_quality':'需改善' if weak else '未发现简单格式问题',
            'accepted':baseline.get('status_code') in {401,403} and 200<=result.get('status_code',0)<300,
            'note':'仅验证提供的一组 HTTP Basic 凭据；状态变化需要人工核对。不保存凭据。'}
    row=Evidence(project_id=pid,kind='credential_check',source_type='credential_audit',content=json.dumps(report,ensure_ascii=False));db.add(row);db.commit();ensure_evidence_integrity(db,row)
    report['evidence_id']=row.id
    if weak and report['accepted']:
        finding=create_finding(db,pid,'已提供凭据的强度需改善','medium',data.url,'单组 HTTP Basic 验证出现认证状态变化，且密码格式较弱。','使用独立长密码并启用多因素认证。','credential_audit','credential_check',report,finding_state='candidate')
        row.finding_id=finding.id;db.commit();ensure_evidence_integrity(db,row);report['finding_id']=finding.id
    return report

class OobInput(BaseModel):
    callback_base:str=Field(max_length=500)
    target_template:str=Field(max_length=1000)

@router.post('/api/projects/{pid}/oob-check')
async def oob_start(pid:int,data:OobInput,db:Session=Depends(get_db)):
    project=project_for(db,pid)
    try:parse_target(data.target_template)
    except ValueError as exc:raise HTTPException(400,str(exc))
    base=urlsplit(data.callback_base)
    if base.scheme!='https' or not base.hostname or base.username or base.query or base.fragment:raise HTTPException(400,'请配置自己的 HTTPS 回调转发地址。')
    if '{{oob-url}}' not in data.target_template or not target_in_scope(data.target_template,project.scope_text.splitlines()):raise HTTPException(400,'目标必须在授权范围内并包含 {{oob-url}}。')
    token=secrets.token_urlsafe(24);digest=hashlib.sha256(token.encode()).hexdigest()
    callback=data.callback_base.rstrip('/')+'/api/oob/callback/'+token
    safe_target=redact_url(data.target_template)
    evidence=Evidence(project_id=pid,kind='oob_pending',source_type='oob',content=json.dumps({'target':safe_target,'status':'pending'},ensure_ascii=False))
    db.add(evidence);db.flush()
    row=pref(db,'oob:'+digest);row.value_json=json.dumps({'project_id':pid,'evidence_id':evidence.id,'target':safe_target,'expires':time.time()+86400,'received':False});db.commit()
    ensure_evidence_integrity(db,evidence)
    result=await http_probe(data.target_template.replace('{{oob-url}}',quote(callback,safe='')),project.scope_text.splitlines(),httpx_proxy_url(db,pid))
    return {'evidence_id':evidence.id,'request_status':result.get('status_code'),'request_error':result.get('error'),'status':'等待回调' if result.get('ok') else '请求未成功，等待回调确认','note':'需将自己的公网 HTTPS 回调路径转发到此服务；不是 Interactsh 协议。'}

@router.get('/api/projects/{pid}/oob-checks')
def oob_status(pid:int,db:Session=Depends(get_db)):
    project_for(db,pid)
    rows=db.query(Evidence).filter_by(project_id=pid,source_type='oob').order_by(Evidence.id.desc()).limit(20).all()
    cutoff=datetime.now(timezone.utc).replace(tzinfo=None)-timedelta(hours=24)
    return [{'evidence_id':r.id,'status':'已收到回调' if r.kind=='oob_received' else '已过期，未收到回调' if r.captured_at<cutoff else '等待回调（24 小时有效）','finding_id':r.finding_id} for r in rows]

@router.api_route('/api/oob/callback/{token}',methods=['GET','POST'])
def oob_callback(token:str,db:Session=Depends(get_db)):
    if len(token)>100:raise HTTPException(404)
    row=db.query(AppPreference).filter_by(key='oob:'+hashlib.sha256(token.encode()).hexdigest()).first()
    if not row:raise HTTPException(404)
    data=json.loads(row.value_json)
    if data['expires']<time.time():raise HTTPException(410)
    if not data['received']:
        project=project_for(db,data['project_id'])
        if not target_in_scope(data['target'],project.scope_text.splitlines()):raise HTTPException(403)
        evidence=db.get(Evidence,data['evidence_id']);evidence.kind='oob_received';evidence.content=json.dumps({'status':'received','target':data['target'],'time':time.time()})
        data['received']=True;row.value_json=json.dumps(data);db.commit();ensure_evidence_integrity(db,evidence)
        finding=create_finding(db,project.id,'带外回调已观察到','medium',data['target'],'收到与本次测试相关的 HTTP 回调，需要核对触发组件及业务行为。','确认回调来源，并限制不必要的服务端外连。','oob','oob_received',{'evidence_id':evidence.id},finding_state='candidate')
        evidence.finding_id=finding.id;db.commit();ensure_evidence_integrity(db,evidence)
    return Response(status_code=204)
