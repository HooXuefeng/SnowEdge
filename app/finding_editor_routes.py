"""Analyst-owned finding editing with optimistic concurrency and audit history."""
import hashlib
import json
import re
import secrets
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy.orm import Session
from starlette.requests import Request

from .db import get_db
from .models import Finding, Project, Evidence, RemediationEvent, FindingLifecycle
from .scope import target_in_scope
from .ui_i18n import configure_templates
from .services.evidence_chain import ensure_evidence_integrity
from .services.evidence_safety import safe_evidence_text, redact_url
from .services.finding_states import update_finding_states
from .services.remediation import ensure_lifecycle
from .services.utility_tools import parse_target

router=APIRouter()
templates=configure_templates(Jinja2Templates(directory=Path(__file__).parent/'templates'))
FIELDS=('title','severity','target','vuln_type','description','parameter','recommendation','cwe_id','owasp_category','txb02_category')

class FindingInput(BaseModel):
    title:str=Field(min_length=1,max_length=300)
    severity:str='medium'
    target:str=Field(min_length=1,max_length=1000)
    vuln_type:str=Field(default='',max_length=160)
    description:str=Field(min_length=1,max_length=60000)
    parameter:str=Field(default='',max_length=300)
    recommendation:str=Field(default='',max_length=60000)
    cwe_id:str=Field(default='',max_length=32)
    owasp_category:str=Field(default='',max_length=80)
    txb02_category:str=Field(default='',max_length=180)

def snapshot(finding):return {key:getattr(finding,key) for key in FIELDS}
def revision(finding):return hashlib.sha256(json.dumps(snapshot(finding),sort_keys=True,ensure_ascii=False).encode()).hexdigest()

def get_finding(db,fid):
    finding=db.get(Finding,fid)
    if not finding:raise HTTPException(404,'漏洞不存在')
    return finding

def context(db,project,finding=None,data=None,error=''):
    from .main import _project_context
    result=_project_context(db,project,'findings')
    result.update(finding=finding,fields=data if data is not None else snapshot(finding) if finding else {},revision=revision(finding) if finding else '',error=error,source_kind='',source_id='')
    return result

def audit(db,finding,kind,before,after):
    lifecycle=db.query(FindingLifecycle).filter_by(finding_id=finding.id).first()
    if not lifecycle:
        lifecycle=FindingLifecycle(project_id=finding.project_id,finding_id=finding.id,status='open');db.add(lifecycle);db.flush()
    db.add(RemediationEvent(project_id=finding.project_id,finding_id=finding.id,lifecycle_id=lifecycle.id,event_type=kind,source='analyst',detail=json.dumps({'before':before,'after':after},ensure_ascii=False)))
    db.commit()

@router.get('/projects/{pid}/findings/new')
def new_page(pid:int,request:Request,source_kind:str='',source_id:int|None=None,query_id:int|None=None,db:Session=Depends(get_db)):
    project=db.get(Project,pid)
    if not project:raise HTTPException(404,'项目不存在')
    ctx=context(db,project)
    if source_kind and source_id:
        from .services.workflow_context import source_context
        try:source=source_context(db,pid,source_kind,source_id)
        except ValueError as exc:raise HTTPException(404,str(exc))
        data={'title':source['label'],'severity':'info','target':source['target'],'description':'待人工验证的线索。\n来源：'+source['ref']+'\n'+json.dumps(source['data'],ensure_ascii=False,indent=2),'recommendation':''}
        if query_id:
            from .models import CopilotQuery
            row=db.get(CopilotQuery,query_id)
            from .services.workflow_context import mentions_source
            if not row or row.project_id!=pid or row.status!='done' or not mentions_source(row.question,source['ref']):raise HTTPException(404,'研判记录不属于此来源。')
            data['description']+='\n\nAI 研判草稿（需人工核实，不代表已确认）：\n'+json.loads(row.answer_json).get('answer','')
        ctx.update(fields=data,source_kind=source_kind,source_id=source_id)
    return templates.TemplateResponse(request=request,name='finding_edit.html',context=ctx)

@router.get('/findings/{fid}/edit')
def edit_page(fid:int,request:Request,db:Session=Depends(get_db)):
    finding=get_finding(db,fid)
    return templates.TemplateResponse(request=request,name='finding_edit.html',context=context(db,db.get(Project,finding.project_id),finding))

async def save(request,db,project,finding=None):
    form=await request.form()
    linked_source=None
    source_kind=str(form.get('source_kind',''));source_id=str(form.get('source_id',''))
    if not finding and source_kind:
        from .services.workflow_context import source_context
        try:linked_source=source_context(db,project.id,source_kind,int(source_id))
        except (ValueError,TypeError) as exc:raise HTTPException(400,'来源无效或不属于当前项目。')
    values={key:str(form.get(key,'')).strip() for key in FIELDS}
    try:
        data=FindingInput(**values).model_dump()
        if data['severity'] not in {'critical','high','medium','low','info'}:raise ValueError('请选择有效风险等级。')
        if data['cwe_id'] and not re.fullmatch(r'CWE-\d{1,7}',data['cwe_id']):raise ValueError('CWE 请填写 CWE-数字，例如 CWE-79。')
        if finding is None or data['target']!=finding.target:
            parse_target(data['target'])
            if not target_in_scope(data['target'],project.scope_text.splitlines()):raise ValueError('目标不在当前项目授权范围。请先核对项目设置。')
        data['target']=redact_url(data['target'])
    except (ValidationError,ValueError) as exc:
        message='请检查必填项和字段长度。' if isinstance(exc,ValidationError) else str(exc)
        ctx=context(db,project,finding,values,message);ctx.update(revision=str(form.get('revision','')),source_kind=source_kind,source_id=source_id)
        return templates.TemplateResponse(request=request,name='finding_edit.html',context=ctx,status_code=400)
    if finding:
        before=snapshot(finding)
        if form.get('revision')!=revision(finding):
            ctx=context(db,project,finding,values,'记录已被其他页面修改。你的输入仍保留，请重新打开最新记录核对后再保存。');ctx['revision']=str(form.get('revision',''))
            return templates.TemplateResponse(request=request,name='finding_edit.html',context=ctx,status_code=409)
        ensure_lifecycle(db,finding)
        # Keep the original detection fingerprint stable: later scanner runs still deduplicate.
        query=db.query(Finding).filter(Finding.id==finding.id,*[getattr(Finding,key)==value for key,value in before.items()])
        if query.update(data,synchronize_session=False)!=1:
            db.rollback();raise HTTPException(409,'记录刚刚发生变化，请重新打开后核对。')
        db.refresh(finding)
        audit(db,finding,'finding_edited',before,data)
    else:
        finding=Finding(project_id=project.id,source='analyst_manual',fingerprint=secrets.token_hex(32),finding_state='candidate',**data)
        db.add(finding);db.flush()
        linked_evidence=None
        if linked_source:
            linked_evidence=Evidence(project_id=project.id,finding_id=finding.id,source_type='analyst',kind='tool_handoff',parent_evidence_id=linked_source['id'] if linked_source['kind']=='evidence' else None,content=json.dumps(linked_source,ensure_ascii=False),redaction_state='redacted')
            db.add(linked_evidence)
        audit(db,finding,'finding_created',{},data)
        if linked_evidence:ensure_evidence_integrity(db,linked_evidence)
    return RedirectResponse(f'/findings/{finding.id}',status_code=303)

@router.post('/projects/{pid}/findings/new')
async def create(pid:int,request:Request,db:Session=Depends(get_db)):
    project=db.get(Project,pid)
    if not project:raise HTTPException(404,'项目不存在')
    return await save(request,db,project)

@router.post('/findings/{fid}/edit')
async def edit(fid:int,request:Request,db:Session=Depends(get_db)):
    finding=get_finding(db,fid)
    return await save(request,db,db.get(Project,finding.project_id),finding)

@router.post('/findings/{fid}/manual-evidence')
async def evidence_add(fid:int,request:Request,db:Session=Depends(get_db)):
    finding=get_finding(db,fid);form=await request.form()
    note=str(form.get('note','')).strip();parent=None
    if len(note)>60000:raise HTTPException(400,'证据文字最多 60000 字符。')
    parent_id=str(form.get('evidence_id','')).strip()
    if parent_id:
        if not parent_id.isdigit():raise HTTPException(400,'证据编号必须是数字')
        parent=db.get(Evidence,int(parent_id))
        if not parent or parent.project_id!=finding.project_id:raise HTTPException(404,'当前项目中没有这条证据')
    if not note and not parent:raise HTTPException(400,'请填写证据说明或选择已有证据编号')
    content,redaction=safe_evidence_text({'note':note,'linked_evidence_id':parent.id if parent else None})
    row=Evidence(project_id=finding.project_id,finding_id=finding.id,parent_evidence_id=parent.id if parent else None,source_type='analyst',kind='manual_evidence',content=content,redaction_state=redaction)
    db.add(row);db.commit();ensure_evidence_integrity(db,row)
    audit(db,finding,'evidence_added',{}, {'evidence_id':row.id,'parent_evidence_id':row.parent_evidence_id})
    return RedirectResponse(f'/findings/{fid}#manual-workflow',status_code=303)

@router.post('/findings/{fid}/manual-retest')
async def manual_retest(fid:int,request:Request,db:Session=Depends(get_db)):
    finding=get_finding(db,fid);form=await request.form()
    outcome=str(form.get('outcome',''));note=str(form.get('note','')).strip()
    if outcome not in {'reproduced','resolved','needs_review'} or not note or len(note)>60000:raise HTTPException(400,'请选择复测结果并填写有效的复测说明')
    content,redaction=safe_evidence_text({'outcome':outcome,'note':note,'method':'manual'})
    row=Evidence(project_id=finding.project_id,finding_id=finding.id,source_type='analyst',kind='manual_retest',content=content,redaction_state=redaction)
    db.add(row);db.commit();ensure_evidence_integrity(db,row)
    update_finding_states(db,finding,verification_state=outcome,source='analyst_manual_retest')
    audit(db,finding,'manual_retest_recorded',{}, {'evidence_id':row.id,'outcome':outcome})
    return RedirectResponse(f'/findings/{fid}#manual-workflow',status_code=303)
