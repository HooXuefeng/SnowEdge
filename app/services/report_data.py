"""Delivery projection over existing Project/Finding/Evidence/Request records.
Only additional authoring and presentation metadata lives in AppPreference.
"""
import hashlib,json
from collections import Counter
from urllib.parse import urlsplit
from ..models import (AppPreference,Asset,Endpoint,StoredRequest,ReplayResult,Identity,
    AuthorizationCase,ResponseDiff,Evidence,EvidenceAttachment,FindingLifecycle,Task,Finding,_utcnow)
from .evidence_safety import redact_text,redact_object

TEMPLATES={'standard':'标准渗透测试报告','scan':'漏洞扫描报告','retest':'复测报告','brief':'简版技术报告','client':'客户正式报告'}
STAGES={'initial':'首次测试报告','retest':'复测报告','final':'最终报告'}
STATES={'open':'未修复','triaged':'未修复','remediation':'整改中','retest_ready':'待复测','resolved':'已修复','accepted_risk':'风险接受','false_positive':'误报'}
KINDS={'http_request':'HTTP Request','http_response':'HTTP Response','screenshot':'Screenshot','code':'Code Snippet','console':'Console Log','network':'Network Evidence','file':'File Evidence','note':'Manual Note','permission':'Permission Comparison'}
EXTRA_FIELDS={'principle':'漏洞原理','impact':'影响分析','verification_steps':'验证过程','difficulty':'利用难度','cvss':'CVSS','affected_assets':'影响资产','references':'参考资料'}

def read_pref(db,key,default=None):
    row=db.query(AppPreference).filter_by(key=key).first()
    return json.loads(row.value_json) if row else ({} if default is None else default)
def save_pref(db,key,value):
    row=db.query(AppPreference).filter_by(key=key).first()
    if not row:row=AppPreference(key=key);db.add(row)
    row.value_json=json.dumps(value,ensure_ascii=False)
def digest(value):return hashlib.sha256(json.dumps(value,ensure_ascii=False,sort_keys=True).encode()).hexdigest()
def finding_meta(db,fid):return read_pref(db,f'report:finding:{fid}')
def project_meta(db,pid):return read_pref(db,f'report:project:{pid}')
def presentation(db,eid):return read_pref(db,f'report:evidence:{eid}')
def safe_text(text):return redact_text(str(text or ''))[0]
def parsed(text):
    try:return json.loads(text)
    except (ValueError,TypeError):return {'note':str(text or '')}

def raw_http(text):
    # Preserve line structure and whitespace; redact only known credential values.
    original=str(text or '').replace('\r\n','\n').replace('\r','\n')
    return safe_text(original).replace('\n','\r\n')

def request_blocks(db,pid,rid,replay_id=None):
    request=db.get(StoredRequest,rid)
    if not request or request.project_id!=pid:raise ValueError('请求不属于当前项目')
    replay=db.get(ReplayResult,replay_id) if replay_id else db.query(ReplayResult).filter_by(project_id=pid,stored_request_id=rid).order_by(ReplayResult.id.desc()).first()
    if replay_id and not replay:raise ValueError('所选响应不存在')
    if replay and (replay.project_id!=pid or replay.stored_request_id!=rid):raise ValueError('响应与请求不匹配')
    original=db.query(Evidence).filter_by(project_id=pid,source_type='report_raw_request',source_id=rid).order_by(Evidence.id.desc()).first()
    url=urlsplit(request.url);path=url.path or '/'
    if url.query:path+='?'+url.query
    headers=parsed(replay.request_headers_json if replay else request.headers_json)
    if not isinstance(headers,dict):headers={}
    if not any(k.lower()=='host' for k in headers):headers={'Host':url.netloc,**headers}
    # Legacy storage does not retain wire version/header duplication. Never claim byte fidelity.
    raw=original.content if original and not replay else f'{request.method} {path} HTTP/1.1\r\n'+'\r\n'.join(f'{k}: {v}' for k,v in headers.items())+'\r\n\r\n'+request.body
    response=''
    if replay and replay.status_code is not None:
        response=f'HTTP/1.1 {replay.status_code}\r\n'+'\r\n'.join(f'{k}: {v}' for k,v in parsed(replay.response_headers_json).items())+'\r\n\r\n'+replay.response_body
    capture=db.query(Evidence).filter_by(project_id=pid,source_type='report_replay',source_id=replay.id).first() if replay else None
    captured=parsed(capture.content) if capture else {}
    if isinstance(captured,dict):
        raw=captured.get('raw_request') or raw
        response=captured.get('raw_response') or response
    source_note='已保存的回放 HTTP 记录（敏感值脱敏；响应体由 HTTP 客户端解压并按 UTF-8 展示）' if captured.get('raw_request') else ''
    if captured.get('body_truncated'):source_note+='；响应体超过保存上限，当前内容已截断。'
    identity=db.get(Identity,replay.identity_id) if replay and replay.identity_id else None
    return {'request_id':rid,'replay_id':replay.id if replay else None,'identity_id':identity.id if identity else None,'identity':identity.name if identity else '匿名 / 未记录身份','request':raw_http(raw),'response':raw_http(response),'source_note':source_note or ('导入的原始请求（敏感值脱敏）' if original and not replay else '根据已保存字段重建 HTTP 展示；历史记录未保存协议版本，HTTP/1.1 为展示格式，原始头顺序、重复头和截断前响应不能恢复；请求路径和正文来自现有请求记录，不作为历史字节级证据。')}

def evidence_rows(db,finding):
    rows=db.query(Evidence).filter_by(project_id=finding.project_id,finding_id=finding.id).all()
    result=[]
    for row in rows:
        meta=presentation(db,row.id)
        result.append({'row':row,'meta':meta,'id':row.id,'kind':meta.get('kind',row.kind),'caption':meta.get('caption',f'证据 {row.id}'),'include':meta.get('include',True),'order':meta.get('order',row.id),'phase':meta.get('phase','retest' if row.kind=='manual_retest' else 'initial'),'description':meta.get('description',''),'conclusion':meta.get('conclusion','')})
    return sorted(result,key=lambda x:(x['order'],x['id']))

def projected_finding(db,finding):
    meta=finding_meta(db,finding.id)
    life=db.query(FindingLifecycle).filter_by(project_id=finding.project_id,finding_id=finding.id).first()
    state=life.status if life else 'open'
    if finding.finding_state=='false_positive':state='false_positive'
    item={k:getattr(finding,k) for k in ('id','title','severity','target','description','recommendation','parameter','vuln_type','cwe_id','owasp_category','txb02_category','finding_state','verification_state')}
    item.update({k:meta.get(k,'') for k in EXTRA_FIELDS})
    item.update(status=state,status_label=STATES.get(state,state),created_at=str(finding.created_at),evidence=[],http=[],retests=[],images=[])
    item['affected_assets']=item['affected_assets'] or finding.target
    links=list(meta.get('requests',[]))
    # Existing handoff evidence already identifies a request. No repeated manual entry required.
    for e in evidence_rows(db,finding):
        row=e['row'];value=parsed(row.content)
        if not e['include']:continue
        if row.kind=='tool_handoff' and isinstance(value,dict) and value.get('kind')=='request':
            link={'request_id':value.get('id'),'role':'poc'}
            if link['request_id'] and not any(x.get('request_id')==link['request_id'] for x in links):links.append(link)
        source=row
        if row.parent_evidence_id:
            parent=db.get(Evidence,row.parent_evidence_id)
            if parent and parent.project_id==finding.project_id:source=parent
        from .workflow_context import structured
        value=structured(source.content,max(200000,len(source.content)+1))
        safe,_=redact_object(value)
        eitem={k:v for k,v in e.items() if k not in ('row','meta')}
        if row.parent_evidence_id and isinstance(value,dict):
            child=parsed(row.content)
            if isinstance(child,dict) and child.get('note'):eitem['description']='\n'.join(x for x in (eitem['description'],safe_text(child['note'])) if x)
        eitem.update(content=safe,sha256=hashlib.sha256(source.content.encode()).hexdigest(),created_at=str(row.created_at),source_id=source.id,task_id=source.task_id,source_type=source.source_type)
        item['evidence'].append(eitem)
        if e['phase']=='retest':item['retests'].append(eitem)
    for link in links:
        if link.get('request_id'):
            block=request_blocks(db,finding.project_id,int(link['request_id']),link.get('replay_id'))
            block.update(role=link.get('role','poc'));item['http'].append(block)
    comparisons=db.query(AuthorizationCase).filter_by(project_id=finding.project_id,finding_id=finding.id).all()
    for case in comparisons:
        compare={'case_id':case.id,'conclusion':case.classification,'confidence':case.confidence,'summary':parsed(case.summary_json),'created_at':str(case.created_at)}
        for role,rid in [('baseline',case.baseline_replay_id),('comparison',case.comparison_replay_id)]:
            if rid:compare[role]=request_blocks(db,finding.project_id,case.stored_request_id,rid)
        if case.response_diff_id:
            diff=db.get(ResponseDiff,case.response_diff_id)
            if diff and diff.project_id==finding.project_id:compare['difference']=parsed(diff.summary_json)
        item.setdefault('permission_comparisons',[]).append(compare)
    item,_=redact_object(item)
    return item

def coverage(db,project):
    assets=db.query(Asset).filter_by(project_id=project.id).all();ids=[a.id for a in assets]
    endpoints=db.query(Endpoint).filter(Endpoint.asset_id.in_(ids)).all() if ids else []
    replays=db.query(ReplayResult).filter_by(project_id=project.id,status='done').all()
    requests=db.query(StoredRequest).filter_by(project_id=project.id).all();request_map={r.id:r for r in requests}
    tested_urls={request_map[r.stored_request_id].url for r in replays if r.stored_request_id in request_map}
    tested_endpoints=[e for e in endpoints if e.url in tested_urls]
    hosts={urlsplit(u).hostname for u in tested_urls}
    tested_assets=[a for a in assets if (urlsplit(a.target).hostname or a.target.split(':')[0]) in hosts]
    cases=db.query(AuthorizationCase).filter_by(project_id=project.id).all()
    return {'assets':len(assets),'tested_assets':len(tested_assets),'endpoints':len(endpoints),'tested_endpoints':len(tested_endpoints),'identities':db.query(Identity).filter_by(project_id=project.id).count(),'permission_scenarios':len(cases),'permission_completed':sum(c.status=='done' for c in cases),'rate':round(100*len(tested_endpoints)/len(endpoints),1) if endpoints else None,'basis':'覆盖率=具有成功请求回放记录的已登记接口/已登记接口。不是漏洞检出率；扫描/人工测试未关联请求的部分不自动计入。','uncovered':[e.url for e in endpoints if e.url not in tested_urls]}

def enrich_snapshot(db,project,data,options=None):
    config={**project_meta(db,project.id),**(options or {})}
    template=config.get('template','client');stage=config.get('stage','initial')
    if template not in TEMPLATES or stage not in STAGES:raise ValueError('报告模板或阶段无效')
    data.update(schema='snowedge-delivery/2',template=template,stage=stage,report_version=config.get('version','1.0'),logo='SnowEdge',project_info={k:getattr(project,k) for k in ('name','client_name','scope_text','start_date','end_date','engagement_type','authorization_note')})
    data['project_info'].update(testers=parsed(project.testers_json),objectives=config.get('objectives',''),method=config.get('method',project.engagement_type),limitations=config.get('limitations',''),modules=config.get('modules',''))
    data['coverage']=coverage(db,project)
    for item in data['findings']:
        enriched=projected_finding(db,db.get(Finding,item['id']))
        enriched['images']=item['images'];item.update(enriched)
        if not item['verification_steps']:data['warnings'].append(f"漏洞 #{item['id']} 缺少验证过程。")
        if not item['evidence'] and not item['http']:data['warnings'].append(f"漏洞 #{item['id']} 当前 Evidence 不足以生成完整漏洞验证过程。")
    sort=config.get('sort','severity');order={int(fid):i for i,fid in enumerate(config.get('order',[]))}
    keys={'severity':lambda f:({'critical':0,'high':1,'medium':2,'low':3,'info':4}.get(f['severity'],5),f['id']),'asset':lambda f:(f['affected_assets'],f['id']),'type':lambda f:(f['vuln_type'],f['id']),'manual':lambda f:(order.get(f['id'],999999),f['id'])}
    if sort not in keys:raise ValueError('排序方式无效')
    data['findings'].sort(key=keys[sort])
    for i,item in enumerate(data['findings'],1):item['number']=f'SE-{i:03d}'
    severity=Counter(f['severity'] for f in data['findings']);states=Counter(f['status'] for f in data['findings'])
    data['summary']={'severity':dict(severity),'states':dict(states),'fixed':states['resolved'],'unfixed':sum(states[s] for s in ('open','triaged','remediation')),'awaiting_retest':states['retest_ready'],'conclusion':config.get('conclusion','') or ('存在需优先处理的高风险问题。' if severity['critical']+severity['high'] else '请结合下列发现、测试覆盖和限制评估风险；未发现高风险不等于不存在风险。')}
    data,_=redact_object(data)
    return data
