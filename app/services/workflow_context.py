"""Project-bound tool output for analyst review; never executes model output."""
import json
from ..models import StoredRequest, ReplayResult, Evidence, Finding
from .evidence_safety import redact_object

MODELS={'request':StoredRequest,'evidence':Evidence,'finding':Finding}

def structured(text,limit=20000):
    def unpack(value,depth=0):
        if depth>6:return '[嵌套内容过深，未发送]'
        if isinstance(value,dict):return {k:unpack(v,depth+1) for k,v in value.items()}
        if isinstance(value,list):return [unpack(v,depth+1) for v in value]
        if isinstance(value,str) and value.lstrip().startswith(('{','[')):
            try:return unpack(json.loads(value),depth+1)
            except ValueError:pass
        return value
    try:value=json.loads(text)
    except (ValueError,TypeError):return str(text or '')[:limit]
    return unpack(value) if len(str(text))<=limit else '[结构化内容过长，未发送，请先提取必要证据]'

def source_context(db,pid,kind,source_id):
    if kind not in MODELS:raise ValueError('不支持的来源类型。')
    row=db.get(MODELS[kind],source_id)
    if not row or row.project_id!=pid:raise ValueError('当前项目中没有这条记录。')
    if kind=='request':
        replay=db.query(ReplayResult).filter_by(project_id=pid,stored_request_id=row.id).order_by(ReplayResult.id.desc()).first()
        data={'name':row.name,'method':row.method,'url':row.url,'headers':structured(row.headers_json),'body':structured(row.body,12000),
              'latest_response':{'id':replay.id,'status':replay.status,'status_code':replay.status_code,'headers':structured(replay.response_headers_json),'body':structured(replay.response_body,16000)} if replay else None}
        target=row.url;label=row.name
    elif kind=='evidence':
        data={'kind':row.kind,'content':structured(row.content),'finding_id':row.finding_id}
        linked=db.get(Finding,row.finding_id) if row.finding_id else None
        target=linked.target if linked and linked.project_id==pid else '';label=f'证据 #{row.id}'
    else:
        data={key:getattr(row,key) for key in ('title','target','severity','description','recommendation','parameter','cwe_id','txb02_category','verification_state')}
        data['evidence']=[{'ref':f'evidence:{e.id}','kind':e.kind,'content':structured(e.content,4000)} for e in db.query(Evidence).filter_by(project_id=pid,finding_id=row.id).order_by(Evidence.id.desc()).limit(8)]
        target=row.target;label=row.title
    safe,_=redact_object(data)
    safe_target,_=redact_object({'target':target})
    result,_=redact_object({'ref':f'{kind}:{row.id}','kind':kind,'id':row.id,'label':label,'target':safe_target['target'],'data':safe,'untrusted_observation':True})
    return result

def focused_sources(db,pid,question):
    import re
    result=[]
    for kind,number in list(dict.fromkeys(re.findall(r'\b(request|evidence|finding):(\d{1,12})\b',question)))[:4]:
        try:result.append(source_context(db,pid,kind,int(number)))
        except ValueError:continue
    return result

def mentions_source(question,ref):
    import re
    return bool(re.search(r'(?<![\w:])'+re.escape(ref)+r'(?!\d)',question))
