from __future__ import annotations
from sqlalchemy import or_
from sqlalchemy.orm import Session
from ..models import Asset,Endpoint,Evidence,Finding,Identity,Project,StoredRequest,StoredRequestRevision,Task,BrowserSession
from .evidence_safety import redact_url

def _clip(v,n=150):
    v=" ".join(str(v or "").split()); return v[:n]+("…" if len(v)>n else "")

def global_search(db:Session,q:str,project_id:int|None=None,limit:int=30)->list[dict]:
    q=(q or "").strip()
    if len(q)<2:return []
    like=f"%{q}%"; rows=[]
    def add(kind,title,subtitle,url,project):
        if len(rows)<limit: rows.append({"kind":kind,"title":_clip(title,120),"subtitle":_clip(subtitle,180),"url":url,"project_id":project})
    pq=db.query(Project).filter(or_(Project.name.ilike(like),Project.client_name.ilike(like))).limit(8)
    for p in pq:add("项目",p.name,p.client_name or p.scope_text,f"/projects/{p.id}",p.id)
    fq=db.query(Finding).filter(or_(Finding.title.ilike(like),Finding.target.ilike(like),Finding.vuln_type.ilike(like),Finding.cwe_id.ilike(like),Finding.txb02_category.ilike(like)))
    if project_id:fq=fq.filter(Finding.project_id==project_id)
    for f in fq.limit(10):add("漏洞",f.title,f"{f.severity} · {redact_url(f.target)}",f"/findings/{f.id}",f.project_id)
    rq=db.query(StoredRequest).filter(or_(StoredRequest.name.ilike(like),StoredRequest.url.ilike(like)))
    if project_id:rq=rq.filter(StoredRequest.project_id==project_id)
    for r in rq.limit(10):add("请求",f"{r.method} · {r.name}",redact_url(r.url),f"/projects/{r.project_id}/requests?selected={r.id}",r.project_id)
    rvq=db.query(StoredRequestRevision).filter(or_(StoredRequestRevision.name.ilike(like),StoredRequestRevision.url.ilike(like)))
    if project_id:rvq=rvq.filter(StoredRequestRevision.project_id==project_id)
    for r in rvq.limit(6):add("请求版本",f"r{r.revision_no} · {r.method} · {r.name}",redact_url(r.url),f"/projects/{r.project_id}/requests?selected={r.stored_request_id}",r.project_id)
    eq=db.query(Endpoint,Asset.project_id).join(Asset,Endpoint.asset_id==Asset.id).filter(or_(Endpoint.url.ilike(like),Endpoint.normalized_path.ilike(like),Endpoint.method.ilike(like)))
    if project_id:eq=eq.filter(Asset.project_id==project_id)
    for e,pid in eq.limit(8):add("接口",f"{e.method} · {e.normalized_path or '/'}",redact_url(e.url),f"/projects/{pid}/endpoints",pid)
    evq=db.query(Evidence).filter(or_(Evidence.kind.ilike(like),Evidence.source_type.ilike(like)))
    if project_id:evq=evq.filter(Evidence.project_id==project_id)
    for e in evq.limit(6):add("证据",f"Evidence #{e.id} · {e.kind}",f"{e.source_type or 'source'} · SHA256 {(e.content_sha256 or '')[:12]}…",f"/projects/{e.project_id}/evidence",e.project_id)
    iq=db.query(Identity).filter(or_(Identity.name.ilike(like),Identity.role.ilike(like)))
    if project_id:iq=iq.filter(Identity.project_id==project_id)
    for i in iq.limit(8):add("身份",i.name,i.role,f"/projects/{i.project_id}/sessions",i.project_id)
    tq=db.query(Task).filter(or_(Task.action.ilike(like),Task.target.ilike(like)))
    if project_id:tq=tq.filter(Task.project_id==project_id)
    for t in tq.limit(6):add("任务",t.action,redact_url(t.target),f"/projects/{t.project_id}/tasks",t.project_id)
    bq=db.query(BrowserSession).filter(BrowserSession.target_url.ilike(like))
    if project_id:bq=bq.filter(BrowserSession.project_id==project_id)
    for b in bq.limit(6):add("浏览器",redact_url(b.target_url),b.status,f"/projects/{b.project_id}/browser?selected={b.id}",b.project_id)
    # Endpoint rows need project resolution through Asset relationship not modeled here; URL search still useful via requests.
    return rows[:limit]
