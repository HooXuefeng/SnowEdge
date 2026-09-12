from __future__ import annotations
from sqlalchemy.orm import Session
from ..models import AuthorizationCase, BrowserSession, Endpoint, Finding, FindingLifecycle, Identity, Project, StoredRequest

def suggested_next_steps(db:Session,project:Project,limit:int=6)->list[dict]:
    asset_ids=[a.id for a in project.assets] or [-1]; endpoints=db.query(Endpoint).filter(Endpoint.asset_id.in_(asset_ids)).all(); requests=db.query(StoredRequest).filter(StoredRequest.project_id==project.id).all(); identities=db.query(Identity).filter(Identity.project_id==project.id).all(); auth_cases=db.query(AuthorizationCase).filter(AuthorizationCase.project_id==project.id).all(); browsers=db.query(BrowserSession).filter(BrowserSession.project_id==project.id).all(); findings=db.query(Finding).filter(Finding.project_id==project.id).all(); lifecycles=db.query(FindingLifecycle).filter(FindingLifecycle.project_id==project.id).all(); steps=[]
    if not endpoints: steps.append({"priority":100,"kind":"discovery","title":"先建立接口资产","reason":"还没有接口记录。可以导入 HAR、Postman 或 OpenAPI，也可以通过浏览器观察收集接口。","url":f"/projects/{project.id}/imports"})
    elif len(requests)<max(1,len(endpoints)//3): steps.append({"priority":92,"kind":"request","title":"把高价值接口送入请求工作台","reason":f"已发现 {len(endpoints)} 个接口，已保存 {len(requests)} 条请求。优先整理登录后和业务关键接口。","url":f"/projects/{project.id}/requests"})
    if requests and len(identities)<2: steps.append({"priority":90,"kind":"identity","title":"建立至少两个测试身份","reason":"已有可复用请求，但身份不足，无法做高质量水平/垂直权限差异验证。","url":f"/projects/{project.id}/sessions"})
    elif requests and len(identities)>=2 and len(auth_cases)<min(len(requests),3): steps.append({"priority":96,"kind":"authorization","title":"优先做权限差异验证","reason":f"已有 {len(identities)} 个身份和 {len(requests)} 条请求，但权限案例只有 {len(auth_cases)} 个。适合使用 Authorization Matrix。","url":f"/projects/{project.id}/authorization-matrix"})
    if endpoints and not browsers: steps.append({"priority":72,"kind":"browser","title":"补一次浏览器观察","reason":"已有接口资产，还没有浏览器观察记录。登录后页面、动态请求和表单交互可能尚未覆盖。","url":f"/projects/{project.id}/browser"})
    unresolved=[f for f in findings if f.finding_state!="false_positive" and f.verification_state not in {"resolved"}]
    if unresolved: steps.append({"priority":88,"kind":"finding","title":"处理待确认/待复测漏洞","reason":f"当前有 {len(unresolved)} 个 Finding 尚未进入 resolved。优先补证据、确认状态或安排复测。","url":f"/projects/{project.id}/remediation"})
    retest_ready=[x for x in lifecycles if x.status=="retest_ready"]
    if retest_ready: steps.append({"priority":94,"kind":"retest","title":"执行已就绪复测","reason":f"{len(retest_ready)} 个漏洞已处于 retest_ready，复测比继续扩大测试面更优先。","url":f"/projects/{project.id}/remediation"})
    if endpoints and len(findings)==0: steps.append({"priority":60,"kind":"coverage","title":"查看覆盖缺口而不是盲目重复测试","reason":"已有攻击面但暂未形成 Finding。使用 Coverage 查看哪些方向还没有证据支持。","url":f"/projects/{project.id}/coverage"})
    steps.sort(key=lambda x:(-x["priority"],x["title"])); return steps[:max(1,min(limit,10))]
