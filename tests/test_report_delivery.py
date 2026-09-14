"""End-to-end delivery acceptance uses isolated test DB, never customer data."""
import io,json,re,zipfile
from pathlib import Path
import pytest
from PIL import Image,ImageDraw
from fastapi.testclient import TestClient
from app.main import app
from app.db import SessionLocal
from app.models import Project,Finding,StoredRequest,ReplayResult,Asset,Evidence,AppPreference
from app.services.delivery_reports import create_snapshot,load_snapshot
from app.delivery_routes import revision

@pytest.fixture
def client():
    with TestClient(app) as c:yield c

def setup_case(c):
    response=c.post('/projects',data={'name':'交付验收项目','scope':'example.test'},follow_redirects=False)
    assert response.status_code==303
    pid=int(response.headers['location'].split('/')[-1])
    response=c.post(f'/projects/{pid}/requests/import',data={'name':'用户信息验证','scheme':'https','raw_request':'GET /api/user?id=1001 HTTP/1.1\r\nHost: example.test\r\nCookie: session=DO-NOT-EXPORT\r\nX-Trace: acceptance\r\n\r\n','explicit_read_only':'true'},follow_redirects=False)
    assert response.status_code==303
    rid=int(response.headers['location'].split('selected=')[1])
    response=c.post(f'/projects/{pid}/findings/new',data={'title':'用户信息访问权限控制缺失','severity':'high','target':'https://example.test/api/user?id=1001','description':'经人工验证，接口未正确核对当前用户与目标资源的归属。','recommendation':'在服务端依据会话身份校验资源归属。','vuln_type':'水平越权','parameter':'id','cwe_id':'CWE-639','owasp_category':'A01:2021'},follow_redirects=False)
    assert response.status_code==303
    fid=int(response.headers['location'].split('/')[-1])
    with SessionLocal() as db:
        p=db.get(Project,pid);p.client_name='验收用客户';p.start_date='2026-09-01';p.end_date='2026-09-10';p.testers_json='["验收测试人员"]';p.authorization_note='仅限 example.test 内的授权测试。'
        f=db.get(Finding,fid);f.finding_state='confirmed'
        replay=ReplayResult(project_id=pid,stored_request_id=rid,status='done',status_code=200,request_headers_json='{"Host":"example.test","Cookie":"DO-NOT-EXPORT"}',response_headers_json='{"Content-Type":"application/json","Set-Cookie":"DO-NOT-EXPORT"}',response_body='{"id":1001,"owner":"test-user"}')
        db.add(replay);db.commit();replay_id=replay.id
        assert db.query(Asset).filter_by(project_id=pid).count()>0
        rev=revision(db,f)
    fields={'revision':rev,'title':'用户信息访问权限控制缺失','severity':'high','description':'经人工验证，接口未正确核对当前用户与目标资源的归属。','recommendation':'在服务端依据会话身份校验资源归属。','vuln_type':'水平越权','parameter':'id','cwe_id':'CWE-639','owasp_category':'A01:2021','principle':'服务端只使用请求参数定位资源，缺少对象级授权判断。','impact':'低权限用户可能读取授权范围外的其他账号信息。','verification_steps':'1. 使用基准身份发送已保存的请求。\n2. 对照另一身份的资源归属与响应。\n3. 核实响应字段与证据记录一致。','difficulty':'低','cvss':'6.5','affected_assets':'example.test 用户信息接口','references':'https://cwe.mitre.org/data/definitions/639.html','poc_request':str(rid),'poc_replay':str(replay_id),'status':'retest_ready'}
    response=c.post(f'/projects/{pid}/reports/findings/{fid}',data=fields,follow_redirects=False)
    assert response.status_code==303,response.text[:1000]
    raw='HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Trace: verification\r\n\r\n{"id":1001,"owner":"test-user"}'
    response=c.post(f'/projects/{pid}/reports/findings/{fid}/evidence',data={'kind':'http_response','caption':'已保存的验证响应','note':'人工核对资源归属与返回数据一致。','raw_response':raw},follow_redirects=False)
    assert response.status_code==303
    image=Image.new('RGB',(900,360),'white');draw=ImageDraw.Draw(image);draw.text((30,30),'SnowEdge delivery acceptance / HTTP 200 / owner: test-user',fill='black');blob=io.BytesIO();image.save(blob,format='PNG')
    response=c.post(f'/projects/{pid}/reports/findings/{fid}/evidence',data={'kind':'screenshot','caption':'接口响应与资源归属验证'},files={'file':('acceptance.png',blob.getvalue(),'image/png')},follow_redirects=False)
    assert response.status_code==303
    return pid,fid,rid,raw

def freeze(c,pid,fid,stage='initial'):
    r=c.post(f'/projects/{pid}/reports/delivery',data={'finding_ids':str(fid),'variant':'client','template':'client','stage':stage,'version':'1.0','sort':'severity','include_images':'yes','objectives':'验证用户数据的对象级访问控制。','method':'授权人工验证与请求回放','limitations':'仅验证授权的测试账号，不包含生产用户数据。','modules':'用户信息接口'},follow_redirects=False)
    assert r.status_code==303,r.text[:1000]
    return r.headers['location'].split('/')[-2]

def test_real_delivery_end_to_end(client):
    pid,fid,rid,raw=setup_case(client);sid=freeze(client,pid,fid)
    assert client.get(f'/projects/{pid}/reports/delivery/{sid}/preview').status_code==200
    assert client.get(f'/projects/{pid}/reports/delivery/{sid}/preview/pages').json()['pages']>1
    assert client.get(f'/projects/{pid}/reports/delivery/{sid}/preview/pages/1').content.startswith(b'\x89PNG')
    assert client.get(f'/projects/{pid}/reports/delivery/{sid}/preview/pages/9999').status_code==400
    out=Path('qa/report_delivery');out.mkdir(parents=True,exist_ok=True)
    for fmt in ('pdf','html','json','csv','docx'):
        response=client.get(f'/projects/{pid}/reports/delivery/{sid}/{fmt}')
        assert response.status_code==200,response.text[:1000] if fmt!='pdf' else response.content[:300]
        assert len(response.content)>100 and response.headers['content-disposition'].startswith('attachment')
        (out/f'acceptance.{fmt}').write_bytes(response.content)
        if fmt=='pdf':assert response.content.startswith(b'%PDF')
        if fmt=='docx':
            with zipfile.ZipFile(io.BytesIO(response.content)) as z:assert 'word/document.xml' in z.namelist() and any(x.startswith('word/media') for x in z.namelist())
        if fmt in ('html','json','csv'):assert 'DO-NOT-EXPORT' not in response.text
    data=client.get(f'/projects/{pid}/reports/delivery/{sid}/json').json();f=data['findings'][0]
    assert f['http'][0]['request_id']==rid and 'HTTP/1.1 200' in f['http'][0]['response']
    assert any(e['content'].get('response')==raw for e in f['evidence'] if isinstance(e['content'],dict))
    assert f['images'] and f['principle'] and data['summary']['awaiting_retest']==1
    # Retest appends evidence, keeps first report and initial evidence intact.
    r=client.post(f'/projects/{pid}/reports/findings/{fid}/evidence',data={'kind':'http_response','phase':'retest','caption':'整改后的拒绝访问响应','raw_request':'GET /api/user?id=1001 HTTP/1.1\r\nHost: example.test\r\n\r\n','raw_response':'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n','note':'整改后对照账号请求被拒绝。','conclusion':'resolved'},follow_redirects=False)
    assert r.status_code==303
    new=freeze(client,pid,fid,'retest');updated=client.get(f'/projects/{pid}/reports/delivery/{new}/json').json()
    assert updated['summary']['fixed']==1 and updated['findings'][0]['retests']
    assert client.get(f'/projects/{pid}/reports/delivery/{sid}/json').json()==data
    assert client.get(f'/projects/{pid+999}/reports/delivery/{sid}/json').status_code==404

def test_evidence_visibility_and_concurrency(client):
    pid,fid,rid,_=setup_case(client)
    with SessionLocal() as db:
        eid=db.query(Evidence).filter_by(project_id=pid,finding_id=fid,kind='http_response').first().id
    r=client.post(f'/projects/{pid}/reports/findings/{fid}/evidence/{eid}',data={'caption':'不交付的内容','order':'1','description':'内部核对','remove':'yes'},follow_redirects=False)
    assert r.status_code==303
    sid=freeze(client,pid,fid);data=client.get(f'/projects/{pid}/reports/delivery/{sid}/json').json()
    assert all(e['id']!=eid for e in data['findings'][0]['evidence'])
    assert client.post(f'/projects/{pid}/reports/findings/{fid}',data={'revision':'stale'}).status_code==409
    with SessionLocal() as db:assert db.get(Evidence,eid) is not None

def test_ai_insufficient_and_mock(client):
    pid,fid,_,_=setup_case(client)
    assert client.post(f'/projects/{pid}/reports/findings/{fid}/ai').status_code==409


def test_invalid_retest_has_no_side_effects(client):
    pid,fid,_,_=setup_case(client)
    with SessionLocal() as db:before=db.query(Evidence).filter_by(finding_id=fid).count()
    r=client.post(f'/projects/{pid}/reports/findings/{fid}/evidence',data={'kind':'note','note':'invalid','phase':'retest','conclusion':'not-valid'})
    assert r.status_code==400
    with SessionLocal() as db:assert db.query(Evidence).filter_by(finding_id=fid).count()==before


def test_ai_draft_requires_real_references_and_manual_save(client,monkeypatch):
    from app.services import analyst_copilot
    pid,fid,_,_=setup_case(client)
    class Provider:
        async def analyst_copilot(self,question,context,refs):
            return {'answer':{'title':'待核对的优化标题','severity':'high','made_up_evidence':'must be discarded'},'citations':[refs[0]],'gaps':[]}
    monkeypatch.setattr(analyst_copilot,'current_ai_provider_name',lambda:'test-provider')
    monkeypatch.setattr(analyst_copilot,'get_ai_provider',lambda:Provider())
    r=client.post(f'/projects/{pid}/reports/findings/{fid}/ai')
    assert r.status_code==200 and r.json()['review_required']
    assert 'made_up_evidence' not in r.json()['draft']
    with SessionLocal() as db:assert db.get(Finding,fid).title!='待核对的优化标题'
    class InvalidProvider:
        async def analyst_copilot(self,*args):return {'answer':{'title':'unsupported'},'citations':['evidence:999999999']}
    monkeypatch.setattr(analyst_copilot,'get_ai_provider',lambda:InvalidProvider())
    assert client.post(f'/projects/{pid}/reports/findings/{fid}/ai').status_code==400
    with SessionLocal() as db:
        f=Finding(project_id=pid,title='没有证据',severity='info',target='https://example.test',description='待验证');db.add(f);db.commit();empty=f.id
    assert client.post(f'/projects/{pid}/reports/findings/{empty}/ai').status_code==400


def test_templates_change_presentation_and_retain_snapshot(client):
    from app.services.report_render import html_report
    pid,fid,_,_=setup_case(client);sid=freeze(client,pid,fid)
    data=client.get(f'/projects/{pid}/reports/delivery/{sid}/json').json()
    full=html_report(data);data['template']='brief';brief=html_report(data)
    assert 'X-Trace: verification' in full and 'X-Trace: verification' not in brief
    assert data['findings'][0]['http']
    data['template']='retest';assert '整改与复测结论' in html_report(data)


def test_existing_screenshot_link_and_exclusion(client):
    from app.models import EvidenceAttachment
    pid,fid,_,_=setup_case(client)
    with SessionLocal() as db:
        screenshot=db.query(EvidenceAttachment).filter_by(finding_id=fid).first();source=screenshot.evidence_id
        second=Finding(project_id=pid,title='复用同一张取证截图',severity='low',target='https://example.test',description='关联已有证据');db.add(second);db.commit();second_id=second.id
    r=client.post(f'/projects/{pid}/reports/findings/{second_id}/evidence',data={'kind':'screenshot','existing_id':source,'caption':'从项目证据引用的截图','note':'引用说明'},follow_redirects=False)
    assert r.status_code==303
    sid=freeze(client,pid,second_id);data=client.get(f'/projects/{pid}/reports/delivery/{sid}/json').json()
    f=data['findings'][0]
    assert len(f['images'])==1 and f['images'][0]['evidence_id']==source
    assert '引用说明' in f['evidence'][0]['description']
    eid=f['evidence'][0]['id']
    client.post(f'/projects/{pid}/reports/findings/{second_id}/evidence/{eid}',data={'order':'1','remove':'yes'})
    sid=freeze(client,pid,second_id);data=client.get(f'/projects/{pid}/reports/delivery/{sid}/json').json()
    assert not data['findings'][0]['images']


def test_excluded_handoff_does_not_auto_export_request(client):
    from app.services import report_data as rd
    pid,fid,rid,_=setup_case(client)
    with SessionLocal() as db:
        metadata=rd.finding_meta(db,fid);metadata['requests']=[];rd.save_pref(db,f'report:finding:{fid}',metadata)
        evidence=Evidence(project_id=pid,finding_id=fid,kind='tool_handoff',content=json.dumps({'kind':'request','id':rid}));db.add(evidence);db.commit()
        assert rd.projected_finding(db,db.get(Finding,fid))['http']
        rd.save_pref(db,f'report:evidence:{evidence.id}',{'include':False});db.commit()
        assert not rd.projected_finding(db,db.get(Finding,fid))['http']
