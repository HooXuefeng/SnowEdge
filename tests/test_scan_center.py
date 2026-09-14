import asyncio
import base64
import json
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi.testclient import TestClient
from app.db import Base, engine, SessionLocal
from app.main import app
from app.models import Project, PersistentJob, Evidence, Finding, AppPreference
from app.services import scan_engine as scan
from app.services import job_engine as queue
from app.services.auto_decode import decode
from app.services.scan_rules import import_rules, matches
from app.services.network_routes import httpx_proxy_url


@pytest.fixture
def pid():
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        p=Project(name='扫描隔离测试',scope_text='example.test\n*.example.test\n192.0.2.0/24')
        db.add(p);db.commit()
        return p.id


@pytest.mark.parametrize('encoded,expected',[
    ('SGVsbG8=','Hello'),('%E9%9B%AA%E5%B3%B0','雪峰'),('&#x96EA;','雪'),
    (r'\u96ea\u5cf0','雪峰'),(r'\xe9\x9b\xaa','雪'),('e99baa','雪'),
    (r'\ud83d\ude00','😀'),
])
def test_decode_formats(encoded,expected):
    assert decode(encoded)['result']==expected


def test_decoder_layers_jwt_and_no_execution():
    assert decode(base64.b64encode(b'%E9%9B%AA').decode(),5)['result']=='雪'
    enc=lambda x:base64.urlsafe_b64encode(json.dumps(x).encode()).decode().rstrip('=')
    result=decode(enc({'alg':'none'})+'.'+enc({'sub':'test'})+'.unused')
    assert '未验证' in result['result']
    value="__import__('os').system('echo should-not-run')"
    assert decode(value)['result']==value
    with pytest.raises(ValueError):decode('a'*32001)


def test_nuclei_subset_preserves_case_and_path_semantics():
    template='''id: sample
info: {name: Sample, severity: low}
http:
  - method: GET
    path: ['{{BaseURL}}/status']
    matchers:
      - type: word
        words: [Ready]
'''
    rule=import_rules(template)[0]
    assert rule['path-base']=='base'
    assert not matches(rule,{'ok':True,'body':'ready'})
    rule['matchers'][0]['case-insensitive']=True
    assert matches(rule,{'ok':True,'body':'ready'})
    with pytest.raises(ValueError):import_rules(template.replace('/status','/?q={{interactsh-url}}'))
    with pytest.raises(ValueError):import_rules(template.replace('method: GET','raw: [GET /]'))
    with pytest.raises(ValueError):import_rules('a: &a [*a]')


def test_scope_ports_and_queue_controls(pid):
    assert scan.parse_ports('80,443,8000-8002')==[80,443,8000,8001,8002]
    assert scan.parse_targets('example.test:9000',['example.test'])==['https://example.test:9000']
    with pytest.raises(ValueError):scan.parse_targets('outside.test',['example.test'])
    with pytest.raises(ValueError):scan.parse_ports('1-65535')
    with TestClient(app) as client:
        base=f'/api/projects/{pid}/scans'
        assert client.post(base,json={'targets':'outside.test'}).status_code==400
        assert client.post(base,json={'targets':'example.test','stages':['credentials']}).status_code==400
        r=client.post(base,json={'targets':'example.test','stages':['http']})
        assert r.status_code==200
        jid=r.json()['id']
        assert client.post(f'{base}/{jid}/pause').json()['status']=='paused'
        assert client.post(f'{base}/{jid}/resume').json()['status']=='queued'
        assert client.post(f'{base}/{jid}/cancel').json()['status']=='cancelled'
        assert client.post(f'{base}/{jid}/retry').json()['status']=='queued'
        assert client.post(f'/api/projects/{pid+9999}/scans/{jid}/pause').status_code==404
        assert client.get('/decoder').status_code==200
        assert client.get(f'/projects/{pid}/scan-center').status_code==200


def make_job(db,pid,stages,targets=None):
    payload={'targets':targets or ['https://example.test/'],'ports':[80],'stages':stages,'paths':[],'prefixes':[]}
    p=db.get(Project,pid)
    j=queue.enqueue_job(db,p,'scan_engine',target=payload['targets'][0],payload=payload)
    j.status='running';j.worker_id='test-scan';j.lease_token='lease';j.attempts=1;db.commit()
    return p,j,payload


def test_pipeline_links_current_fingerprint_poc_evidence_finding(pid,monkeypatch):
    async def observation(url,*args,**kwargs):
        body='Active connections: 2\nserver accepts handled requests' if url.endswith('/nginx_status') else '<title>Test</title>'
        return {'ok':True,'url':url,'final_url':url,'status_code':200,'headers':{'server':'nginx/1.2'},'body':body,'title':'Test'}
    monkeypatch.setattr(scan,'http_probe',observation)
    with SessionLocal() as db:
        p,j,payload=make_job(db,pid,['http','rules'])
        result=asyncio.run(scan.run_scan(db,j,p,payload))
        assert result['cursor']==1 and result['items'][0]['http'][0]['products']==['Nginx']
        assert result['items'][0]['findings']
        evidence=db.query(Evidence).filter_by(job_id=j.id,kind='poc_check').all()
        assert evidence and all(e.parent_evidence_id and e.integrity_sha256 for e in evidence)
        hit=next(e for e in evidence if e.finding_id)
        finding=db.get(Finding,hit.finding_id)
        assert finding.project_id==pid and finding.finding_state=='candidate'
        count=len(evidence)
        again=asyncio.run(scan.run_scan(db,j,p,payload))
        assert again['cursor']==1
        assert db.query(Evidence).filter_by(job_id=j.id,kind='poc_check').count()==count


def test_scope_change_stops_next_port_chunk(pid,monkeypatch):
    calls=[]
    async def probe(host,port,proxy):
        calls.append(port)
        if port==1:
            with SessionLocal() as other:
                p=other.get(Project,pid);p.scope_text='other.test';other.commit()
        return {'port':port,'state':'closed_or_filtered'}
    monkeypatch.setattr(scan,'tcp_probe',probe)
    with SessionLocal() as db:
        p,j,payload=make_job(db,pid,['ports'],['example.test'])
        payload['ports']=list(range(1,33))
        with pytest.raises(ValueError,match='授权范围'):asyncio.run(scan.run_scan(db,j,p,payload))
    assert len(calls)==16


def test_pause_resume_checkpoint_does_not_repeat_completed_target(pid,monkeypatch):
    calls=[]
    with SessionLocal() as db:
        p,j,payload=make_job(db,pid,['http'],['https://a.example.test/','https://b.example.test/'])
        jid=j.id
    async def probe(url,*args,**kwargs):
        calls.append(url)
        if len(calls)==1:
            with SessionLocal() as other:
                j=other.get(PersistentJob,jid);j.status='pause_requested';other.commit()
        return {'ok':True,'url':url,'status_code':200,'headers':{},'body':'','title':''}
    monkeypatch.setattr(scan,'http_probe',probe)
    asyncio.run(queue.process_job(jid,'test-scan','lease'))
    with SessionLocal() as db:
        j=db.get(PersistentJob,jid)
        assert j.status=='paused' and json.loads(j.result_json)['cursor']==1
        j.status='running';db.commit()
    asyncio.run(queue.process_job(jid,'test-scan','lease'))
    with SessionLocal() as db:assert db.get(PersistentJob,jid).status=='done'
    assert calls==['https://a.example.test/','https://b.example.test/']


def test_timeout_schedules_retry_and_keeps_checkpoint(pid,monkeypatch):
    async def timed_out(*args):raise asyncio.TimeoutError()
    monkeypatch.setitem(queue.HANDLERS,'scan_engine',timed_out)
    with SessionLocal() as db:
        _,j,_=make_job(db,pid,['http']);jid=j.id
        j.result_json='{"cursor":1,"items":[]}';db.commit()
    asyncio.run(queue.process_job(jid,'test-scan','lease'))
    with SessionLocal() as db:
        j=db.get(PersistentJob,jid)
        assert j.status=='retry_wait' and json.loads(j.result_json)['cursor']==1
        assert 'timed out' in j.error


def test_project_proxy_override_and_global_inheritance(pid):
    with TestClient(app) as client:
        url=f'/api/projects/{pid}/scan-proxy'
        try:
            r=client.post(url,json={'route_type':'socks5','scope':'global','host':'::1','port':1080,'username':'u','password':'p@ss'})
            assert r.status_code==200
            with SessionLocal() as db:assert httpx_proxy_url(db,pid)=='socks5://u:p%40ss@[::1]:1080'
            assert client.post(f'/api/projects/{pid}/scans',json={'targets':'example.test','stages':['subdomains']}).status_code==400
            assert client.post(url,json={'route_type':'direct'}).status_code==200
            with SessionLocal() as db:assert httpx_proxy_url(db,pid) is None
            assert client.post(url,json={'route_type':'inherit','scope':'global'}).status_code==400
        finally:
            with SessionLocal() as db:
                db.query(AppPreference).filter_by(key='global_network_route').delete();db.commit()


def test_credential_validation_scope_and_secret_redaction(pid,monkeypatch):
    probe=AsyncMock(side_effect=[{'ok':True,'status_code':401},{'ok':True,'status_code':200}])
    monkeypatch.setattr('app.scan_routes.http_probe',probe)
    with TestClient(app) as client:
        url=f'/api/projects/{pid}/credential-check'
        for target in ['http://example.test','https://u:p@example.test','https://outside.test','https://example.test/?password=abc']:
            assert client.post(url,json={'url':target,'username':'u','password':'weak'}).status_code==400
        assert probe.await_count==0
        r=client.post(url,json={'url':'https://example.test/private','username':'private-user','password':'weakpass'})
        assert r.status_code==200 and r.json()['accepted']
        with SessionLocal() as db:
            e=db.get(Evidence,r.json()['evidence_id'])
            assert 'weakpass' not in e.content and 'private-user' not in e.content
            assert e.finding_id and e.integrity_sha256


def test_authenticated_http_requires_valid_tls(monkeypatch):
    options=[]
    original=httpx.AsyncClient
    def client(**kwargs):
        options.append(kwargs)
        kwargs['transport']=httpx.MockTransport(lambda request:httpx.Response(200,text='okay'))
        return original(**kwargs)
    monkeypatch.setattr(scan.httpx,'AsyncClient',client)
    asyncio.run(scan.http_probe('https://example.test',['example.test'],auth=httpx.BasicAuth('u','p')))
    assert options[0]['verify'] is True and options[0]['follow_redirects'] is False


@pytest.mark.parametrize('provider,payload',[
    ('fofa',{'results':[['http://example.test:8080','192.0.2.1',8080,'http','Test']]}),
    ('hunter',{'code':200,'data':{'arr':[{'url':'http://example.test:8080','port':8080,'web_title':'Test'}]}}),
    ('quake',{'code':0,'data':[{'ip':'192.0.2.1','port':8080,'service':{'name':'http'}}]}),
    ('shodan',{'matches':[{'ip_str':'192.0.2.1','port':8080,'http':{'title':'Test'}}]}),
])
def test_mapping_adapters_keep_ports_and_encrypt_keys(pid,monkeypatch,provider,payload):
    from app.services import scan_integrations as integrations
    original=httpx.AsyncClient;requests=[]
    def reply(request):requests.append(request);return httpx.Response(200,json=payload)
    def client(**kwargs):return original(**kwargs,transport=httpx.MockTransport(reply))
    monkeypatch.setattr(integrations.httpx,'AsyncClient',client)
    with SessionLocal() as db:
        integrations.save_config(db,'mapping:'+provider,{'api_key':'MAPPING-SECRET'})
        row=db.query(AppPreference).filter_by(key='mapping:'+provider).one()
        assert 'MAPPING-SECRET' not in row.secret_encrypted
        result=asyncio.run(integrations.mapping_search(db,db.get(Project,pid),provider,'test',2))
        assert result['items'][0]['in_scope'] and ':8080' in result['items'][0]['target']
        assert 'MAPPING-SECRET' not in json.dumps(result)
    assert len(requests)==1
    if provider=='quake':assert requests[0].headers['X-QuakeToken']=='MAPPING-SECRET'
    elif provider=='hunter':assert requests[0].url.params['page']=='2'


def test_oob_callback_is_correlated_expiring_and_idempotent(pid,monkeypatch):
    from urllib.parse import urlsplit,parse_qs
    calls=[]
    async def probe(url,*args):calls.append(url);return {'ok':True,'status_code':200}
    monkeypatch.setattr('app.scan_routes.http_probe',probe)
    with TestClient(app) as client:
        r=client.post(f'/api/projects/{pid}/oob-check',json={'callback_base':'https://callback.example','target_template':'https://example.test/check?url={{oob-url}}'})
        assert r.status_code==200
        callback=parse_qs(urlsplit(calls[0]).query)['url'][0]
        path=urlsplit(callback).path
        assert client.get(path).status_code==204
        assert client.get(path).status_code==204
        assert client.get('/api/oob/callback/not-a-token').status_code==404
        with SessionLocal() as db:
            evidence=db.get(Evidence,r.json()['evidence_id'])
            assert evidence.kind=='oob_received' and evidence.finding_id
            assert db.query(Finding).filter_by(project_id=pid,source='oob').count()==1


@pytest.mark.parametrize('proxy_type',['http','socks5'])
def test_proxy_handshake_never_connects_directly(monkeypatch,proxy_type):
    class Reader:
        def __init__(self):self.buffer=bytearray(b'\x05\x00\x05\x00\x00\x01\x7f\x00\x00\x01\x01\xbb')
        async def readuntil(self,separator):return b'HTTP/1.1 200 Connection established\r\n\r\n'
        async def readexactly(self,n):part=bytes(self.buffer[:n]);del self.buffer[:n];return part
    class Writer:
        def __init__(self):self.parts=[]
        def write(self,data):self.parts.append(data)
        async def drain(self):pass
        def close(self):pass
    reader=Reader();writer=Writer();connect=AsyncMock(return_value=(reader,writer))
    monkeypatch.setattr(scan.asyncio,'open_connection',connect)
    asyncio.run(scan.open_tunnel('example.test',443,f'{proxy_type}://proxy.test:8080'))
    connect.assert_awaited_once_with('proxy.test',8080)
    assert b'example.test' in b''.join(writer.parts)


def test_live_loopback_pipeline_http_and_service_detection(pid):
    async def exercise():
        async def serve(reader,writer):
            try:
                request=await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'),3)
                path=request.split(b' ')[1]
                status='200 OK' if path in {b'/',b'/nginx_status'} else '404 Not Found'
                body=b'Active connections: 1\nserver accepts handled requests' if path==b'/nginx_status' else b'<title>Local fixture</title>'
                writer.write(f'HTTP/1.1 {status}\r\nServer: nginx/1.2\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n'.encode()+body)
                await writer.drain()
            except (asyncio.IncompleteReadError,asyncio.TimeoutError):pass
            finally:writer.close();await writer.wait_closed()
        server=await asyncio.start_server(serve,'127.0.0.1',0)
        try:
            port=server.sockets[0].getsockname()[1]
            with SessionLocal() as db:
                p=db.get(Project,pid);p.scope_text='127.0.0.1';db.commit()
                p,j,payload=make_job(db,pid,['ports','http','rules'],[f'http://127.0.0.1:{port}/'])
                payload['ports']=[port]
                result=await scan.run_scan(db,j,p,payload)
                item=result['items'][0]
                assert item['status']=='done' and item['services'][0]['service']=='http'
                assert item['http'][0]['title']=='Local fixture' and item['findings']
        finally:server.close();await server.wait_closed()
    asyncio.run(exercise())


def test_scan_ai_references_cannot_cross_projects(pid):
    from app.services.analyst_copilot import build_copilot_context,resolve_citation
    with SessionLocal() as db:
        other=Project(name='Other',scope_text='other.test');db.add(other);db.flush()
        own=Evidence(project_id=pid,source_type='scan_engine',kind='scan_http',content='{"token":"PRIVATE"}')
        foreign=Evidence(project_id=other.id,source_type='scan_engine',kind='scan_http',content='{}')
        db.add_all([own,foreign]);db.commit()
        context,refs=build_copilot_context(db,db.get(Project,pid),f'scan:{own.id} scan:{foreign.id}')
        assert f'scan:{own.id}' in refs and f'scan:{foreign.id}' not in refs
        assert 'PRIVATE' not in json.dumps(context['scan_observations'])
        assert resolve_citation(db,pid,f'scan:{foreign.id}') is None
        assert f'selected={own.id}' in resolve_citation(db,pid,f'scan:{own.id}')['url']
