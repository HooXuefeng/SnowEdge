import asyncio
import io
import json
import re
import zipfile
from unittest.mock import AsyncMock
import pytest
from fastapi.testclient import TestClient
from PIL import Image
from app.main import app
from app.db import Base,engine,SessionLocal
from app.models import Project,StoredRequest,ReplayResult,Finding,Evidence,CopilotQuery,PersistentJob,AppPreference
from app.services.workflow_context import source_context
from app.services.delivery_reports import create_snapshot,load_snapshot,export_snapshot

@pytest.fixture
def seeded():
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        p=Project(name='Delivery fixture',scope_text='example.test');db.add(p);db.flush()
        request=StoredRequest(project_id=p.id,name='Orders',url='https://example.test/orders',headers_json=json.dumps({'Authorization':'Bearer NEVER-SEND'}),body='{"password":"NEVER-SEND"}')
        db.add(request);db.flush()
        replay=ReplayResult(project_id=p.id,stored_request_id=request.id,status_code=200,response_headers_json='{"Set-Cookie":"NEVER-SEND"}',response_body='{"order":1}')
        db.add(replay)
        f=Finding(project_id=p.id,title='Original title',target=request.url,severity='high',source='analyst_manual',description='Manual steps',recommendation='Check ownership',finding_state='confirmed',verification_state='resolved')
        db.add(f);db.flush()
        e=Evidence(project_id=p.id,finding_id=f.id,kind='manual_retest',content=json.dumps({'outcome':'resolved','token':'NEVER-SEND','headers_json':json.dumps({'Authorization':'NEVER-SEND'})}))
        db.add(e);db.commit()
        return p.id,request.id,f.id,e.id

def test_focused_ai_secrets_and_project_boundary(seeded,monkeypatch):
    pid,rid,fid,eid=seeded
    from app.services import analyst_copilot as service
    provider=type('Provider',(),{})()
    provider.analyst_copilot=AsyncMock(return_value={'answer':'Observed response, still needs verification','citations':[f'request:{rid}','request:999999'],'commands':['do not execute']})
    monkeypatch.setattr(service,'get_ai_provider',lambda:provider)
    with SessionLocal() as db:
        source=source_context(db,pid,'request',rid)
        assert 'NEVER-SEND' not in json.dumps(source)
        assert source['data']['latest_response']['status_code']==200
        with pytest.raises(ValueError):source_context(db,pid+999,'request',rid)
        p=db.get(Project,pid);q=service.create_copilot_query(db,p,f'Analyze request:{rid}')
        asyncio.run(service.run_copilot_query(db,p,q))
        context=provider.analyst_copilot.await_args.args[1]
        assert context['focused_sources'][0]['ref']==f'request:{rid}'
        assert 'NEVER-SEND' not in json.dumps(context)
        result=json.loads(q.answer_json)
        assert result['citations']==[f'request:{rid}'] and result['analysis_only']
        assert 'commands' not in result

def test_tool_handoff_creates_candidate_with_evidence(seeded):
    pid,rid,_,_=seeded
    with TestClient(app) as client:
        page=client.get(f'/projects/{pid}/findings/new?source_kind=request&source_id={rid}')
        assert page.status_code==200 and 'NEVER-SEND' not in page.text
        response=client.post(f'/projects/{pid}/findings/new',data={'title':'Reviewed title','target':'https://example.test/orders','severity':'medium','description':'Analyst verified steps','source_kind':'request','source_id':rid},follow_redirects=False)
        assert response.status_code==303
        fid=int(response.headers['location'].split('/')[-1])
        with SessionLocal() as db:
            assert db.get(Finding,fid).finding_state=='candidate'
            evidence=db.query(Evidence).filter_by(finding_id=fid,kind='tool_handoff').one()
            assert f'request:{rid}' in evidence.content and evidence.content_sha256
            assert 'NEVER-SEND' not in evidence.content
        assert client.get(f'/projects/{pid+999}/workflow/request/{rid}').status_code==404

def test_analysis_uses_existing_queue_and_scan_only_creates_draft(seeded,monkeypatch):
    pid,rid,_,_=seeded
    monkeypatch.setattr('app.workflow_routes.run_job_now',lambda _:None)
    with TestClient(app) as client:
        response=client.post(f'/projects/{pid}/workflow/request/{rid}/analyze',follow_redirects=False)
        assert response.status_code==303
        qid=int(response.headers['location'].split('query_id=')[1])
        with SessionLocal() as db:
            assert db.get(CopilotQuery,qid).status=='queued'
            assert db.query(PersistentJob).filter_by(project_id=pid,kind='copilot_query').count()==1
            previous=db.query(PersistentJob).filter_by(project_id=pid).count()
        assert client.post(f'/projects/{pid}/workflow/request/{rid}/scan',follow_redirects=False).status_code==303
        with SessionLocal() as db:
            assert db.query(PersistentJob).filter_by(project_id=pid).count()==previous
            assert 'example.test/orders' in db.query(AppPreference).filter_by(key=f'scan_draft:{pid}').one().value_json

def test_delivery_frozen_images_variants_and_exports(seeded):
    pid,_,fid,_=seeded
    with TestClient(app) as client:
        image=io.BytesIO();Image.new('RGB',(40,40),'white').save(image,format='JPEG')
        assert client.post(f'/findings/{fid}/screenshots',files={'screenshot':('proof.jpg',image.getvalue(),'image/jpeg')},follow_redirects=False).status_code==303
        response=client.post(f'/projects/{pid}/reports/delivery',data={'finding_ids':str(fid),'variant':'internal','include_images':'yes'},follow_redirects=False)
        assert response.status_code==303
        sid=response.headers['location'].split('#snapshot-')[1]
        with SessionLocal() as db:
            value=load_snapshot(db,pid,sid)
            assert value['snapshot']['findings'][0]['images']
            assert 'NEVER-SEND' not in json.dumps(value)
            f=db.get(Finding,fid);f.title='Changed after delivery';db.commit()
            assert load_snapshot(db,pid,sid)['snapshot']['findings'][0]['title']=='Original title'
            with pytest.raises(ValueError):load_snapshot(db,pid+999,sid)
        word=client.get(f'/projects/{pid}/reports/delivery/{sid}/docx')
        assert word.status_code==200 and word.headers['x-snapshot-sha256']==value['sha256']
        with zipfile.ZipFile(io.BytesIO(word.content)) as bundle:
            assert b'Original title' in bundle.read('word/document.xml')
            assert any(n.startswith('word/media/') for n in bundle.namelist())
        for fmt in ('md','html'):
            output=client.get(f'/projects/{pid}/reports/delivery/{sid}/{fmt}')
            assert output.status_code==200 and 'Original title' in output.text and 'Changed after delivery' not in output.text
        assert client.get(f'/projects/{pid}/reports/delivery').status_code==200

def test_delivery_cross_project_tamper_and_client_exclusion(seeded):
    pid,_,fid,_=seeded
    with SessionLocal() as db:
        p=db.get(Project,pid)
        with pytest.raises(ValueError):create_snapshot(db,p,[fid,999999],'client')
        sid=create_snapshot(db,p,[fid],'client')
        data=load_snapshot(db,pid,sid)['snapshot']
        assert all('excerpt' not in e for e in data['findings'][0]['evidence'])
        record=db.query(AppPreference).filter_by(key=f'delivery:{pid}:{sid}').one()
        payload=json.loads(record.value_json);payload['snapshot']['project']='tampered';record.value_json=json.dumps(payload);db.commit()
        with pytest.raises(ValueError,match='完整性'):load_snapshot(db,pid,sid)
