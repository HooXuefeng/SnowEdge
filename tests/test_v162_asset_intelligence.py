import asyncio
import json
import os
import sqlite3
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from app.db import Base, SessionLocal, engine
from app.main import app
from app.models import (
    Asset, BatchAssessmentItem, Endpoint, Evidence, FingerprintRule,
    NetworkRouteProfile, PersistentJob, Project, ProjectSkill, ScanProfile, StoredRequest,
    SkillDefinition, TechnologyFingerprint,
)
from app.services.batch_assessment import create_batch
from app.services.fingerprint_engine import refresh_project_fingerprints
from app.services.job_engine import _handle_batch_scan, resource_gate_snapshot
from app.services.network_routes import create_route_profile, httpx_proxy_url, route_payload, select_route
from app.services.request_workspace import create_stored_request, replay_request
from app.services.scan_profiles import apply_profile, capture_profile
from app.skills.registry import ensure_project_skill_rows, seed_builtin_skills


def test_v162_fingerprint_engine_detects_technology_waf_cookie_and_custom_rule():
    Base.metadata.create_all(bind=engine)
    db=SessionLocal()
    try:
        project=Project(name='V162 FP',scope_text='app.example.test')
        db.add(project);db.commit();db.refresh(project)
        asset=Asset(project_id=project.id,target='app.example.test',kind='hostname')
        db.add(asset);db.commit();db.refresh(asset)
        endpoint=Endpoint(asset_id=asset.id,url='https://app.example.test/',method='GET',status_code=200)
        db.add(endpoint);db.commit()
        body='<html><head><title>QA</title></head><body><script id="__NEXT_DATA__"></script></body></html>'
        obs={
            'ok':True,'final_url':'https://app.example.test/?ticket=FP-SECRET','status_code':200,
            'headers':{'server':'nginx/1.25.3','cf-ray':'abc123','set-cookie':'JSESSIONID=SECRET; HttpOnly','x-internal-gateway':'v2'},
            'body':body,
        }
        db.add(Evidence(project_id=project.id,kind='http_response',source_type='QA',redaction_state='clean',content=json.dumps(obs)))
        db.add(FingerprintRule(project_id=project.id,name='Internal Gateway',category='middleware',product='Internal Gateway',source='header',header_name='x-internal-gateway',pattern='v2',confidence=87,enabled=1))
        db.commit()
        summary=refresh_project_fingerprints(db,project)
        products={x.product for x in db.query(TechnologyFingerprint).filter(TechnologyFingerprint.project_id==project.id).all()}
        assert {'Nginx','Cloudflare','Next.js','Java Servlet','Internal Gateway'} <= products
        nginx=db.query(TechnologyFingerprint).filter(TechnologyFingerprint.project_id==project.id,TechnologyFingerprint.product=='Nginx').one()
        assert nginx.version=='1.25.3'
        assert 'FP-SECRET' not in nginx.evidence_summary_json
        assert '••••' in nginx.evidence_summary_json
        assert summary['fingerprints'] >= 5
    finally: db.close()


def test_v162_scan_profile_captures_and_restores_existing_safe_skill_state():
    Base.metadata.create_all(bind=engine)
    db=SessionLocal()
    try:
        project=Project(name='V162 Profile',scope_text='example.test')
        db.add(project);db.commit();db.refresh(project)
        seed_builtin_skills(db);ensure_project_skill_rows(db,project.id)
        skills=db.query(SkillDefinition).filter(SkillDefinition.builtin==1).order_by(SkillDefinition.id.asc()).limit(3).all()
        assert len(skills)>=2
        rows={r.skill_id:r for r in db.query(ProjectSkill).filter(ProjectSkill.project_id==project.id).all()}
        for row in rows.values(): row.enabled=0
        rows[skills[0].id].enabled=1;rows[skills[1].id].enabled=1;db.commit()
        profile=capture_profile(db,project,f'QA Safe Profile {project.id}','captured',batch_target_limit=7)
        for row in rows.values(): row.enabled=0
        db.commit()
        result=apply_profile(db,project,profile)
        assert set(result['enabled'])=={skills[0].slug,skills[1].slug}
        assert project.scan_profile_id==profile.id
        assert profile.batch_target_limit==7
    finally: db.close()


def test_v162_network_route_encrypts_password_and_project_selection():
    Base.metadata.create_all(bind=engine)
    db=SessionLocal()
    try:
        project=Project(name='V162 Route',scope_text='example.test')
        db.add(project);db.commit();db.refresh(project)
        route=create_route_profile(db,name=f'Burp QA {project.id}',route_type='burp',host='127.0.0.1',port=8080,username='qa',password='ROUTE-SECRET',notes='local')
        assert 'ROUTE-SECRET' not in route.secret_encrypted
        assert 'password' not in route_payload(route)
        select_route(db,project,route.id)
        proxy=httpx_proxy_url(db,project.id)
        assert proxy.startswith('http://qa:ROUTE-SECRET@127.0.0.1:8080')
        select_route(db,project,None)
        assert httpx_proxy_url(db,project.id) is None
    finally: db.close()


def test_v162_batch_filters_scope_and_executes_serialized_safe_gate(monkeypatch):
    Base.metadata.create_all(bind=engine)
    calls=[]
    async def fake_run(db,project,target):
        calls.append(target)
    monkeypatch.setattr('app.orchestrator.run_authorized_scan',fake_run)
    db=SessionLocal()
    try:
        project=Project(name='V162 Batch',scope_text='a.example.test\nb.example.test')
        db.add(project);db.commit();db.refresh(project)
        seed_builtin_skills(db);ensure_project_skill_rows(db,project.id)
        skills=db.query(SkillDefinition).filter(SkillDefinition.builtin==1).order_by(SkillDefinition.id.asc()).limit(2).all()
        rows={r.skill_id:r for r in db.query(ProjectSkill).filter(ProjectSkill.project_id==project.id).all()}
        for row in rows.values(): row.enabled=0
        rows[skills[0].id].enabled=1;db.commit()
        profile=capture_profile(db,project,f'Batch Bound Profile {project.id}','batch binding',batch_target_limit=5)
        batch=create_batch(db,project,'QA Batch','https://a.example.test\nhttps://b.example.test\nhttps://outside.example.test',profile)
        assert batch.total_targets==3 and batch.skipped_targets==1 and batch.max_parallel==1
        # Simulate unrelated project skill changes while the Batch is queued.
        for row in rows.values(): row.enabled=0
        rows[skills[1].id].enabled=1;db.commit()
        job=PersistentJob(project_id=project.id,kind='batch_scan',target=f'batch:{batch.id}',payload_json=json.dumps({'batch_id':batch.id}),scope_snapshot_json='[]',scope_hash='x',status='running')
        db.add(job);db.commit();db.refresh(job)
        result=asyncio.run(_handle_batch_scan(db,job,project,{'batch_id':batch.id}))
        assert result['completed']==2 and result['failed']==0 and result['skipped']==1
        assert calls==['https://a.example.test','https://b.example.test']
        enabled={x[0] for x in db.query(SkillDefinition.slug).join(ProjectSkill,ProjectSkill.skill_id==SkillDefinition.id).filter(ProjectSkill.project_id==project.id,ProjectSkill.enabled==1).all()}
        assert enabled=={skills[0].slug}
        items=db.query(BatchAssessmentItem).filter(BatchAssessmentItem.batch_id==batch.id).all()
        assert sum(1 for x in items if x.status=='done')==2
    finally: db.close()



def test_v162_http_route_is_used_by_real_request_replay():
    Base.metadata.create_all(bind=engine)
    observed={}

    class ProxyHandler(BaseHTTPRequestHandler):
        def log_message(self,*args):
            return
        def do_GET(self):
            observed['path']=self.path
            observed['host']=self.headers.get('Host','')
            payload=b'{"via":"proxy"}'
            self.send_response(200)
            self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server=ThreadingHTTPServer(('127.0.0.1',0),ProxyHandler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    db=SessionLocal()
    try:
        project=Project(name='V162 Proxy Replay',scope_text='example.test')
        db.add(project);db.commit();db.refresh(project)
        route=create_route_profile(db,name=f'HTTP Proxy E2E {project.id}',route_type='http',host='127.0.0.1',port=server.server_address[1])
        select_route(db,project,route.id)
        stored=create_stored_request(db,project.id,'Proxy GET','GET','http://example.test/proxy-test?ticket=PROXY-SECRET',headers={'Accept':'application/json'},source='qa')
        result=asyncio.run(replay_request(db,['example.test'],stored,None))
        assert result.status=='done' and result.status_code==200
        assert '"via":"proxy"' in result.response_body
        assert observed['path'].startswith('http://example.test/proxy-test')
        assert 'PROXY-SECRET' in observed['path']
    finally:
        db.close();server.shutdown();server.server_close();thread.join(timeout=2)

def test_v162_resource_gate_snapshot_counts_scan_jobs():
    Base.metadata.create_all(bind=engine)
    db=SessionLocal()
    try:
        project=Project(name='V162 Gate',scope_text='example.test')
        db.add(project);db.commit();db.refresh(project)
        for kind in ['project_scan','batch_scan']:
            db.add(PersistentJob(project_id=project.id,kind=kind,target='x',payload_json='{}',scope_snapshot_json='[]',scope_hash='x',status='running'))
        db.commit()
        gates=resource_gate_snapshot(db)
        assert gates['scan']['running']>=2
        assert gates['scan']['limit']==2
        assert gates['browser']['limit']==1
    finally: db.close()


def test_v162_ui_routes_datagrid_context_actions_and_secret_redaction():
    Base.metadata.create_all(bind=engine)
    db=SessionLocal()
    try:
        project=Project(name='V162 UI',scope_text='app.example.test')
        db.add(project);db.commit();db.refresh(project)
        asset=Asset(project_id=project.id,target='app.example.test',kind='hostname')
        db.add(asset);db.commit();db.refresh(asset)
        db.add(Endpoint(asset_id=asset.id,url='https://app.example.test/api/user?ticket=UI-SECRET',method='GET',status_code=200,source='qa'))
        db.add(TechnologyFingerprint(project_id=project.id,asset_id=asset.id,category='waf',product='CTG-WAF',confidence=98,rule_id='qa',evidence_source='QA'))
        db.commit();pid=project.id
    finally: db.close()
    with TestClient(app) as client:
        page=client.get(f'/projects/{pid}/asset-intelligence')
        assert page.status_code==200
        assert 'Fingerprint Engine 2.0' in page.text and 'Network Route Profile' in page.text and 'Batch Job' in page.text
        ep=client.get(f'/projects/{pid}/endpoints')
        assert ep.status_code==200 and '统一 Endpoint 数据表' in ep.text and 'Browser Observe' in ep.text
        assert 'UI-SECRET' not in ep.text
        assert 'data-datagrid' in ep.text


def test_v162_portability_schema_and_fingerprint_metadata():
    from app.services.project_portability import export_manifest
    Base.metadata.create_all(bind=engine)
    db=SessionLocal()
    try:
        p=Project(name='V162 Portable',scope_text='example.test')
        db.add(p);db.commit();db.refresh(p)
        a=Asset(project_id=p.id,target='example.test',kind='hostname');db.add(a);db.commit();db.refresh(a)
        db.add(TechnologyFingerprint(project_id=p.id,asset_id=a.id,category='web_server',product='Nginx',confidence=96,rule_id='builtin',evidence_source='Evidence#1'));db.commit()
        m=export_manifest(db,p)
        assert m['schema']=='snowedge-project/1.6.2'
        assert m['technology_fingerprints'][0]['product']=='Nginx'
        assert m['security_notice']['network_route_password_included'] is False
    finally: db.close()


def test_v162_v16_database_migrates_to_v162_head(tmp_path):
    db_path=tmp_path/'v16.db'
    sql=(
        "CREATE TABLE projects (id INTEGER PRIMARY KEY, name VARCHAR(200), scope_text TEXT, client_name VARCHAR(240), environment VARCHAR(80), engagement_type VARCHAR(80), status VARCHAR(60), start_date VARCHAR(32), end_date VARCHAR(32), authorization_note TEXT, testers_json TEXT, template_slug VARCHAR(80), created_at DATETIME);"
        "CREATE TABLE identities (id INTEGER PRIMARY KEY, project_id INTEGER, name VARCHAR(120), role VARCHAR(80), headers_encrypted TEXT, cookies_encrypted TEXT, vault_item_id INTEGER, notes TEXT, created_at DATETIME);"
        "CREATE TABLE backup_records (id INTEGER PRIMARY KEY, project_id INTEGER, backup_type VARCHAR(60), file_path VARCHAR(2000), file_sha256 VARCHAR(64), size_bytes INTEGER, status VARCHAR(60), detail_json TEXT, created_at DATETIME);"
        "CREATE TABLE evidence_attachments (id INTEGER PRIMARY KEY, project_id INTEGER, finding_id INTEGER, evidence_id INTEGER, attachment_type VARCHAR(60), label VARCHAR(300), file_path VARCHAR(2000), mime_type VARCHAR(100), file_sha256 VARCHAR(64), size_bytes INTEGER, sort_order INTEGER, annotation_json TEXT, created_at DATETIME);"
        "CREATE TABLE stored_request_revisions (id INTEGER PRIMARY KEY, project_id INTEGER, stored_request_id INTEGER, revision_no INTEGER, name VARCHAR(240), method VARCHAR(16), url VARCHAR(2000), headers_json TEXT, secret_headers_encrypted TEXT, body TEXT, policy_class VARCHAR(50), change_note VARCHAR(500), created_at DATETIME);"
        "CREATE TABLE secret_vault_items (id INTEGER PRIMARY KEY);CREATE TABLE workspace_drafts (id INTEGER PRIMARY KEY);CREATE TABLE recovery_events (id INTEGER PRIMARY KEY);"
        "CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL);INSERT INTO alembic_version(version_num) VALUES('v1_6_reliability');"
    )
    con=sqlite3.connect(db_path);con.executescript(sql);con.commit();con.close()
    env=os.environ.copy();env['DATABASE_URL']=f'sqlite:///{db_path}'
    code=("from sqlalchemy import inspect\nfrom app.db import engine\nfrom app.schema_migrations import ensure_schema_current\nensure_schema_current()\ni=inspect(engine)\n"
          "tables=set(i.get_table_names())\nassert {'technology_fingerprints','fingerprint_rules','scan_profiles','network_route_profiles','batch_assessments','batch_assessment_items'} <= tables\n"
          "cols={c['name'] for c in i.get_columns('projects')}\nassert {'scan_profile_id','network_route_profile_id'} <= cols\n"
          "with engine.connect() as c: rev=c.exec_driver_sql('SELECT version_num FROM alembic_version').scalar()\nassert rev=='v1_8_toolchain_runs'\nprint(rev)\n")
    r=subprocess.run([sys.executable,'-c',code],cwd=str(Path(__file__).resolve().parents[1]),env=env,capture_output=True,text=True,timeout=120)
    assert r.returncode==0,r.stdout+r.stderr
    assert 'v1_8_toolchain_runs' in r.stdout
