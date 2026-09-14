import html
import importlib.util
import re
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from app.db import Base, engine, SessionLocal
from app.main import app
from app.models import Project, Finding, Evidence, RemediationEvent, AppPreference
from app.finding_editor_routes import revision


@pytest.fixture
def project_id():
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        p = Project(name='Manual workflow', scope_text='example.test')
        db.add(p); db.commit()
        return p.id


def fields(**changes):
    data = dict(title='Manual issue', severity='high', target='https://example.test/item',
                description='Reproduction steps', parameter='item', recommendation='Check ownership',
                cwe_id='CWE-639', txb02_category='Access control', owasp_category='', vuln_type='IDOR')
    data.update(changes)
    return data


def test_manual_finding_edit_evidence_retest_report(project_id):
    with TestClient(app) as client:
        created = client.post(f'/projects/{project_id}/findings/new', data=fields(), follow_redirects=False)
        assert created.status_code == 303
        fid = int(created.headers['location'].split('/')[-1])
        with SessionLocal() as db:
            finding = db.get(Finding, fid)
            original_fingerprint, old_revision = finding.fingerprint, revision(finding)
        updated = fields(title='Corrected issue', severity='low', cwe_id='', txb02_category='', revision=old_revision)
        assert client.post(f'/findings/{fid}/edit', data=updated, follow_redirects=False).status_code == 303
        conflict = client.post(f'/findings/{fid}/edit', data=updated)
        assert conflict.status_code == 409
        assert 'Corrected issue' in conflict.text
        assert client.get(f'/findings/{fid}').status_code == 200
        with SessionLocal() as db:
            finding = db.get(Finding, fid)
            assert finding.fingerprint == original_fingerprint
            assert finding.cwe_id == '' and finding.txb02_category == ''
            assert finding.title == 'Corrected issue' and finding.severity == 'low'
        assert client.post(f'/findings/{fid}/manual-evidence', data={'note': 'Observed request and response'}, follow_redirects=False).status_code == 303
        assert client.post(f'/findings/{fid}/manual-retest', data={'outcome': 'resolved', 'note': 'Ownership check now rejects other accounts'}, follow_redirects=False).status_code == 303
        import io
        from PIL import Image
        screenshot=io.BytesIO();Image.new('RGB',(32,32),'white').save(screenshot,format='PNG')
        assert client.post(f'/findings/{fid}/screenshots',files={'screenshot':('proof.png',screenshot.getvalue(),'image/png')},data={'label':'Manual proof'},follow_redirects=False).status_code==303
        report = client.get(f'/projects/{project_id}/reports/export.docx')
        assert report.status_code == 200
        import io
        with zipfile.ZipFile(io.BytesIO(report.content)) as document:
            assert b'Corrected issue' in document.read('word/document.xml')
            assert any(name.startswith('word/media/') for name in document.namelist())
        with SessionLocal() as db:
            assert db.get(Finding, fid).verification_state == 'resolved'
            assert db.query(Evidence).filter_by(finding_id=fid).count() >= 2
            kinds = {e.event_type for e in db.query(RemediationEvent).filter_by(finding_id=fid)}
            assert {'finding_created', 'finding_edited', 'evidence_added', 'manual_retest_recorded'} <= kinds


def test_manual_target_scope_and_cross_project_evidence(project_id):
    with TestClient(app) as client:
        assert client.post(f'/projects/{project_id}/findings/new', data=fields(target='https://outside.test')).status_code == 400
        created = client.post(f'/projects/{project_id}/findings/new', data=fields(), follow_redirects=False)
        fid = int(created.headers['location'].split('/')[-1])
        with SessionLocal() as db:
            other = Project(name='Other', scope_text='other.test'); db.add(other); db.flush()
            evidence = Evidence(project_id=other.id, kind='manual', content='private')
            db.add(evidence); db.commit(); eid = evidence.id
        assert client.post(f'/findings/{fid}/manual-evidence', data={'evidence_id': eid}).status_code == 404


@pytest.mark.parametrize('headers,status', [
    ({'Origin': 'https://evil.test'}, 403), ({'Origin': 'null'}, 403),
    ({'Sec-Fetch-Site': 'cross-site'}, 403), ({'Host': 'evil.test'}, 400),
    ({'Host': 'evil@localhost'}, 400), ({'Origin': 'http://testserver'}, 303),
])
def test_local_origin_mutation_guard(project_id, headers, status):
    with TestClient(app) as client:
        assert client.post(f'/projects/{project_id}/findings/new', data=fields(), headers=headers, follow_redirects=False).status_code == status


def test_project_changes_require_bound_confirmation(project_id):
    data = dict(name='Renamed project', scope_text='example.test\nnew.test', client_name='', environment='', start_date='', end_date='', authorization_note='Approved extension')
    with TestClient(app) as client:
        preview = client.post(f'/projects/{project_id}/edit', data=data)
        approval = html.unescape(re.search(r'name="approval" value="([^"]+)"', preview.text).group(1))
        with SessionLocal() as db:
            assert db.get(Project, project_id).name == 'Manual workflow'
        tampered = dict(data, confirm='yes', approval=approval, scope_text='evil.test')
        assert client.post(f'/projects/{project_id}/edit', data=tampered, follow_redirects=False).status_code != 303
        assert client.post(f'/projects/{project_id}/edit', data=dict(data, confirm='yes', approval=approval), follow_redirects=False).status_code == 303
        with SessionLocal() as db:
            assert db.get(Project, project_id).scope_text == data['scope_text']
            assert db.query(AppPreference).filter(AppPreference.key.like(f'project_audit:{project_id}:%')).count() == 1


def test_installation_key_unique_stable_and_concurrent(tmp_path, monkeypatch):
    from app.install_secret import installation_secret
    from concurrent.futures import ThreadPoolExecutor
    monkeypatch.setenv('SNOWEDGE_STATE_DIR', str(tmp_path / 'one'))
    with ThreadPoolExecutor(max_workers=8) as pool:
        keys = list(pool.map(lambda _: installation_secret(), range(16)))
    assert len(set(keys)) == 1 and len(keys[0]) == 64
    monkeypatch.setenv('SNOWEDGE_STATE_DIR', str(tmp_path / 'two'))
    assert installation_secret() != keys[0]


def test_release_allowlist_excludes_workspace_canaries(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location('release_builder', Path(__file__).resolve().parents[1] / 'scripts/build-release.py')
    builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)
    source = tmp_path / 'source'; source.mkdir()
    for name in builder.FILES + ['SnowEdge.exe', 'requirements.txt', 'app/main.py']:
        p = source / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text('placeholder', encoding='utf-8')
    for name in ['.env', '.venv/private.py', '.runtime/app-secret', 'ai_pentest.db', 'backups/private.zip', 'qa/private.png', 'app/__pycache__/private.py']:
        p = source / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text('PRIVATE-CANARY', encoding='utf-8')
    monkeypatch.setattr(builder, 'ROOT', source)
    result = builder.build(tmp_path / 'output')
    with zipfile.ZipFile(result['zip']) as bundle:
        for name in bundle.namelist():
            assert b'PRIVATE-CANARY' not in bundle.read(name)
        assert sum(name.endswith('.exe') for name in bundle.namelist()) == 1


def test_proxy_lifecycle_and_failed_closed(project_id, monkeypatch):
    from app.services.network_routes import create_route_profile, select_route, httpx_proxy_url
    from app.models import NetworkRouteProfile
    with SessionLocal() as db:
        row=create_route_profile(db,name=f'Lifecycle-{project_id}',route_type='http',host='127.0.0.1',port=8080,password='test-only')
        rid=row.id;select_route(db,db.get(Project,project_id),rid)
    with TestClient(app) as client:
        path=f'/projects/{project_id}/network-routes/{rid}/manage'
        assert client.post(path,data={'action':'delete'},follow_redirects=False).status_code==200
        with SessionLocal() as db:
            assert db.get(NetworkRouteProfile,rid)
            select_route(db,db.get(Project,project_id),None)
        assert client.post(path,data={'action':'disable'},follow_redirects=False).status_code==303
        assert client.post(path,data={'action':'select'},follow_redirects=False).status_code==200
        assert client.post(path,data={'action':'enable'},follow_redirects=False).status_code==303
        from unittest.mock import AsyncMock
        probe=AsyncMock(return_value={'ok':True,'status_code':204})
        monkeypatch.setattr('app.network_management_routes.http_probe',probe)
        assert client.post(path,data={'action':'test','target':'https://example.test'}).status_code==200
        assert probe.await_args.kwargs['method']=='HEAD'
        with SessionLocal() as db:
            assert 'last_used' in db.query(AppPreference).filter_by(key=f'route_usage:{rid}').one().value_json
        assert client.post(path,data={'action':'delete'},follow_redirects=False).status_code==303
        with SessionLocal() as db:
            assert db.get(NetworkRouteProfile,rid) is None
            p=db.get(Project,project_id);p.network_route_profile_id=999999;db.commit()
            with pytest.raises(ValueError):httpx_proxy_url(db,project_id)


def test_clear_ai_key_suppresses_environment_fallback(project_id,monkeypatch):
    from app.services.personal_settings import save_personal_settings, ai_runtime_settings
    from app.config import settings
    monkeypatch.setattr(settings,'ai_api_key','environment-test-key')
    with SessionLocal() as db:
        save_personal_settings(db,{'ai_api_key':'stored-test-key','ai_provider':'openai'})
    with TestClient(app) as client:
        assert client.post('/setup/credentials/ai/clear',follow_redirects=False).status_code==303
        result=client.post('/setup/credentials/burp/regenerate',follow_redirects=False)
        assert result.status_code==200 and 'no-store' in result.headers['cache-control']
        assert client.post('/setup/credentials/burp/clear',follow_redirects=False).status_code==303
    with SessionLocal() as db:
        assert not ai_runtime_settings(db)['api_key']
