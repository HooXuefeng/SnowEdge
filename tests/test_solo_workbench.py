import asyncio
import base64
import json
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from app.db import Base, engine, SessionLocal
from app.main import app
from app.models import Project, Evidence, StoredRequest, CopilotQuery, PersistentJob
from app.services.utility_tools import local_tool
from app.services.analyst_copilot import build_copilot_context, resolve_citation


@pytest.fixture
def project_ids():
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        rows = [Project(name=f'个人作业台 {i}', scope_text='example.test') for i in range(2)]
        db.add_all(rows); db.commit()
        return [row.id for row in rows]


def test_new_local_tools_do_not_claim_jwt_verification():
    encode = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
    jwt = f'{encode({"alg":"HS256"})}.{encode({"sub":"test"})}.signature'
    result = local_tool('jwt', jwt)
    assert result['声明']['sub'] == 'test'
    assert '未验证' in result['签名状态']
    with pytest.raises(ValueError): local_tool('jwt', 'invalid')
    assert local_tool('base64_encode', 'hello')['编码结果'] == 'aGVsbG8='
    encoded = local_tool('url_encode', '测试 & value')['编码结果']
    assert local_tool('url_decode', encoded)['解码结果'] == '测试 & value'
    result = local_tool('targets', 'https://example.test/a\nexample.test\ninvalid target\n192.0.2.1')
    assert result['去重后数量'] == 2 and result['无效行号'] == [3]


def test_diagnostic_evidence_handoff_is_scoped_and_idempotent(project_ids, monkeypatch):
    pid, other = project_ids
    monkeypatch.setattr('app.utility_routes.network_tool', AsyncMock(return_value={'地址':'https://example.test/api?token=SUPERSECRET', 'HTTP 状态':200}))
    with TestClient(app) as client:
        response = client.post('/api/tools/run', json={'project_id':pid, 'kind':'http', 'value':'https://example.test/api?token=SUPERSECRET'})
        assert response.status_code == 200
        eid = response.json()['evidence_id']
        with SessionLocal() as db:
            row = db.get(Evidence, eid)
            assert row.project_id == pid and row.task_id and row.integrity_sha256
            assert 'SUPERSECRET' not in row.content
            assert json.loads(row.content)['target'] == 'https://example.test/api'
        assert client.post(f'/api/projects/{other}/diagnostics/{eid}/request').status_code == 404
        first = client.post(f'/api/projects/{pid}/diagnostics/{eid}/request')
        second = client.post(f'/api/projects/{pid}/diagnostics/{eid}/request')
        assert first.status_code == 200 and first.json()['url'] == second.json()['url']
        with SessionLocal() as db:
            assert db.query(StoredRequest).filter_by(project_id=pid, source=f'diagnostic:{eid}').count() == 1
            project = db.get(Project, pid); project.scope_text = 'different.test'; db.commit()
        assert client.post(f'/api/projects/{pid}/diagnostics/{eid}/request').status_code == 400


def test_copilot_diagnostic_references_cannot_cross_projects(project_ids):
    pid, other = project_ids
    with SessionLocal() as db:
        own = Evidence(project_id=pid, kind='utility_http', source_type='utility_tool', content=json.dumps({'target':'https://example.test', 'result':{'token':'PRIVATE'}}))
        foreign = Evidence(project_id=other, kind='utility_dns', source_type='utility_tool', content='{"foreign":"do not include"}')
        db.add_all([own, foreign]); db.commit()
        context, refs = build_copilot_context(db, db.get(Project, pid), f'解释 utility:{own.id} utility:{foreign.id}')
        assert f'utility:{own.id}' in refs and f'utility:{foreign.id}' not in refs
        assert 'PRIVATE' not in json.dumps(context['diagnostics'])
        assert resolve_citation(db, pid, f'utility:{foreign.id}') is None
        assert f'selected={own.id}' in resolve_citation(db, pid, f'utility:{own.id}')['url']


def test_assistant_uses_queue_and_preserves_project_boundary(project_ids, monkeypatch):
    pid, other = project_ids
    execute = AsyncMock()
    monkeypatch.setattr('app.workbench_routes.run_job_now', execute)
    with TestClient(app) as client:
        result = client.post(f'/api/projects/{pid}/assistant', json={'question':'解释当前项目证据'})
        assert result.status_code == 200
        qid = result.json()['id']
        assert client.get(f'/api/projects/{other}/assistant?query_id={qid}').status_code == 404
        assert client.get(f'/api/projects/{pid}/assistant?query_id=999999999').status_code == 404
        query = client.get(f'/api/projects/{pid}/assistant?query_id={qid}').json()['query']
        assert query['status'] == 'queued'
        with SessionLocal() as db:
            job = db.get(PersistentJob, result.json()['job_id'])
            assert job.kind == 'copilot_query' and json.loads(job.payload_json) == {'query_id':qid}
        execute.assert_awaited_once()


def test_workbench_renders_all_stages_and_contextual_assistant(project_ids):
    with TestClient(app) as client:
        page = client.get(f'/projects/{project_ids[0]}/workbench')
        assert page.status_code == 200
        for label in ['个人作业台', '资产收集', '请求验证', '分析研判', '证据交付', 'AI 随行助手']:
            assert label in page.text
        assert 'role="tabpanel"' in page.text
        assert client.get('/projects/99999999/workbench').status_code == 404
