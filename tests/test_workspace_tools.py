import asyncio
import socket
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event

from app.db import Base, SessionLocal, engine
from app.main import app
from app.models import Asset, Endpoint, Finding, Project
from app.services.utility_tools import local_tool, network_tool, parse_target
from app.services.finding_quality import finding_quality, project_quality_summary


def test_network_http_is_head_bounded_and_redacted(monkeypatch):
    import httpx
    from app.services import utility_tools
    original = httpx.AsyncClient
    requests = []
    def respond(request):
        requests.append(request)
        return httpx.Response(302, headers={"server":"example", "set-cookie":"secret", "location":"https://outside.test/?token=SECRET"}, content=b"not downloaded")
    monkeypatch.setattr(utility_tools.httpx, "AsyncClient", lambda **kwargs: original(**kwargs, transport=httpx.MockTransport(respond)))
    result = asyncio.run(network_tool("http", "https://example.test/?token=SECRET", ["example.test"]))
    assert len(requests) == 1 and requests[0].method == "HEAD"
    assert result["HTTP 状态"] == 302
    assert result["重定向"] == "未跟随"
    assert "SECRET" not in str(result) and "set-cookie" not in str(result)


def test_dns_and_tls_return_results(monkeypatch):
    async def check_dns():
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, "getaddrinfo", AsyncMock(return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.5', 0))]))
        assert (await network_tool("dns", "example.test", ["example.test"]))["IPv4"] == ["192.0.2.5"]
    asyncio.run(check_dns())
    monkeypatch.setattr('app.services.utility_tools.analyze_tls', AsyncMock(return_value={"ok":True,"protocol":"TLSv1.3","cipher":"test","notBefore":"start","notAfter":"end","issuer":[],"subjectAltName":[]}))
    assert asyncio.run(network_tool("tls", "example.test", ["example.test"]))["证书校验"] == "通过"


def test_tcp_can_connect_to_local_service():
    async def check():
        async def connected(reader, writer):
            writer.close()
            await writer.wait_closed()
        server = await asyncio.start_server(connected, '127.0.0.1', 0)
        async with server:
            port = server.sockets[0].getsockname()[1]
            result = await network_tool('tcp', f'127.0.0.1:{port}', ['127.0.0.1'])
            assert result['连接'] == '成功'
    asyncio.run(check())


@pytest.fixture
def project():
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        row = Project(name="工具与体验验证", scope_text="example.test")
        db.add(row); db.commit(); db.refresh(row)
        return row.id


def test_local_tools_and_invalid_input():
    assert local_tool("ip", "192.168.1.55/24")["地址总数"] == 256
    assert local_tool("base64", "SGVsbG8=")["解码结果"] == "Hello"
    assert '"a": 1' in local_tool("json", '{"a":1}')["格式化结果"]
    assert len(local_tool("sha256", "hello")["SHA-256"]) == 64
    result = local_tool("url", "https://example.test/?token=SECRET")
    assert "SECRET" not in str(result)
    assert result["参数名称"] == ["token"]
    assert parse_target("[::1]:443")[0] == "::1"
    for value in ["file:///etc/passwd", "https://user:pass@example.test", "example.test:99999"]:
        with pytest.raises(ValueError): parse_target(value)


def test_out_of_scope_never_connects(monkeypatch):
    connect = AsyncMock()
    monkeypatch.setattr(asyncio, "open_connection", connect)
    with pytest.raises(ValueError, match="授权范围"):
        asyncio.run(network_tool("tcp", "outside.test:443", ["example.test"]))
    connect.assert_not_called()
    with pytest.raises(ValueError, match="代理"):
        asyncio.run(network_tool("tcp", "example.test:443", ["example.test"], "http://proxy:8080"))


def test_tools_routes_and_asset_scope(project, monkeypatch):
    with TestClient(app) as client:
        page = client.get(f"/tools?project_id={project}")
        assert page.status_code == 200
        assert "实用工具" in page.text and "TLS 证书" in page.text
        assert client.post("/api/tools/run", json={"kind":"json", "value":"{"}).status_code == 400
        assert client.post("/api/tools/run", json={"kind":"dns", "value":"example.test"}).status_code == 400
        assert client.post("/api/tools/run", json={"kind":"tcp", "value":"outside.test", "project_id":project}).status_code == 400
        response = client.post("/api/tools/save-asset", json={"kind":"dns", "value":"outside.test", "project_id":project})
        assert response.status_code == 400
        for _ in range(2):
            assert client.post("/api/tools/save-asset", json={"kind":"dns", "value":"example.test", "project_id":project}).status_code == 200
    with SessionLocal() as db:
        assert db.query(Asset).filter_by(project_id=project).count() == 1


def test_endpoint_page_is_paginated_and_does_not_sync(project):
    with SessionLocal() as db:
        asset = Asset(project_id=project, target="example.test", kind="hostname")
        db.add(asset); db.flush()
        db.add_all([Endpoint(asset_id=asset.id, url=f"https://example.test/item/{i}", method="GET", normalized_path=f"/item/{i}") for i in range(61)])
        db.commit()
        before = [(e.id, e.last_seen_at) for e in db.query(Endpoint).filter_by(asset_id=asset.id).order_by(Endpoint.id)]
    with TestClient(app) as client:
        page = client.get(f"/projects/{project}/endpoints")
        assert page.status_code == 200
        assert page.text.count('data-inspector-kind="接口详情"') == 50
        page2 = client.get(f"/projects/{project}/endpoints?page=2")
        assert page2.text.count('data-inspector-kind="接口详情"') == 11
        filtered = client.get(f"/projects/{project}/endpoints?q=/item/60")
        assert filtered.text.count('data-inspector-kind="接口详情"') == 1
    with SessionLocal() as db:
        assert before == [(e.id, e.last_seen_at) for e in db.query(Endpoint).filter_by(asset_id=asset.id).order_by(Endpoint.id)]


def test_quality_batch_has_constant_query_count(project):
    with SessionLocal() as db:
        db.add_all([Finding(project_id=project, title=f"Finding {i}", severity="low", target="example.test", description="sample", recommendation="sample", source="manual") for i in range(20)])
        db.commit()
        count = []
        def record(*args): count.append(1)
        event.listen(engine, "before_cursor_execute", record)
        try: summary = project_quality_summary(db, project)
        finally: event.remove(engine, "before_cursor_execute", record)
        assert len(count) == 6
        assert summary["count"] == 20
        for row in summary["rows"]:
            assert row == finding_quality(db, db.get(Finding, row["finding_id"]))
