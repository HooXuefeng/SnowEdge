import asyncio
import json
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from app.db import Base, SessionLocal, engine
from app.main import app
from app.models import AppPreference, Asset, Evidence, PersistentJob, Project, Service
from app.services.job_engine import enqueue_job
from app.services.toolchain import _run_process, build_command, ingest_tool_output, parse_tool_output


def _project() -> int:
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        row = Project(name="工具链测试", scope_text="example.test\n*.example.test\n192.0.2.0/24")
        db.add(row); db.commit(); db.refresh(row)
        return row.id


def test_nmap_xml_maps_assets_and_services():
    payload = """<?xml version='1.0'?><nmaprun><host><address addr='192.0.2.8' addrtype='ipv4'/><ports><port protocol='tcp' portid='443'><state state='open'/><service name='https' product='nginx' version='1.26'/></port></ports></host></nmaprun>"""
    result = parse_tool_output("nmap", payload)
    assert result["assets"] == [{"target": "192.0.2.8", "kind": "host"}]
    assert result["services"][0]["port"] == 443
    assert result["services"][0]["name"] == "https"
    assert "nginx" in result["services"][0]["banner"]


def test_projectdiscovery_jsonl_maps_each_result_type():
    subdomains = parse_tool_output("subfinder", '{"host":"api.example.test"}\n')
    assert subdomains["assets"][0]["target"] == "api.example.test"
    ports = parse_tool_output("naabu", '{"host":"example.test","ip":"192.0.2.8","port":8443,"protocol":"tcp"}\n')
    assert ports["services"][0]["port"] == 8443
    web = parse_tool_output("httpx", '{"url":"https://example.test/","status_code":200,"tech":["nginx"]}\n')
    assert web["endpoints"][0]["status_code"] == 200
    crawl = parse_tool_output("katana", '{"request":{"method":"GET","endpoint":"https://example.test/api"},"response":{"status_code":200}}\n')
    assert crawl["endpoints"][0]["url"].endswith("/api")
    nuclei = parse_tool_output("nuclei", json.dumps({"template-id":"demo-check","matched-at":"https://example.test/","info":{"name":"演示检查","severity":"high","classification":{"cwe-id":["CWE-200"]}}}, ensure_ascii=False))
    assert nuclei["findings"][0]["severity"] == "high"
    assert nuclei["findings"][0]["cwe_id"] == "CWE-200"


def test_commands_are_allowlisted_and_do_not_use_a_shell():
    command = build_command("nmap", "C:/Tools/nmap.exe", "https://example.test/path", [80, 443])
    assert command[0] == "C:/Tools/nmap.exe"
    assert command[-1] == "example.test"
    assert "80,443" in command


def test_external_process_capture_and_stop_are_bounded():
    code, stdout, stderr = asyncio.run(_run_process([sys.executable, "-c", "print('tool-ok')"]))
    assert code == 0 and stdout.strip() == "tool-ok" and not stderr
    try:
        asyncio.run(_run_process([sys.executable, "-c", "import time; time.sleep(10)"], lambda: True))
    except RuntimeError as exc:
        assert "停止" in str(exc)
    else:
        raise AssertionError("stop request did not terminate the external process")


def test_nmap_ingestion_uses_existing_project_models_and_evidence_chain():
    pid = _project()
    payload = """<?xml version='1.0'?><nmaprun><host><address addr='192.0.2.9'/><ports><port protocol='tcp' portid='22'><state state='open'/><service name='ssh' product='OpenSSH'/></port></ports></host></nmaprun>"""
    with SessionLocal() as db:
        project = db.get(Project, pid)
        job = enqueue_job(db, project, "external_tool", target="192.0.2.9", payload={"tool_id": "nmap", "ports": [22]})
        result = ingest_tool_output(db, project, job, "nmap", payload)
        assert result["assets"] == 1 and result["services"] == 1
        asset = db.query(Asset).filter_by(project_id=pid, target="192.0.2.9").one()
        assert db.query(Service).filter_by(asset_id=asset.id, port=22, name="ssh").count() == 1
        evidence = db.get(Evidence, result["evidence_id"])
        assert evidence.job_id == job.id and evidence.integrity_sha256


def test_toolchain_page_path_configuration_and_scope_queue(tmp_path: Path, monkeypatch):
    pid = _project()
    fake = tmp_path / "nmap.exe"
    fake.write_bytes(b"not executed in route test")
    with TestClient(app) as client:
        page = client.get(f"/projects/{pid}/toolchain")
        assert page.status_code == 200
        assert "工具链" in page.text
        configured = client.post(f"/api/projects/{pid}/toolchain/nmap/path", json={"path": str(fake.resolve())})
        assert configured.status_code == 200
        monkeypatch.setattr("app.toolchain_routes.resolve_executable", lambda _db, tool_id: str(fake) if tool_id == "nmap" else "")
        blocked = client.post(f"/api/projects/{pid}/toolchain/nmap/run", json={"target": "outside.test", "ports": "80"})
        assert blocked.status_code == 400
        queued = client.post(f"/api/projects/{pid}/toolchain/nmap/run", json={"target": "example.test", "ports": "80,443"})
        assert queued.status_code == 200
        plan = client.post(f"/api/projects/{pid}/toolchain-plans/infrastructure/run", json={"target": "example.test", "ports": "80,443"})
        assert plan.status_code == 200
        assert [item["tool"] for item in plan.json()["jobs"]] == ["nmap"]
        assert plan.json()["skipped"] == [{"tool": "naabu", "reason": "未安装或未配置路径"}]
        with SessionLocal() as db:
            job = db.get(PersistentJob, queued.json()["id"])
            assert job.kind == "external_tool"
            assert json.loads(job.payload_json) == {"tool_id": "nmap", "ports": [80, 443]}
            pref = db.query(AppPreference).filter_by(key="toolchain:path:nmap").one()
            assert json.loads(pref.value_json)["path"] == str(fake.resolve())
