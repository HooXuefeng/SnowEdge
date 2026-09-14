"""Browser checks against a disposable workspace, never the user's database."""
import json
import re
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUTPUT = ROOT / "qa" / "report_delivery"
OUTPUT.mkdir(parents=True, exist_ok=True)
sandbox = tempfile.TemporaryDirectory(prefix="workspace-browser-", ignore_cleanup_errors=True)
scratch = Path(sandbox.name)
os.environ.update({"LOCAL_ALLOWED_HOSTS":"127.0.0.1,localhost,::1,testserver", "DATABASE_URL": f"sqlite:///{(scratch / 'preview.db').as_posix()}", "APP_SECRET_KEY": "preview-only-key", "AI_PROVIDER": "mock", "AI_API_KEY": "", "AI_API_BASE": "", "BROWSER_ARTIFACT_DIR": str(scratch / 'browser'), "EVIDENCE_ARTIFACT_DIR": str(scratch / 'evidence'), "RESTORE_PENDING_DIR": str(scratch / 'restore'), "JOB_EMBEDDED_WORKERS": "0", "SNOWEDGE_STATE_DIR": str(scratch / "state")})
from app.db import Base, SessionLocal, engine
from app.models import Project, Asset, Endpoint, Evidence
from app.services.personal_settings import save_personal_settings
from app.services.request_workspace import create_stored_request
Base.metadata.create_all(engine)
with SessionLocal() as db:
    save_personal_settings(db, {"backup_enabled": False, "setup_completed": True, "ai_provider": "mock", "backup_dir": str(scratch / 'backups')})
    project = Project(name="企业门户 · 日常安全检查", scope_text="example.test")
    db.add(project); db.commit(); db.refresh(project); pid = project.id
    stored = create_stored_request(db, pid, "用户信息接口", "GET", "https://example.test/api/profile", headers={}, body="", source="manual", explicit_read_only=True)
    rid = stored.id
    asset = db.query(Asset).filter_by(project_id=pid).first()
    db.add_all([Endpoint(asset_id=asset.id, url=f"https://example.test/api/orders/{i}", method="GET", normalized_path=f"/api/orders/{i}", source="manual") for i in range(55)])
    db.commit()
    evidence = Evidence(project_id=pid, source_type='utility_tool', kind='utility_http', content=json.dumps({'tool':'http','label':'HTTP 响应头','target':'https://example.test/api/health','result':{'HTTP 状态':200, '响应头':{'server':'Example'}}}, ensure_ascii=False))
    db.add(evidence); db.commit(); db.refresh(evidence); eid = evidence.id

import importlib.util
spec=importlib.util.spec_from_file_location('report_acceptance',ROOT/'tests/test_report_delivery.py')
acceptance=importlib.util.module_from_spec(spec);spec.loader.exec_module(acceptance)
from fastapi.testclient import TestClient
from app.main import app
with TestClient(app) as client:pid,fid,rid,_=acceptance.setup_case(client)
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
url = f"http://127.0.0.1:{port}"
log = (OUTPUT / 'preview.log').open('w', encoding='utf-8')
server = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', str(port)], cwd=ROOT, env=os.environ.copy(), stdout=log, stderr=log, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
try:
    for _ in range(80):
        try:
            urllib.request.urlopen(url+'/api/health',timeout=1);break
        except Exception:time.sleep(.2)
    from playwright.sync_api import sync_playwright,expect
    with sync_playwright() as p:
        browser=p.chromium.launch(channel='chrome',headless=True)
        page=browser.new_page(viewport={'width':1440,'height':1000});errors=[]
        page.on('pageerror',lambda error:errors.append(str(error)))
        page.goto(url+f'/projects/{pid}/reports')
        expect(page.get_by_role('heading',name='报告中心',exact=True)).to_be_visible()
        page.get_by_role('link',name='编辑详情与 Evidence').click()
        form=page.locator('#reportFindingForm');form.locator('[name=title]').fill('交付页面操作验收')
        form.get_by_role('button',name='保存到 Finding').click()
        expect(page.locator('#reportFindingForm [name=title]')).to_have_value('交付页面操作验收')
        page.screenshot(path=str(OUTPUT/'editor.png'))
        page.locator('#reportAi').click()
        expect(page.locator('#reportAiStatus')).to_contain_text('演示模式')
        evidence=page.locator('.report-evidence').first
        evidence.locator('[name=caption]').fill('用户信息接口验证响应')
        evidence.locator('[name=order]').fill('1')
        evidence.get_by_role('button',name='保存编排').click()
        expect(page.locator('.report-evidence').first.locator('[name=caption]')).to_have_value('用户信息接口验证响应')
        page.goto(url+f'/projects/{pid}/reports')
        page.locator('[name=version]').fill('2.0')
        page.locator('[name=template]').select_option('client')
        page.screenshot(path=str(OUTPUT/'center.png'))
        page.get_by_role('button',name='生成交付版本并预览').click()
        page.wait_for_url('**/preview')
        expect(page.locator('#reportPages img').first).to_be_visible()
        page.locator('#reportPages img').first.evaluate('(image)=>image.decode()')
        expect(page.locator('#previewStatus')).to_contain_text('共')
        assert page.locator('#reportPages').evaluate('(e)=>getComputedStyle(e).backgroundColor')=='rgb(237, 241, 247)'
        page.locator('#previewPage').fill('2');page.locator('#previewGo').click()
        page.locator('#previewPage').fill('1');page.locator('#previewGo').click()
        page.screenshot(path=str(OUTPUT/'preview.png'))
        for fmt in ('PDF','HTML','JSON','CSV','DOCX'):
            with page.expect_download() as event:page.get_by_role('link',name='导出 '+fmt,exact=True).click()
            download=event.value;destination=OUTPUT/('browser-export.'+fmt.lower());download.save_as(str(destination))
            assert destination.stat().st_size>100
        page.goto(url+f'/projects/{pid}/reports');page.set_viewport_size({'width':390,'height':844})
        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1')
        assert not errors,errors
        browser.close();print('Report browser workflow passed: edit, reorder, AI guard, preview and 5 real downloads.')
finally:
    server.terminate()
    try:server.wait(timeout=10)
    except subprocess.TimeoutExpired:server.kill();server.wait()
    log.close();engine.dispose();sandbox.cleanup()
