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
OUTPUT = ROOT / "qa" / "hash_analysis"
OUTPUT.mkdir(parents=True, exist_ok=True)
sandbox = tempfile.TemporaryDirectory(prefix="workspace-browser-", ignore_cleanup_errors=True)
scratch = Path(sandbox.name)
os.environ.update({"DATABASE_URL": f"sqlite:///{(scratch / 'preview.db').as_posix()}", "APP_SECRET_KEY": "preview-only-key", "AI_PROVIDER": "mock", "AI_API_KEY": "", "AI_API_BASE": "", "BROWSER_ARTIFACT_DIR": str(scratch / 'browser'), "EVIDENCE_ARTIFACT_DIR": str(scratch / 'evidence'), "RESTORE_PENDING_DIR": str(scratch / 'restore'), "JOB_EMBEDDED_WORKERS": "0", "SNOWEDGE_STATE_DIR": str(scratch / "state")})
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
    from playwright.sync_api import sync_playwright, expect
    with sync_playwright() as p:
        browser=p.chromium.launch(channel='chrome',headless=True)
        page=browser.new_page(viewport={'width':1440,'height':1000})
        errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
        page.goto(url+'/decoder')
        page.locator('#analysisInput').fill('e10adc3949ba59abbe56e057f20f883e')
        page.get_by_role('button',name='识别与分析',exact=True).click()
        expect(page.locator('#kindLabel')).to_have_text('疑似 Hash')
        page.locator('#startMatch').click()
        expect(page.locator('#matchResult')).to_contain_text('123456')
        page.evaluate('window.scrollTo(0,0)')
        page.screenshot(path=str(OUTPUT/'hash-desktop.png'),full_page=True)
        page.locator('#clearAnalysis').click()
        expect(page.locator('#analysisInput')).to_have_value('')
        page.locator('#analysisInput').fill('536e6f7745646765')
        page.get_by_role('button',name='识别与分析',exact=True).click()
        expect(page.locator('#analysisText')).to_have_text('SnowEdge')
        page.set_viewport_size({'width':390,'height':844})
        page.evaluate('window.scrollTo(0,0)')
        expect(page.locator('#workspaceNavigation')).not_to_be_visible()
        page.locator('#navToggle').click()
        expect(page.locator('#workspaceNavigation')).to_be_visible()
        page.keyboard.press('Escape')
        expect(page.locator('#workspaceNavigation')).not_to_be_visible()
        page.screenshot(path=str(OUTPUT/'hash-mobile.png'),full_page=True)
        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1')
        page.set_viewport_size({'width':1440,'height':1000})
        page.goto(url+'/projects/'+str(pid)+'/authorization-matrix')
        choice=page.locator('input[name=include_anonymous]')
        assert choice.locator('..').evaluate('(e)=>getComputedStyle(e).backgroundColor')=='rgb(255, 255, 255)'
        choice.check()
        assert choice.locator('..').evaluate('(e)=>getComputedStyle(e).backgroundColor')=='rgb(238, 242, 255)'
        choice.uncheck()
        page.evaluate('window.scrollTo(0,0)')
        page.screenshot(path=str(OUTPUT/'matrix-light.png'),full_page=True)
        dark={}
        page.goto(url+'/projects/'+str(pid)+'/attack-surface')
        expect(page.locator('#contextDetail')).to_be_visible()
        page.screenshot(path=str(OUTPUT/'asset-light.png'),full_page=True)
        paths=page.locator('.side-link[href]').evaluate_all('(els)=>els.map(e=>e.getAttribute("href"))')
        paths=list(dict.fromkeys(paths+['/','/tools','/decoder']))
        statuses={}
        for path in paths:
            response=page.goto(url+path)
            statuses[path]=response.status
            assert response.status==200,(path,response.status)
            page.locator('details').evaluate_all('(els)=>els.forEach(e=>e.open=true)')
            dark[path]=page.evaluate(r"""()=>[...document.querySelectorAll('body *')].filter(e=>{const r=e.getBoundingClientRect(),c=getComputedStyle(e).backgroundColor.match(/^rgb\((\d+), (\d+), (\d+)\)$/);return r.width>24&&r.height>18&&c&&Math.max(+c[1],+c[2],+c[3])<80}).map(e=>e.outerHTML.slice(0,120)).slice(0,30)""")
        print(json.dumps({'page_statuses':statuses},ensure_ascii=False))
        assert not any(dark.values()),dark
        assert not errors,errors
        (OUTPUT/'visual-audit.json').write_text(json.dumps(dark,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps({'browser':'passed','dark_components':dark},ensure_ascii=False))
        browser.close()
finally:
    server.terminate()
    try:server.wait(timeout=10)
    except subprocess.TimeoutExpired:server.kill();server.wait()
    log.close();engine.dispose();sandbox.cleanup()
