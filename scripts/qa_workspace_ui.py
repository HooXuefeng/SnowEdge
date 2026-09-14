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
OUTPUT = ROOT / "qa" / "workspace_refresh"
OUTPUT.mkdir(parents=True, exist_ok=True)
sandbox = tempfile.TemporaryDirectory(prefix="workspace-browser-", ignore_cleanup_errors=True)
scratch = Path(sandbox.name)
os.environ.update({"DATABASE_URL": f"sqlite:///{(scratch / 'preview.db').as_posix()}", "APP_SECRET_KEY": "preview-only-key", "AI_PROVIDER": "mock", "AI_API_KEY": "", "AI_API_BASE": "", "BROWSER_ARTIFACT_DIR": str(scratch / 'browser'), "EVIDENCE_ARTIFACT_DIR": str(scratch / 'evidence'), "RESTORE_PENDING_DIR": str(scratch / 'restore'), "JOB_EMBEDDED_WORKERS": "0"})
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
            urllib.request.urlopen(url + '/api/health', timeout=1); break
        except Exception: time.sleep(.2)
    from playwright.sync_api import sync_playwright, expect
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chrome", headless=True)
        page = browser.new_page(viewport={"width":1536,"height":960}, device_scale_factor=1)
        errors = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.goto(url); page.screenshot(path=str(OUTPUT / 'home.png'), full_page=True)
        assert page.locator('.rail').count() == 0
        expect(page.get_by_role('heading', name='我的项目')).to_be_visible()
        page.goto(url + f'/tools?project_id={pid}')
        page.locator('[data-tool="json"]').click(); page.locator('#toolValue').fill('{"name":"hello","ok":true}')
        page.locator('#toolRun').click(); expect(page.locator('#toolStatus')).to_have_text('处理完成')
        expect(page.locator('#toolResult')).to_contain_text('hello')
        page.screenshot(path=str(OUTPUT / 'tools.png'), full_page=True)
        page.locator('#toolValue').fill('{'); page.locator('#toolRun').click(); expect(page.locator('#toolStatus')).to_contain_text('输入格式不正确')
        page.locator('[data-tool="tcp"]').click(); page.locator('#toolValue').fill('outside.test:443'); page.locator('#toolRun').click(); expect(page.locator('#toolStatus')).to_contain_text('授权范围')
        page.goto(url + f'/projects/{pid}'); page.screenshot(path=str(OUTPUT / 'project.png'), full_page=True)
        page.goto(url + f'/projects/{pid}/endpoints'); assert page.locator('[data-inspector-kind="接口详情"]').count() == 50
        page.get_by_role('link', name='下一页').click(); assert page.locator('[data-inspector-kind="接口详情"]').count() == 6
        page.locator('[data-inspector-kind="接口详情"]').first.focus(); page.keyboard.press('Enter'); expect(page.locator('#entityInspector')).to_have_class('entity-inspector open')
        page.goto(url + f'/projects/{pid}/requests?selected={rid}')
        page.locator('[data-tab-target="requestStructured"]').click()
        page.screenshot(path=str(OUTPUT / 'requests.png'), full_page=True)
        attempts = []
        def draft_response(route):
            if route.request.method == 'POST':
                attempts.append(route.request.post_data_json)
                route.fulfill(status=503 if len(attempts) == 1 else 200, content_type='application/json', body=json.dumps({"updated_at":"now"}))
            else: route.continue_()
        page.route('**/draft', draft_response)
        page.locator('#requestEditForm [name="name"]').fill('自动保存重试验证')
        expect(page.locator('#draftSaveState')).to_have_text('自动保存：已加密保存', timeout=12000)
        assert len(attempts) == 2
        # Return newer search response first, then the older response.
        pending = []
        page.route('**/api/global-search?*', lambda route: pending.append(route))
        page.locator('#globalSearchTrigger').click(); page.locator('#globalSearchInput').fill('first')
        page.wait_for_timeout(250); page.locator('#globalSearchInput').fill('second'); page.wait_for_timeout(250)
        assert len(pending) == 2
        def payload(title): return json.dumps({"results":[{"title":title,"kind":"项目","subtitle":"test","url":"/"}]})
        pending[1].fulfill(content_type='application/json', body=payload('new-result')); page.wait_for_timeout(80)
        pending[0].fulfill(content_type='application/json', body=payload('old-result')); page.wait_for_timeout(80)
        expect(page.locator('#globalSearchResults')).to_contain_text('new-result')
        expect(page.locator('#globalSearchResults')).not_to_contain_text('old-result')
        page.keyboard.press('Escape')
        page.goto(url + f'/projects/{pid}/workbench')
        expect(page.get_by_role('heading', name='个人作业台', exact=True)).to_be_visible()
        assert page.locator('.primary-navigation .side-link:visible').count() == 8
        assert page.locator('.solo-summary, .solo-side, .solo-assistant-card').count() == 0
        assert page.evaluate("getComputedStyle(document.body).backgroundColor") == 'rgb(247, 249, 252)'
        page.locator('[data-stage="collect"]').focus(); page.keyboard.press('ArrowRight')
        expect(page.locator('[data-stage="verify"]')).to_have_attribute('aria-selected', 'true')
        expect(page.locator('#stagePanel-verify')).to_be_visible()
        page.screenshot(path=str(OUTPUT / 'workbench.png'), full_page=True)
        page.locator('.assistant-trigger').click()
        expect(page.locator('#assistantDrawer')).to_be_visible()
        page.locator('#assistantQuestion').fill(f'解释诊断 utility:{eid}，哪些结论需要补充验证？')
        expect(page.locator('#assistantSubmit')).to_be_enabled()
        page.locator('#assistantSubmit').click()
        expect(page.locator('#assistantStatus')).to_contain_text('分析已完成', timeout=30000)
        expect(page.locator('#assistantCitations')).to_contain_text(f'utility:{eid}')
        expect(page.locator('#assistantMode')).to_contain_text('演示模式')
        page.screenshot(path=str(OUTPUT / 'assistant.png'), full_page=False)
        page.keyboard.press('Escape'); expect(page.locator('#assistantDrawer')).to_be_hidden()
        page.goto(url + f'/tools?project_id={pid}&tool=jwt')
        expect(page.locator('#toolTitle')).to_have_text('JWT 查看')
        page.locator('#toolSearch').fill('证书'); expect(page.locator('[data-tool="tls"]')).to_be_visible(); expect(page.locator('[data-tool="json"]')).to_be_hidden()
        page.locator('#toolSearch').fill('')
        page.route('**/api/tools/run', lambda route: route.fulfill(content_type='application/json', body=json.dumps({'ok':True,'result':{'HTTP 状态':200},'asset_target':'example.test','project_id':pid,'evidence_id':eid,'evidence_url':f'/projects/{pid}/evidence?selected={eid}#evidence-{eid}'})))
        page.locator('[data-tool="http"]').click(); page.locator('#toolValue').fill('https://example.test/api/health'); page.locator('#toolRun').click()
        expect(page.locator('#toolHandoff')).to_be_visible(); page.locator('#toolAi').click(); expect(page.locator('#assistantQuestion')).to_have_value(re.compile(f'utility:{eid}')); page.keyboard.press('Escape')
        page.locator('#toolRequest').click(); page.wait_for_url('**/requests?selected=*')
        page.set_viewport_size({'width':390,'height':844}); page.goto(url + f'/projects/{pid}/workbench'); assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        page.locator('.assistant-trigger').click(); expect(page.locator('#assistantDrawer')).to_be_visible()
        assert page.locator('#assistantDrawer').bounding_box()['width'] <= 390
        page.screenshot(path=str(OUTPUT / 'assistant-mobile.png'), full_page=False)
        page.keyboard.press('Escape')
        page.set_viewport_size({"width":390,"height":844}); page.goto(url + '/tools#local')
        page.locator('#navToggle').click(); expect(page.locator('#navToggle')).to_have_attribute('aria-expanded','true'); page.keyboard.press('Escape')
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        page.screenshot(path=str(OUTPUT / 'mobile.png'), full_page=True)
        page.set_viewport_size({"width":1536,"height":960})
        page.goto(url + '/decoder')
        page.locator('#analysisInput').fill('%E9%9B%AA%E5%B3%B0')
        page.locator('#analysisForm button:not([type=button])').click()
        expect(page.locator('#analysisText')).to_have_text('雪峰')
        page.screenshot(path=str(OUTPUT / 'decoder.png'), full_page=True)
        page.goto(url + f'/projects/{pid}/scan-center')
        page.locator('#scanTargets').fill('outside.test')
        page.locator('#unifiedScanForm button[type=submit]').click()
        expect(page.locator('#scanNotice')).to_contain_text('授权范围')
        page.locator('#scanTargets').fill('https://example.test')
        page.locator('#unifiedScanForm button[type=submit]').click()
        expect(page.locator('#scanJobs')).to_contain_text('排队中')
        page.locator('#scanJobs').get_by_role('button', name='暂停', exact=True).click()
        expect(page.locator('#scanJobs')).to_contain_text('已暂停')
        page.screenshot(path=str(OUTPUT / 'scan-center.png'), full_page=True)
        page.set_viewport_size({"width":390,"height":844})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 2')
        page.screenshot(path=str(OUTPUT / 'scan-mobile.png'), full_page=True)
        page.set_viewport_size({"width":1536,"height":960})
        page.goto(url + f'/projects/{pid}/findings/new')
        page.locator('[name=title]').fill('普通用户可读取其他订单')
        page.locator('[name=target]').fill('https://example.test/api/orders/1')
        page.locator('[name=description]').fill('使用普通用户身份请求其他用户的订单，响应包含订单信息。')
        page.locator('[name=recommendation]').fill('在服务端校验订单归属。')
        page.screenshot(path=str(OUTPUT / 'manual-finding-editor.png'), full_page=True)
        page.locator('#findingEditor button[type=submit]').click()
        page.wait_for_url(re.compile(r'/findings/\d+$'))
        finding_url=page.url
        page.goto(finding_url + '/edit')
        page.locator('[name=severity]').select_option('high')
        page.locator('#findingEditor button[type=submit]').click()
        page.wait_for_url(finding_url)
        page.locator('form[action$="/manual-evidence"] [name=note]').fill('人工验证：第二个测试账户可读取该订单。')
        page.locator('form[action$="/manual-evidence"] button').click()
        page.wait_for_url(finding_url + '#manual-workflow')
        page.set_viewport_size({"width":390,"height":844})
        page.goto(finding_url + '/edit')
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 2')
        page.screenshot(path=str(OUTPUT / 'manual-finding-mobile.png'), full_page=True)
        page.set_viewport_size({"width":1536,"height":960})
        page.goto(url + f'/projects/{pid}/workflow/request/{rid}')
        page.get_by_role('button',name='AI 分析当前内容',exact=True).click()
        page.wait_for_url(re.compile(r'query_id=\d+'))
        analysis_url=page.url
        for _ in range(30):
            page.goto(analysis_url)
            if page.get_by_text('将研判带入漏洞草稿，人工核对后保存',exact=True).count():break
            page.wait_for_timeout(500)
        expect(page.get_by_text('将研判带入漏洞草稿，人工核对后保存',exact=True)).to_be_visible()
        page.screenshot(path=str(OUTPUT / 'tool-workflow.png'),full_page=True)
        page.goto(url + f'/projects/{pid}/reports/delivery')
        page.locator('[name=finding_ids]').first.check()
        page.get_by_role('button',name='保存交付快照',exact=True).click()
        page.wait_for_url(re.compile(r'#snapshot-'))
        expect(page.get_by_role('link',name='Word',exact=True)).to_be_visible()
        page.locator('h1').click();page.evaluate('window.scrollTo(0,0)')
        page.screenshot(path=str(OUTPUT / 'delivery.png'),full_page=True)
        page.set_viewport_size({"width":390,"height":844})
        page.wait_for_timeout(300)
        assert page.locator('.sidebar').bounding_box()['x']+page.locator('.sidebar').bounding_box()['width']<=1
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 2')
        page.screenshot(path=str(OUTPUT / 'delivery-mobile.png'),full_page=True)
        assert not errors, errors
        browser.close()
        print('Browser checks passed: desktop/mobile layout, workflow tabs, tool search and request handoff, AI queue and citations, scope, pagination, keyboard inspector, draft retry, search ordering. Screenshots:', OUTPUT)
finally:
    server.terminate(); server.wait(timeout=10); log.close(); engine.dispose(); sandbox.cleanup()
