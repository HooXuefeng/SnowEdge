from fastapi.testclient import TestClient

from app.db import Base, SessionLocal, engine
from app.main import app
from app.models import (
    Asset, Endpoint, Finding, FindingLifecycle, Project,
    StoredRequest, WorkspaceDraft,
)
from app.services.coverage_matrix import snapshot_coverage


def _seed_project():
    Base.metadata.create_all(bind=engine)
    db=SessionLocal()
    try:
        project=Project(name="V163 中文工作台 QA",scope_text="app.example.test")
        db.add(project);db.commit();db.refresh(project)

        asset=Asset(project_id=project.id,target="app.example.test",kind="hostname")
        db.add(asset);db.commit();db.refresh(asset)
        endpoint=Endpoint(
            asset_id=asset.id,
            url="https://app.example.test/api/order/1001",
            normalized_path="/api/order/{id}",
            method="GET",status_code=200,source="javascript",auth_observed=1,
        )
        db.add(endpoint)

        request=StoredRequest(
            project_id=project.id,name="订单详情",method="GET",
            url="https://app.example.test/api/order/1001",
            headers_json="{}",secret_headers_encrypted="",body="",
            source="manual",policy_class="READ_ONLY",
        )
        db.add(request);db.commit();db.refresh(request)

        finding=Finding(
            project_id=project.id,title="订单详情权限候选问题",severity="medium",
            target="https://app.example.test/api/order/1001",
            description="用于 V1.6.3 中文 UI 验证的候选漏洞。",
            recommendation="补齐权限差异证据后再决定是否确认。",
            source="authorization_testing",finding_state="candidate",
            verification_state="needs_review",
        )
        db.add(finding);db.commit();db.refresh(finding)
        db.add(FindingLifecycle(
            project_id=project.id,finding_id=finding.id,status="retest_ready",
            retest_status="not_queued",
        ))
        db.add(WorkspaceDraft(
            project_id=project.id,entity_type="stored_request",entity_id=request.id,
            content_json="{}",
        ))
        db.commit()
        snapshot_coverage(db,project)
        return project.id, endpoint.id, request.id, finding.id
    finally:
        db.close()


def test_v163_health_and_chinese_navigation():
    pid, _, _, _ = _seed_project()
    with TestClient(app) as client:
        health=client.get("/api/health")
        assert health.status_code==200
        assert health.json()["version"]=="1.8.0"
        page=client.get(f"/projects/{pid}")
        assert page.status_code==200
        for marker in ["项目工作台","继续测试","资产与发现","分析与 AI","凭据保险库","搜索或执行命令"]:
            assert marker in page.text
        assert "V1.8.0" in page.text


def test_v163_project_continue_testing_is_actionable():
    pid, _, request_id, _ = _seed_project()
    with TestClient(app) as client:
        page=client.get(f"/projects/{pid}")
        assert page.status_code==200
        assert "恢复请求草稿" in page.text
        assert "继续漏洞复测" in page.text
        assert "处理待确认漏洞" in page.text
        assert "补齐权限验证" in page.text
        assert f"selected={request_id}" in page.text


def test_v163_endpoint_grid_has_quick_filters_columns_and_inspector():
    pid, _, _, _ = _seed_project()
    with TestClient(app) as client:
        page=client.get(f"/projects/{pid}/endpoints")
        assert page.status_code==200
        for marker in ["快捷筛选","列设置","已观察鉴权","JS 来源","data-inspector-kind=\"接口详情\""]:
            assert marker in page.text
        assert "发送到请求工作台" in page.text


def test_v163_finding_grid_has_chinese_filters_and_inspector():
    pid, _, _, _ = _seed_project()
    with TestClient(app) as client:
        page=client.get(f"/projects/{pid}/findings")
        assert page.status_code==200
        for marker in ["待确认","已确认","需补证据","data-inspector-kind=\"漏洞详情\"","证据质量"]:
            assert marker in page.text


def test_v163_coverage_dimensions_have_direct_actions():
    pid, _, _, _ = _seed_project()
    with TestClient(app) as client:
        page=client.get(f"/projects/{pid}/coverage")
        assert page.status_code==200
        assert "已测试内容 · 当前缺口" in page.text
        assert "去补身份" in page.text or "开始权限验证" in page.text
        assert "查看测试覆盖度" not in page.text  # this page itself should show concrete actions, not a circular CTA


def test_v163_request_workspace_exposes_keyboard_shortcuts():
    pid, _, request_id, _ = _seed_project()
    with TestClient(app) as client:
        page=client.get(f"/projects/{pid}/requests?selected={request_id}")
        assert page.status_code==200
        for marker in ["快捷键","Ctrl+Enter","Ctrl+S","Alt+1","Alt+4","原始请求","结构化编辑"]:
            assert marker in page.text
        assert 'id="requestReplayForm"' in page.text


def test_v163_command_palette_is_chinese_and_supports_actions():
    pid, _, _, _ = _seed_project()
    with TestClient(app) as client:
        page=client.get(f"/projects/{pid}")
        assert page.status_code==200
        for marker in ["window.WORKSPACE_COMMANDS","打开请求工作台","刷新测试覆盖度","打开凭据保险库"]:
            assert marker in page.text
        js=client.get("/static/app.js")
        assert js.status_code==200
        assert "工作台命令" in js.text
        assert "openEntityInspector" in js.text
        assert "grid-column-menu" in js.text


def test_v163_chinese_project_export_filenames_are_utf8_safe():
    pid, _, _, _ = _seed_project()
    with TestClient(app) as client:
        for url in [f"/projects/{pid}/export", f"/projects/{pid}/reports/export.docx"]:
            response = client.get(url)
            assert response.status_code == 200
            cd = response.headers.get("content-disposition", "")
            assert "filename*=UTF-8''" in cd
            assert "project_" in cd
            assert response.content[:2] == b"PK"
