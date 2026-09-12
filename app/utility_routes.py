from pathlib import Path
import asyncio
import ipaddress
import json
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from starlette.requests import Request

from .db import get_db
from .models import Asset, Project, Task, Evidence, StoredRequest
from .scope import target_in_scope
from .ui_i18n import configure_templates
from .services.utility_tools import TOOLS, TOOL_MAP, local_tool, network_tool, parse_target
from .services.network_routes import httpx_proxy_url
from .services.evidence_safety import redact_object
from .services.evidence_chain import ensure_evidence_integrity

router = APIRouter()
templates = configure_templates(Jinja2Templates(directory=Path(__file__).parent / "templates"))


class ToolInput(BaseModel):
    kind: str = Field(max_length=30)
    value: str = Field(min_length=1, max_length=32000)
    project_id: int | None = None


@router.get("/tools")
def tools_page(request: Request, project_id: int | None = None, db: Session = Depends(get_db)):
    project = db.get(Project, project_id) if project_id else None
    if project_id and not project:
        raise HTTPException(404, "项目不存在。")
    context = {"active_nav": "tools"}
    if project:
        from .main import _project_context
        context = _project_context(db, project, "tools")
    # Keep bookmarked legacy tools working while the normal catalog uses the decoder entry.
    visible_tools=[tool for tool in TOOLS if tool['id'] not in {'base64','url_decode','jwt'} or tool['id']==request.query_params.get('tool')]
    context.update({"tools": visible_tools, "tool_projects": db.query(Project).order_by(Project.id.desc()).all()})
    return templates.TemplateResponse(request=request, name="tools.html", context=context)


@router.post("/api/tools/run")
async def run_tool(payload: ToolInput, request: Request, db: Session = Depends(get_db)):
    tool = TOOL_MAP.get(payload.kind)
    if not tool:
        raise HTTPException(400, "工具不存在。")
    if not tool["network"]:
        try:
            return {"ok": True, "result": local_tool(payload.kind, payload.value)}
        except (ValueError, UnicodeError, RecursionError):
            raise HTTPException(400, "输入格式不正确，请核对所选工具需要的内容。")
    project = db.get(Project, payload.project_id) if payload.project_id else None
    if not project:
        raise HTTPException(400, "请先选择项目，网络诊断会使用该项目的授权范围。")
    slots = request.app.state.tool_slots
    if slots.locked():
        raise HTTPException(429, "当前有多个诊断正在运行，请稍后重试。")
    try:
        async with slots:
            result = await network_tool(payload.kind, payload.value, project.scope_text.splitlines(), httpx_proxy_url(db, project.id))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except (OSError, TimeoutError):
        raise HTTPException(400, "连接失败或超时，请检查域名解析、端口及网络连接。")
    except Exception:
        # Do not expose proxy credentials or raw URLs in exception messages.
        raise HTTPException(400, "诊断未完成，请检查网络、代理和证书配置后重试。")
    host, _, target_url = parse_target(payload.value)
    # Retain a reusable URL without credentials, query values or fragments.
    safe_url = urlsplit(target_url)._replace(query='', fragment='').geturl()
    task = Task(project_id=project.id, action=f"utility_{payload.kind}", target=host, policy_class="READ_ONLY", status="done", detail=f"已完成{tool['name']}；脱敏诊断结果已保存至证据中心。")
    db.add(task)
    db.flush()
    safe_result_data, _ = redact_object(result)
    safe_result = json.dumps(safe_result_data, ensure_ascii=False)
    # Reuse the same displayed, bounded diagnostic data; never save raw input.
    safe_data = {"tool":payload.kind, "label":tool['name'], "target":safe_url, "result":safe_result_data}
    content = json.dumps(safe_data, ensure_ascii=False)
    if len(content) > 20000:
        safe_data['result'] = {"摘要":safe_result[:12000], "截断":True}
        content = json.dumps(safe_data, ensure_ascii=False)
    evidence = Evidence(project_id=project.id, task_id=task.id, source_type="utility_tool", source_id=task.id, kind=f"utility_{payload.kind}", content=content, redaction_state="redacted")
    db.add(evidence)
    db.flush()
    ensure_evidence_integrity(db, evidence)
    db.commit()
    return {"ok": True, "result": result, "asset_target": host, "project_id": project.id, "evidence_id":evidence.id, "evidence_url":f"/projects/{project.id}/evidence?selected={evidence.id}#evidence-{evidence.id}"}


@router.post("/api/projects/{project_id}/diagnostics/{evidence_id}/request")
def diagnostic_to_request(project_id: int, evidence_id: int, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    evidence = db.get(Evidence, evidence_id)
    if not project or not evidence or evidence.project_id != project_id or evidence.source_type != 'utility_tool':
        raise HTTPException(404, "诊断记录不存在。")
    try:
        data = json.loads(evidence.content)
        _, _, url = parse_target(data['target'])
    except (ValueError, KeyError, TypeError):
        raise HTTPException(400, "诊断没有可复用的目标地址。")
    if not target_in_scope(url, project.scope_text.splitlines()):
        raise HTTPException(400, "目标已不在项目授权范围内。")
    source = f"diagnostic:{evidence.id}"
    stored = db.query(StoredRequest).filter(StoredRequest.project_id == project_id, StoredRequest.source == source).first()
    if not stored:
        from .services.request_workspace import create_stored_request
        stored = create_stored_request(db, project_id, f"诊断 #{evidence.id} · 后续验证", 'GET', url, source=source, explicit_read_only=True)
    return {"url":f"/projects/{project_id}/requests?selected={stored.id}", "message":"已创建请求草稿；查询参数需重新补齐，尚未发送请求。"}


@router.post("/api/tools/save-asset")
def save_asset(payload: ToolInput, db: Session = Depends(get_db)):
    project = db.get(Project, payload.project_id) if payload.project_id else None
    if not project:
        raise HTTPException(400, "请选择项目。")
    try:
        host, _, _ = parse_target(payload.value)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    target = f"https://[{host}]" if ":" in host else host
    if not target_in_scope(target, project.scope_text.splitlines()):
        raise HTTPException(400, "目标不在当前项目授权范围内。")
    asset = db.query(Asset).filter(Asset.project_id == project.id, Asset.target == host).first()
    if not asset:
        try:
            ipaddress.ip_address(host)
            kind = "ip"
        except ValueError:
            kind = "hostname"
        asset = Asset(project_id=project.id, target=host, kind=kind)
        db.add(asset)
        db.commit()
    return {"ok": True, "url": f"/projects/{project.id}/attack-surface", "message": "已加入项目资产"}
