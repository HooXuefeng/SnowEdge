"""Personal workflow hub and contextual AI companion."""
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from starlette.requests import Request

from .db import get_db
from .models import Project, Task, Evidence, WorkspaceDraft, CopilotQuery, PersistentJob
from .ui_i18n import configure_templates
from .services.analyst_copilot import create_copilot_query, copilot_payload, resolve_citation
from .services.job_engine import enqueue_job, run_job_now
from .services.personal_next_steps import suggested_next_steps
from .services.evidence_safety import redact_text

router = APIRouter()
templates = configure_templates(Jinja2Templates(directory=Path(__file__).parent / "templates"))

STAGES = [
    {"id":"collect", "name":"资产收集", "hint":"建立目标和接口清单", "items":[
        ("导入抓包与接口", "HAR / Postman / OpenAPI / Burp", "/imports"),
        ("项目资产", "主机、服务与发现结果", "/attack-surface"),
        ("接口与参数", "筛选接口，进入请求验证", "/endpoints"),
        ("扫描中心", "统一进行批量探测、指纹与规则验证", "/scan-center"),
        ("编辑授权范围", "先核对项目范围，再执行网络操作", "/edit"),
    ]},
    {"id":"verify", "name":"请求验证", "hint":"重放、对比并补齐证据", "items":[
        ("请求工作台", "编辑、重放、历史版本与响应对比", "/requests"),
        ("浏览器观察", "登录后页面与动态接口", "/browser"),
        ("身份与会话", "管理不同测试角色", "/sessions"),
        ("权限差异验证", "比较身份之间的访问结果", "/authorization-matrix"),
    ]},
    {"id":"analyze", "name":"分析研判", "hint":"分清事实、线索与待验证假设", "items":[
        ("手工新建漏洞", "记录人工发现、影响与修复建议", "/findings/new"),
        ("整理漏洞与复测", "修改风险等级、分类与验证结论", "/findings"),
        ("覆盖度与缺口", "查找还没有验证的方向", "/coverage"),
    ]},
    {"id":"deliver", "name":"证据交付", "hint":"确认、复测并输出报告", "items":[
        ("漏洞清单", "确认候选问题和证据质量", "/findings"),
        ("证据中心", "查看来源、内容与关联记录", "/evidence"),
        ("整改与复测", "跟进修复后的验证", "/remediation"),
        ("报告与导出", "交付前检查和文档生成", "/reports"),
    ]},
]


def get_project(db, project_id):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "项目不存在。")
    return project


@router.get("/projects/{project_id}/workbench")
def workbench(project_id: int, request: Request, db: Session = Depends(get_db)):
    project = get_project(db, project_id)
    from .main import _project_context
    context = _project_context(db, project, "workbench")
    context.update({
        "stages": STAGES,
        "next_steps": suggested_next_steps(db, project, limit=3),
        "recent_diagnostics": db.query(Evidence).filter(Evidence.project_id == project_id, Evidence.source_type == "utility_tool").order_by(Evidence.id.desc()).limit(5).all(),
        "recent_activity": db.query(Task).filter(Task.project_id == project_id).order_by(Task.id.desc()).limit(5).all(),
        "active_work": db.query(PersistentJob).filter(PersistentJob.project_id == project_id, PersistentJob.status.in_(["queued", "running", "retry_wait", "cancel_requested"])).order_by(PersistentJob.id.desc()).limit(5).all(),
        "request_drafts": db.query(WorkspaceDraft).filter(WorkspaceDraft.project_id == project_id, WorkspaceDraft.entity_type == "stored_request").order_by(WorkspaceDraft.updated_at.desc()).limit(3).all(),
    })
    return templates.TemplateResponse(request=request, name="workbench.html", context=context)


class AssistantQuestion(BaseModel):
    question: str = Field(min_length=1, max_length=3000)


@router.post("/api/projects/{project_id}/assistant")
def ask_assistant(project_id: int, payload: AssistantQuestion, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    project = get_project(db, project_id)
    question, _ = redact_text(payload.question)
    try:
        row = create_copilot_query(db, project, question)
    except ValueError:
        raise HTTPException(400, "请填写想要讨论的问题。")
    job = enqueue_job(db, project, "copilot_query", target=f"copilot:{row.id}", payload={"query_id":row.id}, priority=90, timeout_seconds=180, max_attempts=2)
    background_tasks.add_task(run_job_now, job.id)
    return {"id":row.id, "job_id":job.id, "status":"queued", "url":f"/projects/{project_id}/copilot?selected={row.id}"}


@router.get("/api/projects/{project_id}/assistant")
def assistant_answer(project_id: int, query_id: int | None = None, db: Session = Depends(get_db)):
    get_project(db, project_id)
    row = db.get(CopilotQuery, query_id) if query_id else db.query(CopilotQuery).filter(CopilotQuery.project_id == project_id).order_by(CopilotQuery.id.desc()).first()
    if row and row.project_id != project_id:
        raise HTTPException(404, "问答不存在。")
    if query_id and not row:
        raise HTTPException(404, "问答不存在。")
    if not row:
        return {"query":None}
    payload = copilot_payload(row)
    if row.status == "error":
        # Upstream exceptions can include provider URLs; expose a useful generic message.
        payload["answer"] = {"answer":"", "gaps":["分析未完成，请检查 AI 配置或到任务中心重试。"], "citations":[], "suggested_views":[]}
    citations = [item for ref in payload.get("answer", {}).get("citations", []) if (item := resolve_citation(db, project_id, ref))]
    return {"query":payload, "citations":citations, "url":f"/projects/{project_id}/copilot?selected={row.id}"}
