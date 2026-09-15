from __future__ import annotations

import json
from datetime import UTC, datetime
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy.orm import Session

from ..models import PersistentJob, Project, ToolchainRun, ToolchainStep
from .toolchain import CATALOG_BY_ID, PLANS, resolve_executable


MAX_STEP_TARGETS = 100
TERMINAL_JOB_STATUSES = {"done", "error", "cancelled"}


def _now():
    return datetime.now(UTC).replace(tzinfo=None)


def _loads(raw: str, default):
    try:
        value = json.loads(raw or "")
        return value
    except (TypeError, ValueError):
        return default


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _safe_url(value: str) -> str:
    text = str(value or "").strip()
    if "://" not in text:
        return text
    parsed = urlsplit(text)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


def _unique_inputs(rows: list[dict]) -> list[dict]:
    result = []
    seen = set()
    for row in rows:
        target = _safe_url(row.get("target", ""))[:1200]
        ports = sorted({int(p) for p in row.get("ports", []) if str(p).isdigit() and 1 <= int(p) <= 65535})[:1024]
        if not target:
            continue
        key = (target.lower(), tuple(ports))
        if key in seen:
            continue
        seen.add(key); result.append({"target": target, "ports": ports})
        if len(result) >= MAX_STEP_TARGETS:
            break
    return result


def _inputs_for_step(run: ToolchainRun, step: ToolchainStep, previous: ToolchainStep | None) -> list[dict]:
    source_ports = _loads(run.ports_json, [])
    if previous is None:
        target = run.source_target
        if CATALOG_BY_ID[step.tool_id].needs_url and "://" not in target:
            target = f"https://{target}"
        return [{"target": target, "ports": source_ports if CATALOG_BY_ID[step.tool_id].accepts_ports else []}]

    handoff = _loads(previous.result_json, {}).get("handoff", {})
    assets = [str(item.get("target") or "") for item in handoff.get("assets", []) if isinstance(item, dict)]
    endpoints = [str(item.get("url") or "") for item in handoff.get("endpoints", []) if isinstance(item, dict)]
    services = [item for item in handoff.get("services", []) if isinstance(item, dict)]
    rows: list[dict] = []
    if step.tool_id == "nmap" and services:
        grouped: dict[str, list[int]] = {}
        for item in services:
            target = str(item.get("target") or "")
            port = item.get("port")
            if target and isinstance(port, int):
                grouped.setdefault(target, []).append(port)
        rows = [{"target": target, "ports": ports} for target, ports in grouped.items()]
    elif step.tool_id in {"katana", "nuclei"}:
        targets = endpoints or assets
        rows = [{"target": value if "://" in value else f"https://{value}", "ports": []} for value in targets]
    elif step.tool_id == "httpx":
        targets = assets or [str(item.get("target") or "") for item in services]
        rows = [{"target": value, "ports": []} for value in targets]
    else:
        rows = [{"target": value, "ports": source_ports if CATALOG_BY_ID[step.tool_id].accepts_ports else []} for value in (assets or [run.source_target])]
    return _unique_inputs(rows)


def _queue_step(db: Session, run: ToolchainRun, step: ToolchainStep, inputs: list[dict]) -> None:
    from .job_engine import enqueue_job

    if not inputs:
        step.status = "skipped"; step.error = "上一步没有产生可传递的目标。"; step.finished_at = _now(); step.updated_at = _now()
        db.commit(); _advance(db, run, step.position + 1); return
    step.input_json = _json(inputs)
    step.status = "queueing"; step.started_at = _now(); step.finished_at = None; step.error = ""; step.updated_at = _now()
    run.status = "running"; run.current_step = step.position; run.started_at = run.started_at or _now(); run.updated_at = _now(); db.commit()
    ids = []
    for item in inputs:
        payload = {"tool_id": step.tool_id, "ports": item["ports"], "toolchain_run_id": run.id, "toolchain_step_id": step.id}
        job = enqueue_job(db, db.get(Project, run.project_id), "external_tool", target=item["target"], payload=payload, timeout_seconds=900)
        ids.append(job.id)
    step.job_ids_json = _json(ids); step.status = "running"; step.updated_at = _now(); db.commit()
    if ids:
        sync_toolchain_job(db, db.get(PersistentJob, ids[-1]))


def _advance(db: Session, run: ToolchainRun, position: int) -> None:
    step = db.query(ToolchainStep).filter_by(run_id=run.id, position=position).first()
    if not step:
        steps = db.query(ToolchainStep).filter_by(run_id=run.id).all()
        run.status = "done"; run.current_step = run.total_steps; run.finished_at = _now(); run.updated_at = _now()
        run.summary_json = _json({
            "steps": len(steps), "completed": sum(1 for item in steps if item.status == "done"),
            "skipped": sum(1 for item in steps if item.status == "skipped"),
        })
        db.commit(); return
    previous = db.query(ToolchainStep).filter_by(run_id=run.id, position=position - 1).first()
    _queue_step(db, run, step, _inputs_for_step(run, step, previous))


def create_toolchain_run(db: Session, project: Project, plan_id: str, source_target: str, ports: list[int]) -> tuple[ToolchainRun, list[dict]]:
    plan = PLANS.get(plan_id)
    if not plan:
        raise ValueError("未知工具链方案。")
    installed = [tool_id for tool_id in plan["tools"] if resolve_executable(db, tool_id)]
    skipped = [{"tool": tool_id, "reason": "未安装或未配置路径"} for tool_id in plan["tools"] if tool_id not in installed]
    if not installed:
        raise ValueError("该方案所需工具均未安装，请先配置至少一个工具。")
    run = ToolchainRun(project_id=project.id, plan_id=plan_id, name=plan["name"], source_target=source_target, ports_json=_json(ports), status="queued", total_steps=len(installed))
    db.add(run); db.flush()
    for position, tool_id in enumerate(installed, 1):
        db.add(ToolchainStep(run_id=run.id, project_id=project.id, position=position, tool_id=tool_id))
    db.commit(); db.refresh(run)
    _advance(db, run, 1)
    return run, skipped


def sync_toolchain_job(db: Session, job: PersistentJob) -> None:
    payload = _loads(job.payload_json, {})
    run_id, step_id = payload.get("toolchain_run_id"), payload.get("toolchain_step_id")
    if not run_id or not step_id:
        return
    run, step = db.get(ToolchainRun, run_id), db.get(ToolchainStep, step_id)
    if not run or not step or step.status not in {"running", "error"}:
        return
    jobs = [db.get(PersistentJob, value) for value in _loads(step.job_ids_json, [])]
    jobs = [item for item in jobs if item]
    if not jobs or any(item.status not in TERMINAL_JOB_STATUSES for item in jobs):
        return
    failures = [item for item in jobs if item.status in {"error", "cancelled"}]
    if failures:
        step.status = "error"; step.error = "; ".join((item.error or item.status)[:300] for item in failures)[:5000]; step.finished_at = _now(); step.updated_at = _now()
        run.status = "error"; run.error = f"{CATALOG_BY_ID[step.tool_id].name} 步骤失败：{step.error}"; run.finished_at = _now(); run.updated_at = _now(); db.commit(); return
    handoff = {"assets": [], "services": [], "endpoints": []}
    totals = {"records": 0, "assets": 0, "services": 0, "endpoints": 0, "findings": 0}
    for item in jobs:
        result = _loads(item.result_json, {})
        for key in totals:
            totals[key] += int(result.get(key) or 0)
        for key in handoff:
            handoff[key].extend(result.get("handoff", {}).get(key, []))
    for key in handoff:
        handoff[key] = handoff[key][:MAX_STEP_TARGETS]
    step.status = "done"; step.result_json = _json({**totals, "handoff": handoff}); step.finished_at = _now(); step.updated_at = _now(); db.commit()
    _advance(db, run, step.position + 1)


def retry_toolchain_step(db: Session, run: ToolchainRun, step: ToolchainStep) -> None:
    if run.status != "error" or step.status != "error":
        raise ValueError("只有失败的流程步骤可以重试。")
    run.status = "running"; run.error = ""; run.finished_at = None; run.updated_at = _now()
    step.job_ids_json = "[]"; step.result_json = "{}"; step.error = ""; step.status = "pending"; step.finished_at = None; step.updated_at = _now(); db.commit()
    _queue_step(db, run, step, _loads(step.input_json, []))


def run_payload(db: Session, run: ToolchainRun) -> dict:
    steps = db.query(ToolchainStep).filter_by(run_id=run.id).order_by(ToolchainStep.position).all()
    return {
        "id": run.id, "plan_id": run.plan_id, "name": run.name, "target": run.source_target, "status": run.status,
        "current_step": run.current_step, "total_steps": run.total_steps, "error": run.error,
        "created_at": run.created_at, "started_at": run.started_at, "finished_at": run.finished_at,
        "steps": [{"id": step.id, "position": step.position, "tool_id": step.tool_id, "name": CATALOG_BY_ID[step.tool_id].name,
                   "status": step.status, "jobs": _loads(step.job_ids_json, []), "result": _loads(step.result_json, {}), "error": step.error} for step in steps],
    }
