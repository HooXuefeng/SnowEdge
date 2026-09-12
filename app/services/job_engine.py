from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import socket
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from ..config import settings
from ..db import SessionLocal
from ..models import (
    AgentRun,
    BrowserSession,
    BatchAssessment,
    BatchAssessmentItem,
    CopilotQuery,
    Evidence,
    FindingLifecycle,
    JobWorker,
    PersistentJob,
    PersistentJobEvent,
    Project,
    Task,
)
from ..scope import target_in_scope


TERMINAL_STATUSES = {"done", "error", "cancelled"}
ACTIVE_STATUSES = {"queued", "running", "retry_wait", "cancel_requested", "pause_requested", "paused"}
ALLOWED_JOB_KINDS = {
    "scan_engine",
    "project_scan",
    "browser_observe",
    "copilot_query",
    "agent_team",
    "proof_retest",
    "endpoint_sync",
    "knowledge_refresh",
    "authorization_matrix",
    "batch_scan",
}

_claim_lock: asyncio.Lock | None = None

RESOURCE_CLASS_BY_KIND = {
    "scan_engine": "scan",
    "project_scan": "scan",
    "batch_scan": "scan",
    "browser_observe": "browser",
    "copilot_query": "ai",
    "agent_team": "ai",
    "authorization_matrix": "validation",
    "proof_retest": "validation",
    "endpoint_sync": "local",
    "knowledge_refresh": "local",
}
RESOURCE_LIMITS = {"scan": 2, "browser": 1, "ai": 2, "validation": 2, "local": 4}


def job_resource_class(kind: str) -> str:
    return RESOURCE_CLASS_BY_KIND.get(kind, "local")


def resource_gate_snapshot(db: Session) -> dict:
    running = db.query(PersistentJob).filter(PersistentJob.status.in_(["running", "pause_requested", "cancel_requested"])).all()
    counts = {}
    for job in running:
        cls = job_resource_class(job.kind)
        counts[cls] = counts.get(cls, 0) + 1
    return {name: {"running": counts.get(name, 0), "limit": limit} for name, limit in RESOURCE_LIMITS.items()}


def _resource_slot_available(db: Session, kind: str) -> bool:
    cls = job_resource_class(kind); limit = RESOURCE_LIMITS.get(cls, 4)
    kinds = [k for k, v in RESOURCE_CLASS_BY_KIND.items() if v == cls]
    count = db.query(PersistentJob).filter(PersistentJob.status.in_(["running", "pause_requested", "cancel_requested"]), PersistentJob.kind.in_(kinds)).count()
    return count < limit



def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _scope_rules(project: Project) -> list[str]:
    return [x.strip() for x in project.scope_text.splitlines() if x.strip()]


def _scope_snapshot(project: Project) -> tuple[str, str]:
    rules = _scope_rules(project)
    raw = json.dumps(rules, ensure_ascii=False, separators=(",", ":"))
    return raw, hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, default=str)


def _loads(raw: str, default):
    try:
        return json.loads(raw or "")
    except Exception:
        return default


def add_job_event(db: Session, job: PersistentJob, event_type: str, detail: str = "") -> None:
    db.add(PersistentJobEvent(
        job_id=job.id,
        event_type=event_type[:80],
        status=job.status[:60],
        detail=detail[:5000],
    ))


def enqueue_job(
    db: Session,
    project: Project | None,
    kind: str,
    *,
    target: str = "",
    payload: dict | None = None,
    priority: int = 100,
    max_attempts: int | None = None,
    timeout_seconds: int | None = None,
) -> PersistentJob:
    if kind not in ALLOWED_JOB_KINDS:
        raise ValueError("Unsupported persistent job kind.")

    if project:
        scope_json, scope_hash = _scope_snapshot(project)
        project_id = project.id
    else:
        scope_json, scope_hash, project_id = "[]", "", None

    safe_payload = payload or {}
    # Job payloads are intentionally reference-only. Reject obvious secret-bearing fields.
    forbidden = {"authorization", "cookie", "password", "secret", "token", "api_key", "apikey", "body", "headers"}
    if any(str(k).lower() in forbidden for k in safe_payload):
        raise ValueError("Persistent job payload must not contain secret-bearing fields or request bodies.")

    row = PersistentJob(
        project_id=project_id,
        kind=kind,
        target=target[:1200],
        payload_json=_json(safe_payload),
        scope_snapshot_json=scope_json,
        scope_hash=scope_hash,
        status="queued",
        priority=max(0, min(int(priority), 1000)),
        attempts=0,
        max_attempts=max(1, min(int(max_attempts or settings.job_default_max_attempts), 10)),
        timeout_seconds=max(5, min(int(timeout_seconds or settings.job_default_timeout_seconds), 3600)),
        updated_at=_utcnow(),
    )
    db.add(row)
    db.flush()
    add_job_event(db, row, "queued", f"Persistent job queued: {kind}.")
    db.commit()
    db.refresh(row)
    return row


def recover_orphaned_jobs(db: Session) -> int:
    """Recover only jobs whose lease has expired.

    A live external worker may legitimately own a running job while the web
    process restarts, so V1.3 no longer requeues every running job blindly.
    """
    now = _utcnow()
    rows = (
        db.query(PersistentJob)
        .filter(PersistentJob.status.in_(["running", "cancel_requested", "pause_requested"]))
        .all()
    )
    recovered = 0
    for row in rows:
        expired = row.lease_expires_at is None or row.lease_expires_at <= now
        if not expired:
            continue
        previous_worker = row.worker_id
        if row.status == "pause_requested":
            row.status = "paused"
            add_job_event(db, row, "paused", "Expired owner; checkpoint retained.")
        elif row.status == "cancel_requested":
            row.status = "cancelled"
            row.finished_at = now
            add_job_event(
                db, row, "cancelled",
                f"Expired lease recovered from worker {previous_worker or 'unknown'}; cancellation finalized."
            )
        else:
            row.status = "queued"
            row.error = ""
            row.started_at = None
            add_job_event(
                db, row, "recovered",
                f"Expired lease recovered after restart/worker loss from worker {previous_worker or 'unknown'}."
            )
        row.worker_id = ""
        row.lease_token = ""
        row.lease_expires_at = None
        row.heartbeat_at = None
        row.updated_at = now
        recovered += 1
    if recovered:
        db.commit()
    return recovered


def register_worker(
    db: Session,
    worker_id: str,
    capabilities: list[str] | None = None,
) -> JobWorker:
    row = db.query(JobWorker).filter(JobWorker.worker_id == worker_id).first()
    now = _utcnow()
    if not row:
        row = JobWorker(
            worker_id=worker_id[:120],
            hostname=socket.gethostname()[:240],
            pid=os.getpid(),
            status="online",
            capabilities_json=_json(capabilities or sorted(ALLOWED_JOB_KINDS)),
            last_heartbeat_at=now,
            started_at=now,
        )
        db.add(row)
    else:
        row.hostname = socket.gethostname()[:240]
        row.pid = os.getpid()
        row.status = "online"
        row.capabilities_json = _json(capabilities or sorted(ALLOWED_JOB_KINDS))
        row.last_heartbeat_at = now
        row.stopped_at = None
    db.commit()
    db.refresh(row)
    return row


def heartbeat_worker(
    db: Session,
    worker_id: str,
    active_job_id: int | None = None,
) -> None:
    row = db.query(JobWorker).filter(JobWorker.worker_id == worker_id).first()
    if not row:
        row = register_worker(db, worker_id)
    row.status = "online"
    row.active_job_id = active_job_id
    row.last_heartbeat_at = _utcnow()
    db.commit()


def stop_worker(db: Session, worker_id: str) -> None:
    row = db.query(JobWorker).filter(JobWorker.worker_id == worker_id).first()
    if row:
        row.status = "offline"
        row.active_job_id = None
        row.last_heartbeat_at = _utcnow()
        row.stopped_at = _utcnow()
        db.commit()


def _claim_specific_job(
    db: Session,
    job_id: int,
    worker_id: str,
    *,
    event_type: str = "started",
) -> tuple[PersistentJob, str] | None:
    """Atomically transition one queued row to running.

    The `status == queued` predicate is the cross-process compare-and-swap
    guard for SQLite. PostgreSQL callers may already hold a row lock, but use
    the same predicate for defense in depth.
    """
    now = _utcnow()
    token = secrets.token_urlsafe(24)
    lease_expires = now + timedelta(seconds=max(15, settings.job_lease_seconds))

    result = db.execute(
        update(PersistentJob)
        .where(
            PersistentJob.id == job_id,
            PersistentJob.status == "queued",
        )
        .values(
            status="running",
            attempts=PersistentJob.attempts + 1,
            started_at=func.coalesce(PersistentJob.started_at, now),
            worker_id=worker_id[:120],
            lease_token=token,
            heartbeat_at=now,
            lease_expires_at=lease_expires,
            updated_at=now,
        )
    )
    if result.rowcount != 1:
        db.rollback()
        return None

    db.commit()
    job = db.get(PersistentJob, job_id)
    if not job:
        return None
    add_job_event(
        db,
        job,
        event_type,
        f"Worker {worker_id} acquired lease; attempt {job.attempts}/{job.max_attempts}.",
    )
    db.commit()
    return job, token

def heartbeat_job(job_id: int, worker_id: str, lease_token: str) -> bool:
    db = SessionLocal()
    try:
        job = db.get(PersistentJob, job_id)
        if (
            not job
            or job.status not in {"running", "cancel_requested", "pause_requested"}
            or job.worker_id != worker_id
            or job.lease_token != lease_token
        ):
            return False
        now = _utcnow()
        job.heartbeat_at = now
        job.lease_expires_at = now + timedelta(seconds=max(15, settings.job_lease_seconds))
        job.updated_at = now
        worker = db.query(JobWorker).filter(JobWorker.worker_id == worker_id).first()
        if worker:
            worker.last_heartbeat_at = now
            worker.active_job_id = job.id
            worker.status = "online"
        db.commit()
        return True
    finally:
        db.close()

def cancel_job(db: Session, job: PersistentJob) -> PersistentJob:
    if job.status in TERMINAL_STATUSES:
        return job
    if job.status in {"queued", "retry_wait", "paused"}:
        job.status = "cancelled"
        job.finished_at = _utcnow()
        _cancel_linked_state(db, job)
        add_job_event(db, job, "cancelled", "Cancelled before execution.")
    elif job.status in {"running", "pause_requested"}:
        job.status = "cancel_requested"
        add_job_event(db, job, "cancel_requested", "Cancellation requested; active coroutine cancellation is best-effort.")
    job.updated_at = _utcnow()
    db.commit()
    db.refresh(job)
    return job


def retry_job(db: Session, job: PersistentJob) -> PersistentJob:
    if job.status not in {"error", "cancelled"}:
        raise ValueError("Only failed or cancelled jobs can be retried.")
    job.status = "queued"
    job.error = ""
    if job.kind != "scan_engine":
        job.result_json = "{}"
    job.next_run_at = None
    job.started_at = None
    job.finished_at = None
    job.updated_at = _utcnow()
    add_job_event(db, job, "manual_retry", "Job manually requeued.")
    db.commit()
    db.refresh(job)
    return job


def _cancel_linked_state(db: Session, job: PersistentJob) -> None:
    payload = _loads(job.payload_json, {})
    if job.kind == "browser_observe":
        row = db.get(BrowserSession, payload.get("session_id"))
        if row and row.project_id == job.project_id and row.status in {"queued", "running"}:
            row.status = "cancelled"
            row.error = "Cancelled from Job Center."
    elif job.kind == "copilot_query":
        row = db.get(CopilotQuery, payload.get("query_id"))
        if row and row.project_id == job.project_id and row.status in {"queued", "running"}:
            row.status = "cancelled"
    elif job.kind == "agent_team":
        row = db.get(AgentRun, payload.get("parent_agent_run_id"))
        if row and row.project_id == job.project_id and row.status in {"queued", "running"}:
            row.status = "cancelled"
            row.summary = "Cancelled from Job Center."
    elif job.kind == "proof_retest":
        row = db.get(FindingLifecycle, payload.get("lifecycle_id"))
        if row and row.project_id == job.project_id and row.retest_status in {"queued", "running"}:
            row.retest_status = "cancelled"
    elif job.kind == "batch_scan":
        batch = db.get(BatchAssessment, payload.get("batch_id"))
        if batch and batch.project_id == job.project_id:
            batch.status = "cancelled"
            for item in db.query(BatchAssessmentItem).filter(BatchAssessmentItem.batch_id == batch.id, BatchAssessmentItem.status.in_(["queued","running"])).all():
                item.status = "cancelled"
                item.detail = "Cancelled from Job Center."
                item.finished_at = _utcnow()


async def _handle_project_scan(db: Session, job: PersistentJob, project: Project, payload: dict) -> dict:
    from ..orchestrator import run_authorized_scan
    from .assessment_memory import refresh_assessment_memory
    from .endpoint_inventory import sync_project_endpoint_inventory
    from .knowledge_graph import rebuild_knowledge_graph

    target = job.target.strip()
    if not target_in_scope(target, _scope_rules(project)):
        raise ValueError("Job blocked: scan target is outside the project's current authorized scope.")

    parent_task_id = payload.get("parent_task_id")
    parent = db.get(Task, parent_task_id) if parent_task_id else None
    if parent and parent.project_id == project.id:
        parent.status = "running"
        parent.detail = f"Persistent Job #{job.id} running."
        db.commit()
    try:
        await run_authorized_scan(db, project, target)
        endpoint_summary = sync_project_endpoint_inventory(db, project.id)
        from .fingerprint_engine import refresh_project_fingerprints
        fingerprint_summary = refresh_project_fingerprints(db, project)
        rebuild_knowledge_graph(db, project.id)
        refresh_assessment_memory(db, project.id)
        if parent:
            parent.status = "done"
            parent.detail = f"Persistent Job #{job.id} completed; endpoint inventory synchronized."
            db.commit()
        return {"target": target, "endpoint_inventory": endpoint_summary, "fingerprints": fingerprint_summary}
    except Exception:
        if parent:
            parent.status = "error"
            parent.detail = f"Persistent Job #{job.id} failed."
            db.commit()
        raise


async def _handle_browser(db: Session, job: PersistentJob, project: Project, payload: dict) -> dict:
    from ..models import Identity
    from .assessment_memory import refresh_assessment_memory
    from .. import browser_routes as browser_module
    from .endpoint_inventory import sync_project_endpoint_inventory
    from .knowledge_graph import rebuild_knowledge_graph

    session = db.get(BrowserSession, payload.get("session_id"))
    if not session or session.project_id != project.id:
        raise ValueError("Browser session not found.")
    identity = db.get(Identity, payload.get("identity_id")) if payload.get("identity_id") else None
    if identity and identity.project_id != project.id:
        raise ValueError("Identity does not belong to this project.")
    await browser_module.capture_browser_session(db, project, session, identity)
    sync_project_endpoint_inventory(db, project.id)
    rebuild_knowledge_graph(db, project.id)
    refresh_assessment_memory(db, project.id)
    if session.status not in {"done", "unavailable"}:
        raise RuntimeError(session.error or f"Browser session ended as {session.status}.")
    return {"browser_session_id": session.id, "status": session.status}


async def _handle_copilot(db: Session, job: PersistentJob, project: Project, payload: dict) -> dict:
    from .analyst_copilot import run_copilot_query
    row = db.get(CopilotQuery, payload.get("query_id"))
    if not row or row.project_id != project.id:
        raise ValueError("Copilot query not found.")
    await run_copilot_query(db, project, row)
    if row.status != "done":
        raise RuntimeError("Copilot query did not complete.")
    return {"query_id": row.id, "citations": row.citation_count, "drift": row.drift_count}


async def _handle_agent_team(db: Session, job: PersistentJob, project: Project, payload: dict) -> dict:
    from .multi_agent import run_specialist_team
    parent = await run_specialist_team(
        db, project, parent_agent_run_id=payload.get("parent_agent_run_id")
    )
    if parent.status != "done":
        raise RuntimeError(parent.summary or "Specialist team did not complete.")
    return {"agent_run_id": parent.id, "summary": parent.summary}


async def _handle_proof_retest(db: Session, job: PersistentJob, project: Project, payload: dict) -> dict:
    from .assessment_memory import refresh_assessment_memory
    from .coverage_matrix import snapshot_coverage
    from .knowledge_graph import rebuild_knowledge_graph
    from .remediation import retest_lifecycle

    lifecycle = db.get(FindingLifecycle, payload.get("lifecycle_id"))
    if not lifecycle or lifecycle.project_id != project.id:
        raise ValueError("Finding lifecycle not found.")
    run = await retest_lifecycle(db, project, lifecycle)
    rebuild_knowledge_graph(db, project.id)
    refresh_assessment_memory(db, project.id)
    snapshot_coverage(db, project)
    if run.status == "error":
        raise RuntimeError(run.detail or "Proof Capsule retest failed.")
    return {"lifecycle_id": lifecycle.id, "retest_run_id": run.id, "status": run.status}


async def _handle_authorization_matrix(db: Session, job: PersistentJob, project: Project, payload: dict) -> dict:
    from ..models import AuthorizationMatrixRun
    from .assessment_memory import refresh_assessment_memory
    from .authorization_matrix import execute_matrix_run, matrix_run_payload
    from .coverage_matrix import snapshot_coverage
    from .knowledge_graph import rebuild_knowledge_graph

    matrix = db.get(AuthorizationMatrixRun, payload.get("matrix_run_id"))
    if not matrix or matrix.project_id != project.id:
        raise ValueError("Authorization Matrix run not found.")
    await execute_matrix_run(db, project, matrix)
    rebuild_knowledge_graph(db, project.id)
    refresh_assessment_memory(db, project.id)
    snapshot_coverage(db, project)
    return matrix_run_payload(matrix)


async def _handle_batch_scan(db: Session, job: PersistentJob, project: Project, payload: dict) -> dict:
    from ..orchestrator import run_authorized_scan
    from .assessment_memory import refresh_assessment_memory
    from .batch_assessment import update_batch_counts
    from .endpoint_inventory import sync_project_endpoint_inventory
    from .fingerprint_engine import refresh_project_fingerprints
    from .knowledge_graph import rebuild_knowledge_graph

    batch = db.get(BatchAssessment, payload.get("batch_id"))
    if not batch or batch.project_id != project.id:
        raise ValueError("Batch assessment not found.")

    # A Batch is bound to the profile selected when it was created. Re-apply
    # that profile at execution time so a queued/recovered job cannot silently
    # inherit unrelated ProjectSkill changes made after the Batch was queued.
    if batch.scan_profile_id:
        from ..models import ScanProfile
        from .scan_profiles import apply_profile
        profile = db.get(ScanProfile, batch.scan_profile_id)
        if not profile:
            raise ValueError("Batch Scan Profile no longer exists.")
        apply_profile(db, project, profile)

    batch.status = "running"; db.commit()
    items = db.query(BatchAssessmentItem).filter(BatchAssessmentItem.batch_id == batch.id).order_by(BatchAssessmentItem.id.asc()).all()
    errors = []
    for item in items:
        if item.status == "skipped":
            continue
        if not target_in_scope(item.target, _scope_rules(project)):
            item.status = "skipped"; item.detail = "Scope changed: target is no longer authorized."; item.finished_at = _utcnow(); db.commit(); continue
        item.status = "running"; item.started_at = _utcnow(); db.commit()
        try:
            await run_authorized_scan(db, project, item.target)
            item.status = "done"; item.detail = "Authorized safe assessment completed."
            item.result_json = _json({"target": item.target, "status": "done"})
        except Exception as exc:
            item.status = "error"; item.detail = f"{type(exc).__name__}: {exc}"[:5000]
            item.result_json = _json({"target": item.target, "status": "error", "error": item.detail})
            errors.append({"target": item.target, "error": item.detail})
        item.finished_at = _utcnow(); db.commit(); update_batch_counts(db, batch)
    endpoint_summary = sync_project_endpoint_inventory(db, project.id)
    fingerprints = refresh_project_fingerprints(db, project)
    rebuild_knowledge_graph(db, project.id); refresh_assessment_memory(db, project.id)
    update_batch_counts(db, batch)
    batch.status = "done" if batch.failed_targets == 0 else "done_with_errors"
    batch.finished_at = _utcnow()
    batch.summary_json = _json({"errors": errors, "endpoint_inventory": endpoint_summary, "fingerprints": fingerprints, "resource_gate": "scan", "max_parallel": 1})
    db.commit()
    return {"batch_id": batch.id, "status": batch.status, "completed": batch.completed_targets, "failed": batch.failed_targets, "skipped": batch.skipped_targets}


async def _handle_endpoint_sync(db: Session, job: PersistentJob, project: Project, payload: dict) -> dict:
    from .endpoint_inventory import sync_project_endpoint_inventory
    return sync_project_endpoint_inventory(db, project.id)


async def _handle_knowledge_refresh(db: Session, job: PersistentJob, project: Project, payload: dict) -> dict:
    from .assessment_memory import refresh_assessment_memory
    from .coverage_matrix import snapshot_coverage
    from .knowledge_graph import rebuild_knowledge_graph

    graph = rebuild_knowledge_graph(db, project.id)
    memory = refresh_assessment_memory(db, project.id)
    coverage = snapshot_coverage(db, project)
    return {"graph": graph, "memory": memory, "coverage_score": coverage.score}


from .scan_engine import run_scan

HANDLERS = {
    "scan_engine": run_scan,
    "project_scan": _handle_project_scan,
    "browser_observe": _handle_browser,
    "copilot_query": _handle_copilot,
    "agent_team": _handle_agent_team,
    "proof_retest": _handle_proof_retest,
    "endpoint_sync": _handle_endpoint_sync,
    "knowledge_refresh": _handle_knowledge_refresh,
    "authorization_matrix": _handle_authorization_matrix,
    "batch_scan": _handle_batch_scan,
}


async def _claim_next_job(worker_id: str) -> tuple[int, str] | None:
    global _claim_lock
    if _claim_lock is None:
        _claim_lock = asyncio.Lock()

    async with _claim_lock:
        db = SessionLocal()
        try:
            now = _utcnow()
            recover_orphaned_jobs(db)

            retry_rows = (
                db.query(PersistentJob)
                .filter(
                    PersistentJob.status == "retry_wait",
                    PersistentJob.next_run_at.is_not(None),
                    PersistentJob.next_run_at <= now,
                )
                .all()
            )
            for row in retry_rows:
                row.status = "queued"
                row.next_run_at = None
                add_job_event(db, row, "retry_due", "Retry delay elapsed; job returned to queue.")
            if retry_rows:
                db.commit()

            if db.bind and db.bind.dialect.name == "postgresql":
                stmt = (
                    select(PersistentJob)
                    .where(PersistentJob.status == "queued")
                    .order_by(PersistentJob.priority.asc(), PersistentJob.id.asc())
                    .with_for_update(skip_locked=True)
                    .limit(20)
                )
                candidates = list(db.execute(stmt).scalars().all())
            else:
                candidates = (
                    db.query(PersistentJob)
                    .filter(PersistentJob.status == "queued")
                    .order_by(PersistentJob.priority.asc(), PersistentJob.id.asc())
                    .limit(20).all()
                )
            row = next((candidate for candidate in candidates if _resource_slot_available(db, candidate.kind)), None)

            if not row:
                heartbeat_worker(db, worker_id, None)
                return None

            claimed = _claim_specific_job(db, row.id, worker_id)
            if not claimed:
                # Another process won the compare-and-swap after our read.
                heartbeat_worker(db, worker_id, None)
                return None
            claimed_row, lease_token = claimed
            heartbeat_worker(db, worker_id, claimed_row.id)
            return claimed_row.id, lease_token
        finally:
            db.close()


async def _lease_heartbeat_loop(job_id: int, worker_id: str, lease_token: str) -> None:
    interval = max(2, min(settings.job_heartbeat_seconds, settings.job_lease_seconds // 2))
    while True:
        await asyncio.sleep(interval)
        if not heartbeat_job(job_id, worker_id, lease_token):
            return


def _attach_new_evidence_to_job(db: Session, job: PersistentJob, after_id: int) -> int:
    from .evidence_chain import ensure_evidence_integrity

    rows = db.query(Evidence).filter(Evidence.id > after_id).order_by(Evidence.id.asc()).all()
    attached = 0
    for evidence in rows:
        ensure_evidence_integrity(db, evidence)
        if evidence.project_id != job.project_id:
            continue
        if evidence.job_id is None:
            evidence.job_id = job.id
            if not evidence.source_type:
                evidence.source_type = "PersistentJob"
                evidence.source_id = job.id
            db.commit()
            ensure_evidence_integrity(db, evidence)
            attached += 1
    return attached


async def process_job(job_id: int, worker_id: str = "worker", lease_token: str = "") -> None:
    db = SessionLocal()
    heartbeat_task = None
    try:
        job = db.get(PersistentJob, job_id)
        if not job or job.status != "running":
            return
        if worker_id and job.worker_id and job.worker_id != worker_id:
            return
        if lease_token and job.lease_token != lease_token:
            return

        worker_id = job.worker_id or worker_id
        lease_token = job.lease_token or lease_token
        heartbeat_task = asyncio.create_task(
            _lease_heartbeat_loop(job_id, worker_id, lease_token)
        )

        project = db.get(Project, job.project_id) if job.project_id else None
        if job.project_id and not project:
            raise ValueError("Project no longer exists.")
        handler = HANDLERS.get(job.kind)
        if not handler:
            raise ValueError("No handler registered for job kind.")
        payload = _loads(job.payload_json, {})
        evidence_before_id = db.query(func.max(Evidence.id)).scalar() or 0
        try:
            result = await asyncio.wait_for(
                handler(db, job, project, payload),
                timeout=job.timeout_seconds,
            )
            db.refresh(job)
            attached_evidence = _attach_new_evidence_to_job(db, job, evidence_before_id)
            if isinstance(result, dict):
                result.setdefault("evidence_attached_to_job", attached_evidence)
            if job.worker_id != worker_id or job.lease_token != lease_token:
                raise RuntimeError("Job lease ownership changed during execution.")
            if job.status == "pause_requested":
                job.status = "paused"
                job.result_json = _json(result or {})
                add_job_event(db, job, "paused", "Scan checkpoint saved; no further requests until resumed.")
            elif job.status == "cancel_requested":
                job.status = "cancelled"
                _cancel_linked_state(db, job)
                add_job_event(db, job, "cancelled", "Cancellation request observed after handler returned.")
            else:
                job.status = "done"
                job.result_json = _json(result or {})
                add_job_event(db, job, "completed", f"Worker {worker_id} completed the job.")
            job.finished_at = _utcnow()
            job.updated_at = _utcnow()
            job.lease_expires_at = None
            job.heartbeat_at = _utcnow()
            db.commit()
        except Exception as exc:
            db.rollback()
            job = db.get(PersistentJob, job_id)
            if not job:
                return
            if job.worker_id and job.worker_id != worker_id:
                return
            if job.lease_token != lease_token:
                return
            if isinstance(exc, asyncio.TimeoutError):
                exc = RuntimeError(f"Job timed out after {job.timeout_seconds} seconds.")
            job.error = f"{type(exc).__name__}: {exc}"
            job.updated_at = _utcnow()
            job.lease_expires_at = None
            if job.status == "pause_requested":
                job.status = "paused"
                add_job_event(db, job, "paused", "Paused after active operation ended; checkpoint retained.")
            elif job.status == "cancel_requested":
                job.status = "cancelled"
                job.finished_at = _utcnow()
                _cancel_linked_state(db, job)
                add_job_event(db, job, "cancelled", job.error)
            elif job.attempts < job.max_attempts:
                delay = min(30 * max(job.attempts, 1), 120)
                job.status = "retry_wait"
                job.next_run_at = _utcnow() + timedelta(seconds=delay)
                job.worker_id = ""
                job.lease_token = ""
                add_job_event(db, job, "retry_scheduled", f"{job.error}; retry in {delay}s.")
            else:
                job.status = "error"
                job.finished_at = _utcnow()
                add_job_event(db, job, "failed", job.error)
            db.commit()
    finally:
        if heartbeat_task:
            heartbeat_task.cancel()
            await asyncio.gather(heartbeat_task, return_exceptions=True)
        db.close()
        worker_db = SessionLocal()
        try:
            heartbeat_worker(worker_db, worker_id, None)
        finally:
            worker_db.close()


async def run_job_now(job_id: int) -> None:
    """Best-effort web-process accelerator.

    The job is persisted first. A dedicated worker may claim it before this
    accelerator; in that case the accelerator only waits for persisted state.
    """
    if not settings.job_immediate_accelerator:
        return
    accelerator_id = f"web-{socket.gethostname()}-{os.getpid()}"
    global _claim_lock
    if _claim_lock is None:
        _claim_lock = asyncio.Lock()

    claimed = False
    lease_token = ""
    timeout_seconds = settings.job_default_timeout_seconds
    async with _claim_lock:
        db = SessionLocal()
        try:
            register_worker(db, accelerator_id, ["web_accelerator"])
            job = db.get(PersistentJob, job_id)
            if not job or job.status in TERMINAL_STATUSES:
                return
            timeout_seconds = job.timeout_seconds
            if job.status == "queued" and _resource_slot_available(db, job.kind):
                acquired = _claim_specific_job(
                    db, job.id, accelerator_id, event_type="accelerator_started"
                )
                if acquired:
                    claimed_job, lease_token = acquired
                    heartbeat_worker(db, accelerator_id, claimed_job.id)
                    claimed = True
        finally:
            db.close()

    if claimed:
        await process_job(job_id, accelerator_id, lease_token)
        return

    deadline = asyncio.get_running_loop().time() + max(10, timeout_seconds + 5)
    while asyncio.get_running_loop().time() < deadline:
        db = SessionLocal()
        try:
            job = db.get(PersistentJob, job_id)
            if not job or job.status in TERMINAL_STATUSES or job.status == "retry_wait":
                return
        finally:
            db.close()
        await asyncio.sleep(0.1)


async def worker_loop(worker_name: str = "worker") -> None:
    db = SessionLocal()
    try:
        register_worker(db, worker_name)
    finally:
        db.close()

    try:
        while True:
            try:
                claimed = await _claim_next_job(worker_name)
                if claimed is None:
                    await asyncio.sleep(max(0.1, settings.job_poll_interval_seconds))
                    continue
                job_id, lease_token = claimed
                await process_job(job_id, worker_name, lease_token)
            except asyncio.CancelledError:
                raise
            except Exception:
                await asyncio.sleep(max(0.25, settings.job_poll_interval_seconds))
    finally:
        db = SessionLocal()
        try:
            stop_worker(db, worker_name)
        finally:
            db.close()


def worker_snapshot(db: Session) -> list[dict]:
    now = _utcnow()
    rows = db.query(JobWorker).order_by(JobWorker.id.desc()).all()
    result = []
    for row in rows:
        age = max(0, int((now - row.last_heartbeat_at).total_seconds())) if row.last_heartbeat_at else None
        status = row.status
        if age is not None and age > max(30, settings.job_lease_seconds * 2):
            status = "stale"
        result.append({
            "worker_id": row.worker_id,
            "hostname": row.hostname,
            "pid": row.pid,
            "status": status,
            "active_job_id": row.active_job_id,
            "heartbeat_age_seconds": age,
            "capabilities": _loads(row.capabilities_json, []),
            "started_at": row.started_at,
        })
    return result

def job_payload(job: PersistentJob) -> dict:
    return {
        "id": job.id,
        "project_id": job.project_id,
        "kind": job.kind,
        "target": job.target,
        "status": job.status,
        "priority": job.priority,
        "attempts": job.attempts,
        "max_attempts": job.max_attempts,
        "timeout_seconds": job.timeout_seconds,
        "scope_hash": job.scope_hash,
        "worker_id": job.worker_id,
        "lease_expires_at": job.lease_expires_at,
        "heartbeat_at": job.heartbeat_at,
        "error": job.error,
        "result": _loads(job.result_json, {}),
        "next_run_at": job.next_run_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "created_at": job.created_at,
    }
