from __future__ import annotations
import json
from sqlalchemy.orm import Session
from ..models import BrowserSession,PersistentJob,Project,RecoveryEvent,Task,WorkspaceDraft,_utcnow
from .job_engine import add_job_event,recover_orphaned_jobs

SAFE_JOB_KINDS={"project_scan","browser_observe","copilot_query","agent_team","proof_retest","endpoint_sync","knowledge_refresh","authorization_matrix"}

def prepare_recovery(db:Session)->dict:
    recovered=recover_orphaned_jobs(db)
    stale_tasks=db.query(Task).filter(Task.status=="running").all()
    for task in stale_tasks:
        task.status="recovery_pending"
        db.add(RecoveryEvent(project_id=task.project_id,event_type="stale_task",entity_type="task",entity_id=task.id,status="pending",detail_json=json.dumps({"action":task.action,"target":task.target},ensure_ascii=False)))
    stale_browser=db.query(BrowserSession).filter(BrowserSession.status=="running").all()
    for row in stale_browser:
        row.status="recovery_pending"
        db.add(RecoveryEvent(project_id=row.project_id,event_type="stale_browser",entity_type="browser_session",entity_id=row.id,status="pending",detail_json=json.dumps({"target_url":row.target_url},ensure_ascii=False)))
    if stale_tasks or stale_browser: db.commit()
    return recovery_snapshot(db)|{"leases_recovered":recovered}

def recovery_snapshot(db:Session)->dict:
    jobs=db.query(PersistentJob).filter(PersistentJob.status.in_(["queued","retry_wait","running","cancel_requested"])).order_by(PersistentJob.id.asc()).all()
    browsers=db.query(BrowserSession).filter(BrowserSession.status.in_(["queued","running","recovery_pending"])).order_by(BrowserSession.id.asc()).all()
    tasks=db.query(Task).filter(Task.status=="recovery_pending").order_by(Task.id.asc()).all()
    drafts=db.query(WorkspaceDraft).order_by(WorkspaceDraft.updated_at.desc()).all()
    return {"jobs":jobs,"browsers":browsers,"tasks":tasks,"drafts":drafts,"total":len(jobs)+len(browsers)+len(tasks)+len(drafts)}

def resume_safe_recovery(db:Session)->dict:
    resumed=[]
    for job in db.query(PersistentJob).filter(PersistentJob.status.in_(["retry_wait","queued"])).all():
        if job.kind not in SAFE_JOB_KINDS: continue
        job.status="queued";job.next_run_at=None;job.updated_at=_utcnow();add_job_event(db,job,"recovery_resume","V1.6 crash recovery returned this safe job to the queue.");resumed.append(job.id)
        if job.kind=="browser_observe":
            try:
                payload=json.loads(job.payload_json or "{}")
                session=db.get(BrowserSession,payload.get("session_id"))
                if session and session.status=="recovery_pending": session.status="queued";session.error=""
            except Exception: pass
    db.commit();return {"resumed_jobs":resumed}

def dismiss_recovery(db:Session)->dict:
    tasks=db.query(Task).filter(Task.status=="recovery_pending").all(); browsers=db.query(BrowserSession).filter(BrowserSession.status=="recovery_pending").all()
    for row in tasks: row.status="cancelled"; row.detail=(row.detail or "")+" | Dismissed by V1.6 recovery center."
    for row in browsers: row.status="cancelled"; row.error="Dismissed by V1.6 recovery center."
    db.commit();return {"tasks":len(tasks),"browsers":len(browsers)}
