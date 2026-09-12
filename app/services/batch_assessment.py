from __future__ import annotations
import json
from sqlalchemy.orm import Session
from ..models import BatchAssessment, BatchAssessmentItem, Project, ScanProfile, _utcnow
from ..scope import target_in_scope

MAX_BATCH_TARGETS=50


def _rules(project: Project) -> list[str]: return [x.strip() for x in project.scope_text.splitlines() if x.strip()]


def parse_targets(raw: str) -> list[str]:
    values=[]; seen=set()
    for line in (raw or "").replace(",","\n").splitlines():
        value=line.strip()
        if value and value not in seen:
            seen.add(value);values.append(value)
    return values[:MAX_BATCH_TARGETS]


def create_batch(db: Session, project: Project, name: str, targets_raw: str, profile: ScanProfile | None=None) -> BatchAssessment:
    targets=parse_targets(targets_raw)
    if not targets: raise ValueError("At least one target is required.")
    limit=profile.batch_target_limit if profile else 20
    if len(targets)>limit: raise ValueError(f"Selected profile allows at most {limit} targets per batch.")
    rules=_rules(project); inside=[]; outside=[]
    for target in targets:
        (inside if target_in_scope(target,rules) else outside).append(target)
    if not inside: raise ValueError("No batch target is inside the project's authorized scope.")
    row=BatchAssessment(project_id=project.id,name=(name or "Batch Assessment")[:240],scan_profile_id=profile.id if profile else project.scan_profile_id,
        status="queued",total_targets=len(targets),skipped_targets=len(outside),resource_gate="scan",max_parallel=1,
        summary_json=json.dumps({"outside_scope":outside,"execution":"serialized-safe-gate"},ensure_ascii=False))
    db.add(row);db.flush()
    for target in inside: db.add(BatchAssessmentItem(batch_id=row.id,project_id=project.id,target=target,status="queued"))
    for target in outside: db.add(BatchAssessmentItem(batch_id=row.id,project_id=project.id,target=target,status="skipped",detail="Outside authorized scope."))
    db.commit();db.refresh(row);return row


def update_batch_counts(db: Session, batch: BatchAssessment) -> None:
    items=db.query(BatchAssessmentItem).filter(BatchAssessmentItem.batch_id==batch.id).all()
    batch.completed_targets=sum(1 for x in items if x.status=="done")
    batch.failed_targets=sum(1 for x in items if x.status=="error")
    batch.skipped_targets=sum(1 for x in items if x.status=="skipped")
    db.commit()
