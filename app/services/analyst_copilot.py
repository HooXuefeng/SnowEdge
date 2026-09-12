from __future__ import annotations

import json
import re
from sqlalchemy.orm import Session

from ..ai.factory import get_ai_provider, current_ai_provider_name
from ..config import settings
from ..models import AssessmentMemory, CopilotQuery, KnowledgeNode, Project, Evidence
from .evidence_safety import redact_object
from .assessment_memory import refresh_assessment_memory
from .coverage_matrix import latest_coverage, coverage_payload
from .knowledge_graph import rebuild_knowledge_graph, graph_summary


TOKEN_RE = re.compile(r"[A-Za-z0-9_./:-]{2,}|[\u4e00-\u9fff]{2,}")


def _loads(raw: str, default):
    try:
        return json.loads(raw or "")
    except Exception:
        return default


def _tokens(text: str) -> set[str]:
    return {m.group(0).lower() for m in TOKEN_RE.finditer(text or "")}


def _score(question_tokens: set[str], *parts: str) -> int:
    hay = _tokens(" ".join(parts))
    if not question_tokens:
        return 0
    return len(question_tokens & hay)


def build_copilot_context(db: Session, project: Project, question: str) -> tuple[dict, list[str]]:
    rebuild_knowledge_graph(db, project.id)
    refresh_assessment_memory(db, project.id)
    coverage = coverage_payload(latest_coverage(db, project, refresh=True))

    qtokens = _tokens(question)

    nodes = db.query(KnowledgeNode).filter(KnowledgeNode.project_id == project.id).all()
    ranked_nodes = []
    for node in nodes:
        summary = _loads(node.summary_json, {})
        score = _score(qtokens, node.label, node.node_key, node.node_type, json.dumps(summary, ensure_ascii=False))
        if score or not qtokens:
            ranked_nodes.append((score, node, summary))
    ranked_nodes.sort(key=lambda x: (-x[0], x[1].id))

    memories = db.query(AssessmentMemory).filter(AssessmentMemory.project_id == project.id).all()
    ranked_memories = []
    for memory in memories:
        score = _score(
            qtokens,
            memory.memory_type,
            memory.subject,
            memory.outcome,
            memory.repeat_guidance,
            memory.summary,
        )
        if score or not qtokens:
            ranked_memories.append((score, memory))
    ranked_memories.sort(key=lambda x: (-x[0], -x[1].id))

    coverage_rows = []
    for item in coverage["matrix"]:
        score = _score(qtokens, item["label"], item["category"], item["status"], item["rationale"], item["next_step"])
        coverage_rows.append((score, item))
    coverage_rows.sort(key=lambda x: (-x[0], -x[1]["weight"], x[1]["label"]))

    knowledge_payload = [
        {
            "ref": f"kg:{node.id}",
            "id": node.id,
            "type": node.node_type,
            "label": node.label,
            "risk": node.risk_level,
            "summary": summary,
        }
        for _, node, summary in ranked_nodes[:80]
    ]
    memory_payload = [
        {
            "ref": f"mem:{memory.id}",
            "id": memory.id,
            "type": memory.memory_type,
            "subject": memory.subject,
            "outcome": memory.outcome,
            "confidence": memory.confidence,
            "repeat_guidance": memory.repeat_guidance,
            "summary": memory.summary,
        }
        for _, memory in ranked_memories[:60]
    ]
    coverage_payload_rows = [
        {
            "ref": f"coverage:{item['key']}",
            "key": item["key"],
            "label": item["label"],
            "category": item["category"],
            "status": item["status"],
            "evidence_count": item["evidence_count"],
            "rationale": item["rationale"],
            "next_step": item["next_step"],
        }
        for _, item in coverage_rows[:30]
    ]

    allowed_refs = (
        [x["ref"] for x in knowledge_payload]
        + [x["ref"] for x in memory_payload]
        + [x["ref"] for x in coverage_payload_rows]
    )
    diagnostics = []
    query = db.query(Evidence).filter(Evidence.project_id == project.id, Evidence.source_type == 'utility_tool')
    diagnostic_rows = query.order_by(Evidence.id.desc()).limit(8).all()
    # Explicit references can select older evidence but never another project's data.
    requested = [int(value) for value in re.findall(r'utility:(\d{1,12})', question)[:4]]
    if requested:
        referenced = query.filter(Evidence.id.in_(requested)).all()
        diagnostic_rows = referenced + [row for row in diagnostic_rows if row.id not in requested]
    for evidence in diagnostic_rows[:8]:
        safe, _ = redact_object(_loads(evidence.content, {}))
        encoded = json.dumps(safe, ensure_ascii=False)
        diagnostics.append({'ref':f'utility:{evidence.id}', 'kind':evidence.kind, 'observed_at':str(evidence.captured_at), 'summary':encoded[:4500], 'untrusted_observation':True})
    allowed_refs = [item['ref'] for item in diagnostics] + allowed_refs
    scan_query=db.query(Evidence).filter(Evidence.project_id==project.id,Evidence.source_type.in_(['scan_engine','oob','credential_audit']))
    scan_rows=scan_query.order_by(Evidence.id.desc()).limit(8).all()
    requested_scan=[int(value) for value in re.findall(r'scan:(\d{1,12})',question)[:4]]
    if requested_scan:
        scan_rows=scan_query.filter(Evidence.id.in_(requested_scan)).all()+[row for row in scan_rows if row.id not in requested_scan]
    scan_observations=[]
    for evidence in scan_rows[:8]:
        safe,_=redact_object(_loads(evidence.content,{}))
        scan_observations.append({'ref':f'scan:{evidence.id}','kind':evidence.kind,'summary':json.dumps(safe,ensure_ascii=False)[:4500],'untrusted_observation':True})
    allowed_refs=[item['ref'] for item in scan_observations]+allowed_refs
    from .workflow_context import focused_sources
    focused=focused_sources(db,project.id,question)
    allowed_refs=[item['ref'] for item in focused]+allowed_refs
    return {
        "focused_sources": focused,
        "scan_observations": scan_observations,
        "diagnostics": diagnostics,
        "knowledge": knowledge_payload,
        "memories": memory_payload,
        "coverage": coverage_payload_rows,
        "project_summary": {
            "project_id": project.id,
            "project_name": project.name,
            "graph": graph_summary(db, project.id),
            "coverage_score": coverage["score"],
            "coverage_gaps": coverage["gap"] + coverage["partial"] + coverage["needs_review"],
        },
    }, allowed_refs


def _sanitize_answer(raw: dict, allowed_refs: list[str]) -> tuple[dict, int]:
    if not isinstance(raw, dict):
        raw = {}
    drift = 0
    for forbidden in ("tool_calls", "tool_requests", "commands", "shell", "payloads", "request_body"):
        value = raw.get(forbidden)
        if value:
            drift += len(value) if isinstance(value, list) else 1

    allowed = set(allowed_refs)
    citations = []
    for ref in raw.get("citations", [])[:12]:
        ref = str(ref)
        if ref in allowed:
            citations.append(ref)
        else:
            drift += 1

    allowed_views = {
        "knowledge_graph", "memory", "coverage", "findings", "requests",
        "authorization", "browser", "reports",
    }
    views = []
    for view in raw.get("suggested_views", [])[:6]:
        view = str(view)
        if view in allowed_views:
            views.append(view)
        else:
            drift += 1

    gaps = raw.get("gaps", [])
    return {
        "answer": str(raw.get("answer", ""))[:6000],
        "citations": citations,
        "gaps": [str(x)[:1000] for x in gaps[:8]] if isinstance(gaps, list) else [],
        "suggested_views": views,
        "analysis_only": True,
    }, drift


def create_copilot_query(db: Session, project: Project, question: str) -> CopilotQuery:
    question = (question or "").strip()
    if not question:
        raise ValueError("Question is required.")
    if len(question) > 4000:
        raise ValueError("Question is too long.")
    row = CopilotQuery(
        project_id=project.id,
        question=question,
        status="queued",
        provider=current_ai_provider_name(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


async def run_copilot_query(db: Session, project: Project, row: CopilotQuery) -> CopilotQuery:
    if row.project_id != project.id:
        raise ValueError("Copilot query does not belong to this project.")
    row.status = "running"
    db.commit()
    try:
        context, allowed_refs = build_copilot_context(db, project, row.question)
        provider = get_ai_provider()
        raw = await provider.analyst_copilot(row.question, context, allowed_refs)
        answer, drift = _sanitize_answer(raw, allowed_refs)
        row.answer_json = json.dumps(answer, ensure_ascii=False)
        row.citation_count = len(answer["citations"])
        row.drift_count = drift
        row.status = "done"
    except Exception as exc:
        row.status = "error"
        row.answer_json = json.dumps(
            {
                "answer": "",
                "citations": [],
                "gaps": [f"{type(exc).__name__}: {exc}"],
                "suggested_views": [],
                "analysis_only": True,
            },
            ensure_ascii=False,
        )
    db.commit()
    db.refresh(row)
    return row


async def answer_copilot_query(db: Session, project: Project, question: str) -> CopilotQuery:
    row = create_copilot_query(db, project, question)
    return await run_copilot_query(db, project, row)


def copilot_payload(row: CopilotQuery) -> dict:
    return {
        "id": row.id,
        "question": row.question,
        "status": row.status,
        "provider": row.provider,
        "answer": _loads(row.answer_json, {}),
        "citation_count": row.citation_count,
        "drift_count": row.drift_count,
        "created_at": row.created_at,
    }


def resolve_citation(db: Session, project_id: int, ref: str) -> dict | None:
    if re.fullmatch(r'(request|evidence|finding):\d{1,12}',ref):
        from .workflow_context import source_context
        kind,number=ref.split(':')
        try:source=source_context(db,project_id,kind,int(number))
        except ValueError:return None
        return {'ref':ref,'kind':kind,'label':source['label'],'type':kind,'url':f'/projects/{project_id}/workflow/{kind}/{number}'}
    if ref.startswith('scan:'):
        try:evidence=db.get(Evidence,int(ref.split(':',1)[1]))
        except ValueError:return None
        if not evidence or evidence.project_id!=project_id or evidence.source_type not in {'scan_engine','oob','credential_audit'}:return None
        return {'ref':ref,'kind':'scan','label':f'扫描证据 #{evidence.id}','type':evidence.kind,'url':f'/projects/{project_id}/evidence?selected={evidence.id}'}
    if ref.startswith('utility:'):
        try:
            evidence = db.get(Evidence, int(ref.split(':', 1)[1]))
        except ValueError:
            return None
        if not evidence or evidence.project_id != project_id or evidence.source_type != 'utility_tool':
            return None
        return {'ref':ref, 'kind':'diagnostic', 'label':f'诊断证据 #{evidence.id}', 'type':evidence.kind, 'url':f'/projects/{project_id}/evidence?selected={evidence.id}#evidence-{evidence.id}'}
    if ref.startswith("kg:"):
        try:
            node_id = int(ref.split(":", 1)[1])
        except ValueError:
            return None
        node = db.get(KnowledgeNode, node_id)
        if not node or node.project_id != project_id:
            return None
        return {
            "ref": ref,
            "kind": "knowledge",
            "label": node.label,
            "type": node.node_type,
            "url": f"/projects/{project_id}/knowledge-graph?selected={node.id}",
        }
    if ref.startswith("mem:"):
        try:
            memory_id = int(ref.split(":", 1)[1])
        except ValueError:
            return None
        memory = db.get(AssessmentMemory, memory_id)
        if not memory or memory.project_id != project_id:
            return None
        return {
            "ref": ref,
            "kind": "memory",
            "label": memory.summary[:180] or memory.subject,
            "type": memory.memory_type,
            "url": f"/projects/{project_id}/memory",
        }
    if ref.startswith("coverage:"):
        key = ref.split(":", 1)[1]
        return {
            "ref": ref,
            "kind": "coverage",
            "label": key,
            "type": "coverage",
            "url": f"/projects/{project_id}/coverage",
        }
    return None
