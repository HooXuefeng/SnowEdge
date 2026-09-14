from __future__ import annotations

import json
from collections import Counter, defaultdict
from sqlalchemy import or_
from sqlalchemy.orm import Session

from .browser_workspace import redact_url

from ..models import (
    AgentRun,
    Asset,
    AuthorizationCase,
    BrowserEvent,
    BrowserSession,
    Endpoint,
    Evidence,
    ExecutionGraphNode,
    Finding,
    FindingLifecycle,
    CoverageSnapshot,
    Identity,
    KnowledgeEdge,
    KnowledgeNode,
    Project,
    ProofCapsule,
    RouteCandidate,
    Service,
    SkillPlan,
    SkillRun,
    StoredRequest,
    Task,
    WebArtifact,
)


def _json(data) -> str:
    return json.dumps(data, ensure_ascii=False, default=str)


def _loads(raw: str, default):
    try:
        value = json.loads(raw or "")
        return value
    except Exception:
        return default


def _node(
    db: Session,
    project_id: int,
    node_key: str,
    node_type: str,
    entity_type: str,
    entity_id: int | None,
    label: str,
    summary: dict | None = None,
    risk_level: str = "info",
) -> KnowledgeNode:
    row = KnowledgeNode(
        project_id=project_id,
        node_key=node_key[:240],
        node_type=node_type[:80],
        entity_type=entity_type[:80],
        entity_id=entity_id,
        label=(label or node_key)[:500],
        summary_json=_json(summary or {}),
        risk_level=(risk_level or "info")[:30],
    )
    db.add(row)
    db.flush()
    return row


def _edge(
    db: Session,
    project_id: int,
    source: KnowledgeNode | None,
    target: KnowledgeNode | None,
    relation: str,
    *,
    strength: str = "observed",
    metadata: dict | None = None,
) -> None:
    if not source or not target:
        return
    db.add(KnowledgeEdge(
        project_id=project_id,
        source_node_id=source.id,
        target_node_id=target.id,
        relation=relation[:120],
        strength=strength[:30],
        metadata_json=_json(metadata or {}),
    ))


def rebuild_knowledge_graph(db: Session, project_id: int) -> dict:
    project = db.get(Project, project_id)
    if not project:
        raise ValueError("Project not found.")

    db.query(KnowledgeEdge).filter(KnowledgeEdge.project_id == project_id).delete(synchronize_session=False)
    db.query(KnowledgeNode).filter(KnowledgeNode.project_id == project_id).delete(synchronize_session=False)
    db.commit()

    nodes: dict[str, KnowledgeNode] = {}

    def add(key, node_type, entity_type, entity_id, label, summary=None, risk="info"):
        row = _node(db, project_id, key, node_type, entity_type, entity_id, label, summary, risk)
        nodes[key] = row
        return row

    pnode = add(
        f"project:{project.id}", "project", "Project", project.id, project.name,
        {"scope_rule_count": len([x for x in project.scope_text.splitlines() if x.strip()])},
    )

    assets = db.query(Asset).filter(Asset.project_id == project_id).all()
    asset_ids = [a.id for a in assets] or [-1]
    for asset in assets:
        an = add(
            f"asset:{asset.id}", "asset", "Asset", asset.id, asset.target,
            {"kind": asset.kind},
        )
        _edge(db, project_id, pnode, an, "HAS_ASSET")

    services = db.query(Service).filter(Service.asset_id.in_(asset_ids)).all()
    for service in services:
        sn = add(
            f"service:{service.id}", "service", "Service", service.id,
            f"{service.protocol}/{service.port} {service.name}",
            {"port": service.port, "protocol": service.protocol, "name": service.name, "banner_present": bool(service.banner)},
        )
        _edge(db, project_id, nodes.get(f"asset:{service.asset_id}"), sn, "EXPOSES_SERVICE")

    endpoints = db.query(Endpoint).filter(Endpoint.asset_id.in_(asset_ids)).all()
    for endpoint in endpoints:
        en = add(
            f"endpoint:{endpoint.id}", "endpoint", "Endpoint", endpoint.id,
            f"{endpoint.method} {redact_url(endpoint.url)}",
            {"method": endpoint.method, "status_code": endpoint.status_code, "url": redact_url(endpoint.url)},
        )
        _edge(db, project_id, nodes.get(f"asset:{endpoint.asset_id}"), en, "HAS_ENDPOINT")

    artifacts = db.query(WebArtifact).filter(WebArtifact.asset_id.in_(asset_ids)).all()
    for artifact in artifacts:
        wn = add(
            f"webartifact:{artifact.id}", "web_artifact", "WebArtifact", artifact.id,
            redact_url(artifact.url) if artifact.url else artifact.artifact_type,
            {
                "artifact_type": artifact.artifact_type,
                "status_code": artifact.status_code,
                "content_type": artifact.content_type,
                "source_url": redact_url(artifact.source_url),
            },
        )
        _edge(db, project_id, nodes.get(f"asset:{artifact.asset_id}"), wn, "HAS_WEB_ARTIFACT")

    routes = db.query(RouteCandidate).filter(RouteCandidate.asset_id.in_(asset_ids)).all()
    for route in routes:
        rn = add(
            f"route:{route.id}", "route", "RouteCandidate", route.id,
            f"{route.method} {route.path}",
            {"method": route.method, "path": route.path, "source": route.source, "confidence": route.confidence},
        )
        _edge(db, project_id, nodes.get(f"asset:{route.asset_id}"), rn, "HAS_ROUTE_CANDIDATE")

    tasks = db.query(Task).filter(Task.project_id == project_id).order_by(Task.id.desc()).limit(500).all()
    for task in tasks:
        tn = add(
            f"task:{task.id}", "task", "Task", task.id,
            f"{task.action} · {redact_url(task.target)}",
            {"action": task.action, "target": redact_url(task.target), "policy_class": task.policy_class, "status": task.status},
        )
        _edge(db, project_id, pnode, tn, "HAS_TASK")

    identities = db.query(Identity).filter(Identity.project_id == project_id).all()
    for identity in identities:
        inode = add(
            f"identity:{identity.id}", "identity", "Identity", identity.id,
            f"{identity.name} · {identity.role}",
            {"name": identity.name, "role": identity.role, "secret_material_in_graph": False},
        )
        _edge(db, project_id, pnode, inode, "HAS_IDENTITY")

    stored_requests = db.query(StoredRequest).filter(StoredRequest.project_id == project_id).all()
    for stored in stored_requests:
        srn = add(
            f"request:{stored.id}", "request", "StoredRequest", stored.id,
            f"{stored.method} {redact_url(stored.url)}",
            {
                "method": stored.method,
                "url": redact_url(stored.url),
                "source": stored.source,
                "policy_class": stored.policy_class,
                "headers_in_graph": False,
                "body_in_graph": False,
            },
        )
        _edge(db, project_id, pnode, srn, "HAS_STORED_REQUEST")

    findings = db.query(Finding).filter(Finding.project_id == project_id).all()
    for finding in findings:
        fn = add(
            f"finding:{finding.id}", "finding", "Finding", finding.id,
            finding.title,
            {
                "severity": finding.severity,
                "target": redact_url(finding.target),
                "source": finding.source,
                "description_present": bool(finding.description),
            },
            finding.severity,
        )
        _edge(db, project_id, pnode, fn, "HAS_FINDING")

    finding_ids = [f.id for f in findings]
    task_ids = [t.id for t in tasks]
    evidence_conditions = []
    if finding_ids:
        evidence_conditions.append(Evidence.finding_id.in_(finding_ids))
    if task_ids:
        evidence_conditions.append(Evidence.task_id.in_(task_ids))
    evidence = (
        db.query(Evidence)
        .filter(or_(*evidence_conditions))
        .order_by(Evidence.id.desc())
        .limit(500)
        .all()
        if evidence_conditions else []
    )
    for ev in evidence:
        evn = add(
            f"evidence:{ev.id}", "evidence", "Evidence", ev.id,
            f"{ev.kind} #{ev.id}",
            {"kind": ev.kind, "raw_content_in_graph": False},
        )
        if ev.finding_id:
            _edge(db, project_id, nodes.get(f"finding:{ev.finding_id}"), evn, "SUPPORTED_BY", strength="evidence")
        if ev.task_id:
            _edge(db, project_id, nodes.get(f"task:{ev.task_id}"), evn, "PRODUCED_EVIDENCE", strength="evidence")

    cases = db.query(AuthorizationCase).filter(AuthorizationCase.project_id == project_id).all()
    for case in cases:
        cn = add(
            f"authcase:{case.id}", "authorization_case", "AuthorizationCase", case.id,
            f"{case.test_type} · {case.classification}",
            {
                "test_type": case.test_type,
                "classification": case.classification,
                "confidence": case.confidence,
                "object_label": case.object_label,
                "status": case.status,
            },
            "medium" if case.classification.startswith("potential_") else "info",
        )
        _edge(db, project_id, pnode, cn, "HAS_AUTHORIZATION_CASE")
        _edge(db, project_id, cn, nodes.get(f"request:{case.stored_request_id}"), "TESTS_REQUEST")
        if case.baseline_identity_id:
            _edge(db, project_id, cn, nodes.get(f"identity:{case.baseline_identity_id}"), "USES_BASELINE_IDENTITY")
        if case.comparison_identity_id:
            _edge(db, project_id, cn, nodes.get(f"identity:{case.comparison_identity_id}"), "COMPARES_IDENTITY")
        if case.finding_id:
            _edge(db, project_id, cn, nodes.get(f"finding:{case.finding_id}"), "PROMOTED_TO_FINDING", strength="evidence")

    lifecycles = db.query(FindingLifecycle).filter(FindingLifecycle.project_id == project_id).all()
    for lifecycle in lifecycles:
        ln = add(
            f"lifecycle:{lifecycle.id}", "finding_lifecycle", "FindingLifecycle", lifecycle.id,
            f"Finding #{lifecycle.finding_id} · {lifecycle.status}",
            {
                "finding_id": lifecycle.finding_id,
                "status": lifecycle.status,
                "priority": lifecycle.priority,
                "owner_present": bool(lifecycle.owner),
                "retest_status": lifecycle.retest_status,
                "proof_capsule_id": lifecycle.proof_capsule_id,
                "last_retest_run_id": lifecycle.last_retest_run_id,
                "remediation_note_in_graph": False,
            },
        )
        _edge(db, project_id, nodes.get(f"finding:{lifecycle.finding_id}"), ln, "TRACKED_BY_WORKFLOW")

    latest_coverage = (
        db.query(CoverageSnapshot)
        .filter(CoverageSnapshot.project_id == project_id)
        .order_by(CoverageSnapshot.id.desc())
        .first()
    )
    if latest_coverage:
        cn = add(
            f"coverage:{latest_coverage.id}", "coverage_snapshot", "CoverageSnapshot", latest_coverage.id,
            f"Coverage {latest_coverage.score}/100",
            {
                "score": latest_coverage.score,
                "covered": latest_coverage.covered_count,
                "partial": latest_coverage.partial_count,
                "gap": latest_coverage.gap_count,
                "needs_review": latest_coverage.needs_review_count,
                "matrix_in_graph": False,
            },
        )
        _edge(db, project_id, pnode, cn, "HAS_COVERAGE_SNAPSHOT")

    capsules = db.query(ProofCapsule).filter(ProofCapsule.project_id == project_id).all()
    for capsule in capsules:
        pn = add(
            f"proof:{capsule.id}", "proof_capsule", "ProofCapsule", capsule.id,
            f"{capsule.verifier_type} · {capsule.status}",
            {"verifier_type": capsule.verifier_type, "status": capsule.status, "retest_count": capsule.retest_count},
        )
        _edge(db, project_id, nodes.get(f"finding:{capsule.finding_id}"), pn, "VERIFIED_BY", strength="evidence")

    browser_sessions = db.query(BrowserSession).filter(BrowserSession.project_id == project_id).all()
    browser_session_ids = [s.id for s in browser_sessions] or [-1]
    for session in browser_sessions:
        bn = add(
            f"browser_session:{session.id}", "browser_session", "BrowserSession", session.id,
            session.title or redact_url(session.target_url),
            {
                "target_url": redact_url(session.target_url),
                "final_url": redact_url(session.final_url),
                "status": session.status,
                "identity_id": session.identity_id,
                "summary": _loads(session.summary_json, {}),
                "raw_identity_secrets_in_graph": False,
            },
        )
        _edge(db, project_id, pnode, bn, "HAS_BROWSER_SESSION")
        if session.identity_id:
            _edge(db, project_id, bn, nodes.get(f"identity:{session.identity_id}"), "USES_IDENTITY")

    browser_events = (
        db.query(BrowserEvent)
        .filter(BrowserEvent.browser_session_id.in_(browser_session_ids))
        .order_by(BrowserEvent.id.desc())
        .limit(500)
        .all()
    )
    for event in browser_events:
        ben = add(
            f"browser_event:{event.id}", "browser_event", "BrowserEvent", event.id,
            f"{event.event_type} · {event.method or ''} {redact_url(event.url) if event.url else ''}".strip(),
            {
                "event_type": event.event_type,
                "method": event.method,
                "url": redact_url(event.url),
                "resource_type": event.resource_type,
                "status_code": event.status_code,
                "in_scope": bool(event.in_scope),
                "detail_in_graph": False,
            },
        )
        _edge(db, project_id, nodes.get(f"browser_session:{event.browser_session_id}"), ben, "OBSERVED_EVENT")
        # Link browser observations to matching StoredRequest when URL/method are identical.
        for stored in stored_requests:
            if redact_url(stored.url) == redact_url(event.url) and stored.method == event.method:
                _edge(db, project_id, ben, nodes.get(f"request:{stored.id}"), "MATERIALIZED_AS_REQUEST")
                break

    plans = db.query(SkillPlan).filter(SkillPlan.project_id == project_id).all()
    plan_ids = [p.id for p in plans] or [-1]
    for plan in plans:
        spn = add(
            f"skill_plan:{plan.id}", "skill_plan", "SkillPlan", plan.id,
            f"Skill Plan #{plan.id} · {plan.status}",
            {"target": redact_url(plan.target), "status": plan.status, "executed_agent_run_id": plan.executed_agent_run_id},
        )
        _edge(db, project_id, pnode, spn, "HAS_SKILL_PLAN")

    execution_nodes = db.query(ExecutionGraphNode).filter(ExecutionGraphNode.skill_plan_id.in_(plan_ids)).all()
    for node in execution_nodes:
        gn = add(
            f"execution_node:{node.id}", "execution_node", "ExecutionGraphNode", node.id,
            node.label or node.skill_slug,
            {
                "skill_slug": node.skill_slug,
                "stage": node.stage,
                "execution_mode": node.execution_mode,
                "status": node.status,
                "capabilities": _loads(node.capabilities_json, []),
            },
        )
        _edge(db, project_id, nodes.get(f"skill_plan:{node.skill_plan_id}"), gn, "CONTAINS_EXECUTION_NODE")

    agent_runs = db.query(AgentRun).filter(AgentRun.project_id == project_id).all()
    for run in agent_runs:
        arn = add(
            f"agent_run:{run.id}", "agent_run", "AgentRun", run.id,
            f"AgentRun #{run.id} · {run.stage}",
            {"target": redact_url(run.target), "stage": run.stage, "status": run.status, "mission": run.mission[:500]},
        )
        _edge(db, project_id, pnode, arn, "HAS_AGENT_RUN")

    skill_runs = db.query(SkillRun).filter(SkillRun.project_id == project_id).all()
    for run in skill_runs:
        srn = add(
            f"skill_run:{run.id}", "skill_run", "SkillRun", run.id,
            f"SkillRun #{run.id} · {run.stage}",
            {"target": redact_url(run.target), "stage": run.stage, "status": run.status, "skill_id": run.skill_id},
        )
        _edge(db, project_id, pnode, srn, "HAS_SKILL_RUN")
        if run.agent_run_id:
            _edge(db, project_id, nodes.get(f"agent_run:{run.agent_run_id}"), srn, "EXECUTED_SKILL")

    db.commit()
    return graph_summary(db, project_id)


def graph_summary(db: Session, project_id: int) -> dict:
    nodes = db.query(KnowledgeNode).filter(KnowledgeNode.project_id == project_id).all()
    edges = db.query(KnowledgeEdge).filter(KnowledgeEdge.project_id == project_id).all()
    node_counts = Counter(n.node_type for n in nodes)
    relation_counts = Counter(e.relation for e in edges)
    return {
        "nodes": len(nodes),
        "edges": len(edges),
        "node_counts": dict(sorted(node_counts.items())),
        "relation_counts": dict(sorted(relation_counts.items())),
        "high_risk_nodes": sum(1 for n in nodes if n.risk_level in {"high", "critical"}),
        "finding_nodes": node_counts.get("finding", 0),
        "evidence_nodes": node_counts.get("evidence", 0),
    }


def graph_payload(db: Session, project_id: int, limit: int = 350) -> dict:
    nodes = (
        db.query(KnowledgeNode)
        .filter(KnowledgeNode.project_id == project_id)
        .order_by(KnowledgeNode.id.asc())
        .limit(max(1, min(limit, 1000)))
        .all()
    )
    ids = {n.id for n in nodes}
    edges = (
        db.query(KnowledgeEdge)
        .filter(
            KnowledgeEdge.project_id == project_id,
            KnowledgeEdge.source_node_id.in_(ids or {-1}),
            KnowledgeEdge.target_node_id.in_(ids or {-1}),
        )
        .order_by(KnowledgeEdge.id.asc())
        .all()
    )
    return {
        "nodes": [
            {
                "id": n.id,
                "key": n.node_key,
                "type": n.node_type,
                "label": n.label,
                "risk": n.risk_level,
                "summary": _loads(n.summary_json, {}),
            }
            for n in nodes
        ],
        "edges": [
            {
                "id": e.id,
                "source": e.source_node_id,
                "target": e.target_node_id,
                "relation": e.relation,
                "strength": e.strength,
            }
            for e in edges
        ],
        "summary": graph_summary(db, project_id),
        "truncated": db.query(KnowledgeNode).filter(KnowledgeNode.project_id == project_id).count() > len(nodes),
    }


def related_nodes(db: Session, project_id: int, node_id: int, limit: int = 60) -> dict:
    node = db.get(KnowledgeNode, node_id)
    if not node or node.project_id != project_id:
        raise ValueError("Knowledge node not found.")

    edges = (
        db.query(KnowledgeEdge)
        .filter(
            KnowledgeEdge.project_id == project_id,
            (KnowledgeEdge.source_node_id == node_id) | (KnowledgeEdge.target_node_id == node_id),
        )
        .order_by(KnowledgeEdge.id.asc())
        .limit(max(1, min(limit, 200)))
        .all()
    )
    other_ids = {
        e.target_node_id if e.source_node_id == node_id else e.source_node_id
        for e in edges
    }
    others = {
        n.id: n for n in db.query(KnowledgeNode).filter(KnowledgeNode.id.in_(other_ids or {-1})).all()
    }
    return {
        "node": {
            "id": node.id,
            "key": node.node_key,
            "type": node.node_type,
            "label": node.label,
            "risk": node.risk_level,
            "summary": _loads(node.summary_json, {}),
        },
        "relations": [
            {
                "edge_id": e.id,
                "direction": "out" if e.source_node_id == node_id else "in",
                "relation": e.relation,
                "strength": e.strength,
                "other": {
                    "id": others[oid].id,
                    "type": others[oid].node_type,
                    "label": others[oid].label,
                    "key": others[oid].node_key,
                } if oid in others else None,
            }
            for e in edges
            for oid in [e.target_node_id if e.source_node_id == node_id else e.source_node_id]
        ],
    }
