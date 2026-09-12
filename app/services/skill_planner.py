
from __future__ import annotations

import json
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from ..ai.factory import get_ai_provider
from ..models import (
    Asset, AuthorizationCase, Endpoint, Finding, Identity, Project, ProjectSkill,
    ReplayResult, RouteCandidate, Service, SkillDefinition, SkillPlan, StoredRequest,
    WebArtifact,
)
from ..skills.registry import ensure_project_skill_rows, seed_builtin_skills, set_project_skill
from .execution_graph import build_execution_graph, mark_graph_approved
from .assessment_memory import memory_hints, memory_summary, refresh_assessment_memory

CORE_SKILLS = [
    "evidence-ai-triage",
    "pentest-coverage-judge",
    "reporting-evidence-pack",
    "agent-tool-guardrails",
]

def evidence_profile(db: Session, project_id: int, target: str = "") -> dict:
    assets = db.query(Asset).filter(Asset.project_id == project_id).all()
    asset_ids = [a.id for a in assets] or [-1]
    parsed = urlparse(target if "://" in target else "")
    mem_summary = memory_summary(db, project_id)
    return {
        "assessment_memories": mem_summary.get("count", 0),
        "avoid_repeat_memories": mem_summary.get("avoid_repeat", 0),
        "assets": len(assets),
        "services": db.query(Service).filter(Service.asset_id.in_(asset_ids)).count(),
        "endpoints": db.query(Endpoint).filter(Endpoint.asset_id.in_(asset_ids)).count(),
        "web_artifacts": db.query(WebArtifact).filter(WebArtifact.asset_id.in_(asset_ids)).count(),
        "route_candidates": db.query(RouteCandidate).filter(RouteCandidate.asset_id.in_(asset_ids)).count(),
        "stored_requests": db.query(StoredRequest).filter(StoredRequest.project_id == project_id).count(),
        "replays": db.query(ReplayResult).filter(ReplayResult.project_id == project_id).count(),
        "identities": db.query(Identity).filter(Identity.project_id == project_id).count(),
        "authorization_cases": db.query(AuthorizationCase).filter(AuthorizationCase.project_id == project_id).count(),
        "findings": db.query(Finding).filter(Finding.project_id == project_id).count(),
        "target_has_http_scheme": parsed.scheme in {"http", "https"},
        "target_is_https": parsed.scheme == "https",
    }

def _candidate(slug: str, reason: str, priority: str) -> dict:
    return {"slug": slug, "reason": reason, "priority": priority, "source": "deterministic"}

def deterministic_candidates(profile: dict) -> list[dict]:
    out = []
    seen = set()

    def add(slug: str, reason: str, priority: str = "medium"):
        if slug not in seen:
            seen.add(slug)
            out.append(_candidate(slug, reason, priority))

    if profile["services"] == 0:
        add("safe-reconnaissance", "No service inventory exists yet; constrained reconnaissance can establish a baseline.", "high")

    if profile["target_has_http_scheme"] or profile["endpoints"] or profile["web_artifacts"]:
        add("web-attack-surface-mapping", "Web evidence or an HTTP(S) target is present; map in-scope pages and resources.", "high")
        add("browser-observation-workspace", "A real-browser observation can reveal DOM, XHR/Fetch, forms and console behavior that static crawling cannot see.", "medium")
        add("transport-security-review", "A web surface is present; review TLS and response-header posture.", "medium")

    if profile["target_has_http_scheme"] or profile["web_artifacts"] or profile["route_candidates"]:
        add("javascript-api-mapper", "Web/route evidence exists; static JavaScript and API route mapping can improve coverage.", "high")

    if profile["stored_requests"]:
        add("request-response-diff", "Stored requests are available, so read-only replay and response comparison are actionable.", "high")

    if profile["stored_requests"] and profile["identities"] >= 2:
        add("authorization-differential-review", "At least two authorized identities and stored requests are available for differential authorization review.", "high")

    for slug in CORE_SKILLS:
        reasons = {
            "evidence-ai-triage": "Use bounded AI only after deterministic evidence is available.",
            "pentest-coverage-judge": "Track evidence-backed coverage gaps instead of relying on model intuition.",
            "reporting-evidence-pack": "Keep findings, evidence, and validation history exportable.",
            "agent-tool-guardrails": "Continuously verify Scope/Policy/tool boundaries for AI-orchestrated work.",
        }
        add(slug, reasons[slug], "medium")

    return out

def builtin_catalog(db: Session) -> list[dict]:
    seed_builtin_skills(db)
    rows = db.query(SkillDefinition).filter(SkillDefinition.builtin == 1).order_by(SkillDefinition.category, SkillDefinition.name).all()
    catalog = []
    for skill in rows:
        try:
            caps = json.loads(skill.capabilities_json or "[]")
        except Exception:
            caps = []
        catalog.append({
            "slug": skill.slug,
            "name": skill.name,
            "description": skill.description,
            "category": skill.category,
            "risk_tier": skill.risk_tier,
            "execution_mode": skill.execution_mode,
            "capabilities": caps,
        })
    return catalog

def _merge_recommendations(deterministic: list[dict], ai_result: dict, allowed: set[str]) -> list[dict]:
    merged = {item["slug"]: dict(item) for item in deterministic if item["slug"] in allowed}
    priority_rank = {"high": 3, "medium": 2, "low": 1}
    for item in ai_result.get("recommendations", []):
        slug = item.get("slug")
        if slug not in allowed:
            continue
        if slug in merged:
            merged[slug]["ai_reason"] = str(item.get("reason", ""))[:800]
            ai_priority = str(item.get("priority", "medium")).lower()
            if priority_rank.get(ai_priority, 2) > priority_rank.get(merged[slug].get("priority", "medium"), 2):
                merged[slug]["priority"] = ai_priority
            merged[slug]["source"] = "deterministic+ai"
        else:
            merged[slug] = {
                "slug": slug,
                "reason": "AI selected this Skill from the allowlisted catalog.",
                "ai_reason": str(item.get("reason", ""))[:800],
                "priority": str(item.get("priority", "medium")).lower(),
                "source": "ai",
            }
    return sorted(merged.values(), key=lambda x: (-priority_rank.get(x.get("priority", "medium"), 2), x["slug"]))


def _apply_memory_notes(recommendations: list[dict], hints: list[dict], target: str) -> list[dict]:
    parsed = urlparse(target if "://" in target else "")
    host = parsed.hostname or target
    target_values = {x for x in {target, host} if x}
    action_map = {
        "safe-reconnaissance": {"port_scan"},
        "web-attack-surface-mapping": {"web_discovery", "http_probe"},
        "transport-security-review": {"tls_check", "headers_check"},
        "browser-observation-workspace": set(),
    }
    priority_down = {"high": "medium", "medium": "low", "low": "low"}

    for rec in recommendations:
        slug = rec.get("slug")
        relevant = []
        for hint in hints:
            if not str(hint.get("repeat_guidance", "")).startswith("avoid_repeat"):
                continue
            if slug == "browser-observation-workspace":
                if hint.get("type") == "browser_observation" and hint.get("subject") == target:
                    relevant.append(hint)
                continue
            actions = action_map.get(slug)
            if actions is None or hint.get("type") != "coverage_action":
                continue
            metadata = hint.get("metadata") or {}
            if metadata.get("action") in actions and hint.get("subject") in target_values:
                relevant.append(hint)

        if relevant:
            latest = relevant[0]
            rec["memory_note"] = (
                f"Existing assessment memory: {latest.get('summary', '')} "
                "Review before repeating equivalent work."
            )[:1200]
            rec["priority"] = priority_down.get(rec.get("priority", "medium"), "low")
            rec["source"] = rec.get("source", "deterministic") + "+memory"
    return recommendations


async def generate_skill_plan(db: Session, project: Project, target: str = "") -> SkillPlan:
    refresh_assessment_memory(db, project.id)
    hints = memory_hints(db, project.id, limit=80)
    profile = evidence_profile(db, project.id, target)
    deterministic = _apply_memory_notes(deterministic_candidates(profile), hints, target)
    catalog = builtin_catalog(db)
    allowed = {item["slug"] for item in catalog}

    ai_result = {"recommendations": [], "summary": ""}
    try:
        provider = get_ai_provider()
        ai_result = await provider.recommend_skills(
            {
                "evidence_profile": profile,
                "target_characteristics": {
                    "target_provided": bool(target),
                    "http_scheme": profile["target_has_http_scheme"],
                    "https": profile["target_is_https"],
                },
                "deterministic_candidates": deterministic,
                "memory_hints": hints,
            },
            catalog,
        )
    except Exception as exc:
        ai_result = {"recommendations": [], "summary": f"AI recommendation unavailable: {type(exc).__name__}: {exc}"}

    recommendations = _merge_recommendations(deterministic, ai_result, allowed)
    plan = SkillPlan(
        project_id=project.id,
        target=(target or "").strip(),
        status="draft",
        profile_json=json.dumps(profile, ensure_ascii=False),
        recommendations_json=json.dumps(recommendations, ensure_ascii=False),
        approved_skills_json="[]",
        ai_summary=str(ai_result.get("summary", ""))[:3000],
    )
    db.add(plan)
    db.commit()
    db.refresh(plan)
    build_execution_graph(db, plan)
    return plan

def approve_skill_plan(db: Session, project_id: int, plan_id: int, selected_slugs: list[str]) -> SkillPlan:
    plan = db.get(SkillPlan, plan_id)
    if not plan or plan.project_id != project_id:
        raise ValueError("Skill Plan not found.")

    seed_builtin_skills(db)
    ensure_project_skill_rows(db, project_id)
    builtins = db.query(SkillDefinition).filter(SkillDefinition.builtin == 1).all()
    allowed = {skill.slug: skill for skill in builtins}
    selected = [slug for slug in dict.fromkeys(selected_slugs) if slug in allowed]
    if not selected:
        raise ValueError("At least one built-in Skill must be selected.")

    rows = {
        row.skill_id: row
        for row in db.query(ProjectSkill).filter(ProjectSkill.project_id == project_id).all()
    }
    for skill in builtins:
        row = rows.get(skill.id)
        if row:
            row.enabled = 1 if skill.slug in selected else 0

    plan.approved_skills_json = json.dumps(selected, ensure_ascii=False)
    plan.status = "approved"
    db.commit()
    db.refresh(plan)
    mark_graph_approved(db, plan, selected)
    return plan

def plan_payload(plan: SkillPlan) -> dict:
    def load(raw, default):
        try:
            return json.loads(raw or "")
        except Exception:
            return default
    return {
        "profile": load(plan.profile_json, {}),
        "recommendations": load(plan.recommendations_json, []),
        "approved_skills": load(plan.approved_skills_json, []),
    }
