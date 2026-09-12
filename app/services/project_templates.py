from __future__ import annotations

from urllib.parse import urlparse

from sqlalchemy.orm import Session

from ..models import ProjectSkill, SkillDefinition
from ..skills.registry import ensure_project_skill_rows, seed_builtin_skills

PROJECT_TEMPLATES = {
    "web-api": {
        "name": "Web / API 渗透",
        "description": "适合绝大多数 Web、后台、API 项目。默认覆盖 HTTP、TLS、Header、Web/JS、证据与报告。",
        "skills": {
            "web-attack-surface-mapping", "javascript-api-mapper",
            "transport-security-review", "request-response-diff",
            "authorization-differential-review", "evidence-ai-triage",
            "pentest-coverage-judge", "reporting-evidence-pack",
            "agent-tool-guardrails",
        },
        "engagement_type": "authorized_pentest",
    },
    "quick-web": {
        "name": "单目标快速测试",
        "description": "最小化配置，适合拿到一个 URL 后立即做安全基线和 Web/API 观察。",
        "skills": {
            "web-attack-surface-mapping", "javascript-api-mapper",
            "transport-security-review", "evidence-ai-triage",
            "pentest-coverage-judge", "reporting-evidence-pack",
            "agent-tool-guardrails",
        },
        "engagement_type": "security_assessment",
    },
    "api-authz": {
        "name": "API / 权限测试",
        "description": "突出请求工作台、响应差异和 Authorization Matrix，适合登录后接口与越权测试。",
        "skills": {
            "web-attack-surface-mapping", "javascript-api-mapper",
            "request-response-diff", "authorization-differential-review",
            "evidence-ai-triage", "pentest-coverage-judge",
            "reporting-evidence-pack", "agent-tool-guardrails",
        },
        "engagement_type": "authorized_pentest",
    },
    "retest": {
        "name": "漏洞复测",
        "description": "重点保留 Evidence、Proof Capsule、Coverage 与报告，不主动扩大测试面。",
        "skills": {
            "request-response-diff", "authorization-differential-review",
            "evidence-ai-triage", "pentest-coverage-judge",
            "reporting-evidence-pack", "agent-tool-guardrails",
        },
        "engagement_type": "retest",
    },
    "internal-web": {
        "name": "内网 Web",
        "description": "允许安全的受限端口发现，并结合 Web/API 测试能力。",
        "skills": set(),
        "engagement_type": "internal_review",
        "full_safe": True,
    },
}


def template_list() -> list[dict]:
    return [{"slug": k, **v} for k, v in PROJECT_TEMPLATES.items()]


def apply_project_template(db: Session, project_id: int, slug: str) -> dict:
    if slug not in PROJECT_TEMPLATES:
        slug = "web-api"
    seed_builtin_skills(db)
    ensure_project_skill_rows(db, project_id)
    spec = PROJECT_TEMPLATES[slug]
    skills = db.query(SkillDefinition).all()
    selected = set(spec.get("skills", set()))
    if spec.get("full_safe"):
        selected = {s.slug for s in skills if s.builtin and s.enabled_by_default}
    rows = {
        x.skill_id: x
        for x in db.query(ProjectSkill).filter(ProjectSkill.project_id == project_id).all()
    }
    for skill in skills:
        row = rows.get(skill.id)
        if row:
            row.enabled = 1 if (skill.builtin and skill.slug in selected) else 0
    db.commit()
    return {"slug": slug, "name": spec["name"], "enabled_skills": len(selected)}


def normalize_quick_target(raw: str) -> tuple[str, str]:
    value = (raw or "").strip()
    if not value:
        raise ValueError("目标不能为空。")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("请输入有效的 HTTP/HTTPS 目标。")
    host = parsed.hostname
    return value, host
