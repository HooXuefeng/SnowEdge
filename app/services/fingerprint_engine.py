from __future__ import annotations

import json
import re
from collections import Counter
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from ..models import Asset, Endpoint, Evidence, FingerprintRule, Project, Service, TechnologyFingerprint, WebArtifact, _utcnow
from .evidence_safety import redact_url

BUILTIN_RULES = [
    # source, key, pattern, category, product, confidence
    ("header", "server", "nginx", "web_server", "Nginx", 96),
    ("header", "server", "apache", "web_server", "Apache HTTP Server", 94),
    ("header", "server", "microsoft-iis", "web_server", "Microsoft IIS", 97),
    ("header", "server", "caddy", "web_server", "Caddy", 96),
    ("header", "x-powered-by", "express", "framework", "Express", 95),
    ("header", "x-powered-by", "asp.net", "framework", "ASP.NET", 94),
    ("header", "x-powered-by", "php", "runtime", "PHP", 90),
    ("body", "", "__next_data__", "framework", "Next.js", 96),
    ("body", "", "wp-content/", "cms", "WordPress", 96),
    ("body", "", "wp-includes/", "cms", "WordPress", 94),
    ("body", "", "data-v-app", "frontend", "Vue.js", 88),
    ("body", "", "ng-version=", "frontend", "Angular", 94),
    ("body", "", "id=\"__next\"", "framework", "Next.js", 92),
    ("cookie", "", "jsessionid", "runtime", "Java Servlet", 90),
    ("cookie", "", "phpsessid", "runtime", "PHP", 88),
    ("cookie", "", "asp.net_sessionid", "framework", "ASP.NET", 91),
    ("header", "cf-ray", "", "security_edge", "Cloudflare", 99),
    ("header", "server", "cloudflare", "security_edge", "Cloudflare", 98),
    ("header", "x-sucuri-id", "", "waf", "Sucuri WAF", 98),
    ("body", "", "ctg-waf", "waf", "CTG-WAF", 98),
    ("body", "", "request blocked by waf", "waf", "Generic WAF", 78),
    ("header", "x-akamai-transformed", "", "security_edge", "Akamai", 94),
    ("header", "x-amz-cf-id", "", "security_edge", "AWS CloudFront", 96),
]

SAFE_CATEGORIES = {"technology", "web_server", "framework", "runtime", "frontend", "cms", "waf", "security_edge", "middleware"}
SAFE_SOURCES = {"header", "body", "cookie", "title"}


def _loads(raw: str, default):
    try:
        return json.loads(raw or "")
    except Exception:
        return default


def _asset_for_url(db: Session, project_id: int, url: str) -> Asset | None:
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        host = ""
    if not host:
        return None
    return db.query(Asset).filter(Asset.project_id == project_id, Asset.target == host).first()


def _endpoint_for_url(db: Session, asset_id: int, url: str) -> Endpoint | None:
    return db.query(Endpoint).filter(Endpoint.asset_id == asset_id, Endpoint.url == url).order_by(Endpoint.id.desc()).first()


def _version_from_value(product: str, value: str) -> str:
    value = value or ""
    patterns = {
        "Nginx": r"nginx/?([0-9][0-9.]+)",
        "Apache HTTP Server": r"apache/?([0-9][0-9.]+)",
        "Microsoft IIS": r"microsoft-iis/?([0-9][0-9.]+)",
        "PHP": r"php/?([0-9][0-9.]+)",
    }
    pat = patterns.get(product)
    if not pat:
        return ""
    m = re.search(pat, value, re.I)
    return (m.group(1) if m else "")[:100]


def _upsert(
    db: Session, *, project_id: int, asset_id: int, endpoint_id: int | None,
    category: str, product: str, version: str = "", confidence: int = 70,
    detection_mode: str = "passive", rule_id: str = "", evidence_source: str = "",
    summary: dict | None = None,
) -> TechnologyFingerprint:
    row = db.query(TechnologyFingerprint).filter(
        TechnologyFingerprint.project_id == project_id,
        TechnologyFingerprint.asset_id == asset_id,
        TechnologyFingerprint.category == category,
        TechnologyFingerprint.product == product,
        TechnologyFingerprint.rule_id == rule_id,
    ).first()
    if not row:
        row = TechnologyFingerprint(
            project_id=project_id, asset_id=asset_id, endpoint_id=endpoint_id,
            category=category, product=product, version=version,
            confidence=max(1, min(int(confidence), 100)), detection_mode=detection_mode,
            rule_id=rule_id, evidence_source=evidence_source,
            evidence_summary_json=json.dumps(summary or {}, ensure_ascii=False),
        )
        db.add(row)
    else:
        row.endpoint_id = endpoint_id or row.endpoint_id
        row.version = version or row.version
        row.confidence = max(row.confidence, max(1, min(int(confidence), 100)))
        row.last_seen_at = _utcnow()
        row.evidence_source = evidence_source or row.evidence_source
        row.evidence_summary_json = json.dumps(summary or _loads(row.evidence_summary_json, {}), ensure_ascii=False)
    db.flush()
    return row


def _header_values(headers: dict) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in (headers or {}).items()}


def analyze_http_observation(db: Session, project: Project, observation: dict, evidence_source: str = "http_response") -> int:
    if not isinstance(observation, dict) or not observation.get("ok"):
        return 0
    url = str(observation.get("final_url") or observation.get("url") or "")
    asset = _asset_for_url(db, project.id, url)
    if not asset:
        return 0
    endpoint = _endpoint_for_url(db, asset.id, url)
    headers = _header_values(observation.get("headers") or {})
    body = str(observation.get("body") or "")[:160000]
    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:500] if title_match else ""
    cookies = " ".join([str(v) for k, v in headers.items() if k == "set-cookie"]).lower()
    created = 0

    rules = list(BUILTIN_RULES)
    custom = db.query(FingerprintRule).filter(
        FingerprintRule.enabled == 1,
        (FingerprintRule.project_id.is_(None)) | (FingerprintRule.project_id == project.id),
    ).all()

    def check(source, key, pattern):
        pattern = (pattern or "").lower()
        if source == "header":
            value = headers.get((key or "").lower(), "")
            return (bool(value) if not pattern else pattern in value.lower()), value
        if source == "cookie":
            return pattern in cookies, cookies
        if source == "title":
            return pattern in title.lower(), title
        return pattern in body.lower(), body[:4000]

    for idx, (source, key, pattern, category, product, confidence) in enumerate(rules):
        matched, value = check(source, key, pattern)
        if not matched:
            continue
        _upsert(db, project_id=project.id, asset_id=asset.id, endpoint_id=endpoint.id if endpoint else None,
            category=category, product=product, version=_version_from_value(product, value), confidence=confidence,
            detection_mode="passive", rule_id=f"builtin:{idx}:{product.lower().replace(' ','-')}", evidence_source=evidence_source,
            summary={"source": source, "header": key, "matched": pattern or "header-present", "url": redact_url(url)})
        created += 1

    for rule in custom:
        source = rule.source if rule.source in SAFE_SOURCES else "body"
        matched, _ = check(source, rule.header_name, rule.pattern)
        if not matched:
            continue
        _upsert(db, project_id=project.id, asset_id=asset.id, endpoint_id=endpoint.id if endpoint else None,
            category=rule.category if rule.category in SAFE_CATEGORIES else "technology", product=rule.product,
            confidence=rule.confidence, detection_mode="custom-passive", rule_id=f"custom:{rule.id}", evidence_source=evidence_source,
            summary={"source": source, "header": rule.header_name, "rule_name": rule.name, "url": redact_url(url)})
        created += 1
    db.commit()
    return created


def refresh_project_fingerprints(db: Session, project: Project) -> dict:
    created = 0
    evidence = db.query(Evidence).filter(Evidence.project_id == project.id, Evidence.kind == "http_response").order_by(Evidence.id.asc()).all()
    for ev in evidence:
        data = _loads(ev.content, {})
        if isinstance(data, dict):
            created += analyze_http_observation(db, project, data, evidence_source=f"Evidence#{ev.id}")

    assets = db.query(Asset).filter(Asset.project_id == project.id).all()
    for asset in assets:
        artifacts = db.query(WebArtifact).filter(WebArtifact.asset_id == asset.id, WebArtifact.artifact_type == "technology_snapshot").all()
        for artifact in artifacts:
            meta = _loads(artifact.metadata_json, {})
            for tech in meta.get("technologies", []) if isinstance(meta, dict) else []:
                if not str(tech).strip():
                    continue
                _upsert(db, project_id=project.id, asset_id=asset.id, endpoint_id=None, category="technology",
                    product=str(tech).strip()[:200], confidence=72, detection_mode="passive",
                    rule_id=f"discovery:{str(tech).strip().lower()[:80]}", evidence_source=f"WebArtifact#{artifact.id}",
                    summary={"source": "web_discovery", "url": redact_url(artifact.url)})
        for service in db.query(Service).filter(Service.asset_id == asset.id).all():
            banner=(service.banner or "").lower()
            for needle, product, cat, conf in [("nginx","Nginx","web_server",88),("apache","Apache HTTP Server","web_server",88),("microsoft-iis","Microsoft IIS","web_server",92)]:
                if needle in banner:
                    _upsert(db, project_id=project.id, asset_id=asset.id, endpoint_id=None, category=cat, product=product,
                        version=_version_from_value(product, service.banner), confidence=conf, detection_mode="passive",
                        rule_id=f"service:{product.lower().replace(' ','-')}", evidence_source=f"Service#{service.id}",
                        summary={"port": service.port, "protocol": service.protocol, "service": service.name})
    db.commit()
    rows=db.query(TechnologyFingerprint).filter(TechnologyFingerprint.project_id==project.id).all()
    cats=Counter(x.category for x in rows)
    return {"observations_processed":len(evidence),"fingerprints":len(rows),"matches":created,"categories":dict(cats)}


def fingerprint_recommendation(row: TechnologyFingerprint) -> str:
    p=row.product.lower(); c=row.category
    if c == "waf" or c == "security_edge":
        return "优先被动分析 / Browser / Import；减少重复探测，不自动尝试绕过。"
    if "swagger" in p or "openapi" in p:
        return "优先导入 OpenAPI/Swagger，建立 Endpoint/Parameter 模型。"
    if "vue" in p or "react" in p or "next" in p or "angular" in p:
        return "优先 JS/API Mapper 与 Browser observe-only。"
    if "spring" in p or "java servlet" in p:
        return "优先 Endpoint/Authorization/Headers 安全验证，不自动执行产品 POC。"
    return "结合 Coverage 缺口选择已有安全 Skill；指纹本身不授予新的执行权限。"
