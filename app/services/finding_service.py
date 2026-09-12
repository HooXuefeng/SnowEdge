from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from sqlalchemy.orm import Session

from ..models import Evidence, Finding, FindingOccurrence, Task
from .evidence_safety import safe_evidence_text


DYNAMIC_SEGMENT_RE = re.compile(r"^(?:\d{2,}|[0-9a-fA-F]{16,}|[0-9a-fA-F-]{24,})$")
SENSITIVE_QUERY_NAMES = {
    "token", "access_token", "id_token", "refresh_token", "auth", "authorization",
    "code", "ticket", "apikey", "api_key", "key", "session", "sessionid", "sid",
    "jwt", "credential", "secret",
}

TAXONOMY_RULES = [
    {
        "match": ("authorization", "越权", "horizontal", "vertical", "unauthenticated access"),
        "vuln_type": "Authorization Control",
        "cwe_id": "CWE-862",
        "owasp": "A01:2021 Broken Access Control",
        "txb02": "权限控制",
    },
    {
        "match": ("xss", "cross-site scripting", "跨站脚本"),
        "vuln_type": "Cross-Site Scripting",
        "cwe_id": "CWE-79",
        "owasp": "A03:2021 Injection",
        "txb02": "跨站脚本",
    },
    {
        "match": ("sensitive information", "信息泄露", "敏感信息", "pii"),
        "vuln_type": "Sensitive Information Exposure",
        "cwe_id": "CWE-200",
        "owasp": "",
        "txb02": "敏感信息泄露",
    },
    {
        "match": ("open redirect", "url redirect", "不安全跳转", "任意跳转"),
        "vuln_type": "Open Redirect",
        "cwe_id": "CWE-601",
        "owasp": "A01:2021 Broken Access Control",
        "txb02": "URL跳转",
    },
    {
        "match": ("missing security header", "security header", "hsts", "header"),
        "vuln_type": "Security Header Misconfiguration",
        "cwe_id": "CWE-693",
        "owasp": "A05:2021 Security Misconfiguration",
        "txb02": "安全配置",
    },
    {
        "match": ("tls", "cipher", "certificate"),
        "vuln_type": "TLS / Transport Security",
        "cwe_id": "CWE-326",
        "owasp": "A02:2021 Cryptographic Failures",
        "txb02": "传输安全",
    },
]


def _as_text(content) -> str:
    if isinstance(content, str):
        return content
    return json.dumps(content, ensure_ascii=False, indent=2)


def _redacted_target(target: str) -> str:
    try:
        parsed = urlparse(target)
        if not parsed.scheme or not parsed.netloc:
            return target.strip()
        pairs = []
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            if key.lower() in SENSITIVE_QUERY_NAMES:
                value = "••••"
            pairs.append(f"{key}={value}")
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            "&".join(pairs),
            parsed.fragment,
        ))
    except Exception:
        return target.strip()


def _normalized_target(target: str) -> str:
    try:
        parsed = urlparse(target)
        if not parsed.scheme or not parsed.netloc:
            return target.strip().lower()
        segments = []
        for segment in parsed.path.split("/"):
            if DYNAMIC_SEGMENT_RE.match(segment):
                segments.append("{id}")
            else:
                segments.append(segment)
        query = []
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            if key.lower() in SENSITIVE_QUERY_NAMES:
                value = "{redacted}"
            query.append((key.lower(), value))
        query.sort()
        return urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            "/".join(segments),
            "",
            urlencode(query, doseq=True),
            "",
        ))
    except Exception:
        return target.strip().lower()


def classify_finding(title: str, source: str = "", description: str = "") -> dict:
    hay = f"{title} {source} {description}".lower()
    for rule in TAXONOMY_RULES:
        if any(term.lower() in hay for term in rule["match"]):
            return {
                "vuln_type": rule["vuln_type"],
                "cwe_id": rule["cwe_id"],
                "owasp_category": rule["owasp"],
                "txb02_category": rule["txb02"],
            }
    return {
        "vuln_type": "",
        "cwe_id": "",
        "owasp_category": "",
        "txb02_category": "",
    }


def finding_fingerprint(
    title: str,
    target: str,
    source: str = "",
    vuln_type: str = "",
    parameter: str = "",
) -> str:
    normalized_type = (vuln_type or title).strip().lower()
    # Source is intentionally excluded: the same canonical issue may be observed
    # by Browser, Header Check, Authorization Lab or AI review and should converge.
    raw = "\x1f".join([
        normalized_type,
        _normalized_target(target),
        (parameter or "").strip().lower(),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def add_task_evidence(db: Session, task: Task, kind: str, content) -> Evidence:
    safe_content, redaction_state = safe_evidence_text(content)
    evidence = Evidence(
        project_id=task.project_id,
        task_id=task.id,
        source_type="Task",
        source_id=task.id,
        redaction_state=redaction_state,
        kind=kind[:100],
        content=safe_content,
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    return evidence


def ensure_finding_metadata(db: Session, finding: Finding) -> Finding:
    from ..models import RemediationEvent
    if finding.source == "analyst_manual" or db.query(RemediationEvent.id).filter_by(finding_id=finding.id, event_type="finding_edited").first():
        return finding  # Preserve deliberate analyst edits, including cleared classifications.
    taxonomy = classify_finding(finding.title, finding.source, finding.description)
    safe_target = _redacted_target(finding.target)
    if safe_target != finding.target:
        finding.target = safe_target[:1000]
    if not finding.vuln_type:
        finding.vuln_type = taxonomy["vuln_type"]
    if not finding.cwe_id:
        finding.cwe_id = taxonomy["cwe_id"]
    if not finding.owasp_category:
        finding.owasp_category = taxonomy["owasp_category"]
    if not finding.txb02_category:
        finding.txb02_category = taxonomy["txb02_category"]
    legacy_deterministic_sources = {
        "headers_check", "tls_check", "http_probe", "nuclei_import",
        "nmap_import", "burp_import",
    }
    if finding.finding_state == "candidate" and finding.source in legacy_deterministic_sources:
        finding.finding_state = "confirmed"
    if not finding.fingerprint:
        finding.fingerprint = finding_fingerprint(
            finding.title,
            finding.target,
            finding.source,
            finding.vuln_type,
            finding.parameter,
        )
    db.commit()
    db.refresh(finding)
    return finding


def create_finding(
    db: Session,
    project_id: int,
    title: str,
    severity: str,
    target: str,
    description: str,
    recommendation: str,
    source: str,
    evidence_kind: str,
    evidence_content,
    *,
    vuln_type: str = "",
    parameter: str = "",
    cwe_id: str = "",
    owasp_category: str = "",
    txb02_category: str = "",
    finding_state: str = "",
) -> Finding:
    taxonomy = classify_finding(title, source, description)
    vuln_type = vuln_type or taxonomy["vuln_type"]
    cwe_id = cwe_id or taxonomy["cwe_id"]
    owasp_category = owasp_category or taxonomy["owasp_category"]
    txb02_category = txb02_category or taxonomy["txb02_category"]
    fingerprint = finding_fingerprint(title, target, source, vuln_type, parameter)
    safe_target = _redacted_target(target)
    safe_content, redaction_state = safe_evidence_text(evidence_content)
    deterministic_sources = {
        "headers_check", "tls_check", "http_probe", "nuclei_import",
        "nmap_import", "burp_import",
    }
    finding_state = finding_state or ("confirmed" if source in deterministic_sources else "candidate")

    existing = (
        db.query(Finding)
        .filter(
            Finding.project_id == project_id,
            Finding.fingerprint == fingerprint,
            Finding.dedupe_status != "duplicate",
        )
        .order_by(Finding.id.asc())
        .first()
    )

    if existing:
        evidence = Evidence(
            project_id=project_id,
            finding_id=existing.id,
            source_type="FindingOccurrence",
            redaction_state=redaction_state,
            kind=evidence_kind[:100],
            content=safe_content,
        )
        db.add(evidence)
        db.flush()
        db.add(FindingOccurrence(
            project_id=project_id,
            finding_id=existing.id,
            source=source[:100],
            target=safe_target[:1000],
            fingerprint=fingerprint,
            evidence_id=evidence.id,
            detail_json=json.dumps({"deduplicated": True, "title": title[:300]}, ensure_ascii=False),
        ))
        db.commit()
        db.refresh(existing)
        return existing

    finding = Finding(
        project_id=project_id,
        title=title[:300],
        severity=severity[:30],
        target=safe_target[:1000],
        description=description,
        recommendation=recommendation,
        source=source[:100],
        fingerprint=fingerprint,
        dedupe_status="unique",
        vuln_type=vuln_type[:160],
        parameter=parameter[:300],
        cwe_id=cwe_id[:32],
        owasp_category=owasp_category[:80],
        txb02_category=txb02_category[:180],
        finding_state=finding_state[:60],
        verification_state="unverified",
    )
    db.add(finding)
    db.flush()

    evidence = Evidence(
        project_id=project_id,
        finding_id=finding.id,
        source_type="Finding",
        source_id=finding.id,
        redaction_state=redaction_state,
        kind=evidence_kind[:100],
        content=safe_content,
    )
    db.add(evidence)
    db.flush()
    db.add(FindingOccurrence(
        project_id=project_id,
        finding_id=finding.id,
        source=source[:100],
        target=safe_target[:1000],
        fingerprint=fingerprint,
        evidence_id=evidence.id,
        detail_json=json.dumps({"deduplicated": False}, ensure_ascii=False),
    ))
    db.commit()
    db.refresh(finding)
    return finding
