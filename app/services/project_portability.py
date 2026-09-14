from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from ..models import (
    Asset,
    AuthorizationCase,
    Endpoint,
    EndpointParameter,
    Finding,
    FindingLifecycle,
    Identity,
    Project,
    Service,
    StoredRequest,
    StoredRequestRevision,
    EvidenceAttachment,
    TechnologyFingerprint,
    ScanProfile,
    NetworkRouteProfile,
)
from .endpoint_inventory import endpoint_fingerprint
from .browser_workspace import redact_url
from .finding_service import ensure_finding_metadata


PORTABLE_SCHEMA = "snowedge-project/1.6.2"
SUPPORTED_PORTABLE_SCHEMAS = {PORTABLE_SCHEMA, "ai-pentest-workspace-project/1.6.2", "ai-pentest-workspace-project/1.6", "ai-pentest-workspace-project/1.5", "ai-pentest-workspace-project/1.4", "ai-pentest-workspace-project/1.3", "ai-pentest-workspace-project/1.2"}
MAX_IMPORT_BYTES = 10 * 1024 * 1024
MAX_RECORDS_PER_COLLECTION = 20_000


def _loads(raw: str, default):
    try:
        return json.loads(raw or "")
    except Exception:
        return default


def export_manifest(db: Session, project: Project) -> dict:
    assets = db.query(Asset).filter(Asset.project_id == project.id).order_by(Asset.id.asc()).all()
    asset_ids = [a.id for a in assets] or [-1]
    services = db.query(Service).filter(Service.asset_id.in_(asset_ids)).order_by(Service.id.asc()).all()
    endpoints = db.query(Endpoint).filter(Endpoint.asset_id.in_(asset_ids)).order_by(Endpoint.id.asc()).all()
    endpoint_ids = [e.id for e in endpoints] or [-1]
    params = db.query(EndpointParameter).filter(EndpointParameter.endpoint_id.in_(endpoint_ids)).order_by(EndpointParameter.id.asc()).all()
    requests = db.query(StoredRequest).filter(StoredRequest.project_id == project.id).order_by(StoredRequest.id.asc()).all()
    identities = db.query(Identity).filter(Identity.project_id == project.id).order_by(Identity.id.asc()).all()
    findings = db.query(Finding).filter(Finding.project_id == project.id).order_by(Finding.id.asc()).all()
    lifecycles = db.query(FindingLifecycle).filter(FindingLifecycle.project_id == project.id).order_by(FindingLifecycle.id.asc()).all()
    cases = db.query(AuthorizationCase).filter(AuthorizationCase.project_id == project.id).order_by(AuthorizationCase.id.asc()).all()
    request_revisions = db.query(StoredRequestRevision).filter(StoredRequestRevision.project_id == project.id).order_by(StoredRequestRevision.id.asc()).all()
    attachments = db.query(EvidenceAttachment).filter(EvidenceAttachment.project_id == project.id).order_by(EvidenceAttachment.id.asc()).all()
    fingerprints = db.query(TechnologyFingerprint).filter(TechnologyFingerprint.project_id == project.id).order_by(TechnologyFingerprint.id.asc()).all()
    active_profile = db.get(ScanProfile, project.scan_profile_id) if project.scan_profile_id else None
    active_route = db.get(NetworkRouteProfile, project.network_route_profile_id) if project.network_route_profile_id else None

    return {
        "schema": PORTABLE_SCHEMA,
        "export_type": "sanitized_project",
        "security_notice": {
            "identity_secrets_included": False,
            "stored_request_secret_headers_included": False,
            "stored_request_bodies_included": False,
            "raw_evidence_included": False,
            "browser_screenshots_included": False,
            "remediation_notes_included": False,
            "request_revision_bodies_included": False,
            "screenshot_binaries_included": False,
            "vault_secrets_included": False,
            "workspace_drafts_included": False,
            "network_route_password_included": False,
            "network_route_host_included": False,
        },
        "project": {
            "source_id": project.id,
            "name": project.name,
            "scope_text": project.scope_text,
            "client_name": project.client_name,
            "environment": project.environment,
            "engagement_type": project.engagement_type,
            "status": project.status,
            "start_date": project.start_date,
            "end_date": project.end_date,
            "authorization_note": project.authorization_note,
            "testers": _loads(project.testers_json, []),
            "template_slug": project.template_slug,
            "scan_profile": {"name": active_profile.name, "skills": _loads(active_profile.enabled_skill_slugs_json, [])} if active_profile else None,
            "network_route": {"name": active_route.name, "route_type": active_route.route_type, "endpoint_omitted": True} if active_route else {"name": "Direct", "route_type": "direct"},
        },
        "assets": [
            {"source_id": a.id, "target": a.target, "kind": a.kind}
            for a in assets
        ],
        "services": [
            {
                "source_id": s.id,
                "asset_source_id": s.asset_id,
                "port": s.port,
                "protocol": s.protocol,
                "name": s.name,
                "banner_omitted": True,
            }
            for s in services
        ],
        "technology_fingerprints": [
            {
                "source_id": f.id, "asset_source_id": f.asset_id, "endpoint_source_id": f.endpoint_id,
                "category": f.category, "product": f.product, "version": f.version, "confidence": f.confidence,
                "detection_mode": f.detection_mode, "rule_id": f.rule_id, "evidence_source": f.evidence_source,
            } for f in fingerprints
        ],
        "endpoints": [
            {
                "source_id": e.id,
                "asset_source_id": e.asset_id,
                "url": redact_url(e.url),
                "method": e.method,
                "status_code": e.status_code,
                "normalized_path": e.normalized_path,
                "fingerprint": e.fingerprint,
                "content_type": e.content_type,
                "auth_observed": bool(e.auth_observed),
                "source": e.source,
            }
            for e in endpoints
        ],
        "endpoint_parameters": [
            {
                "source_id": p.id,
                "endpoint_source_id": p.endpoint_id,
                "location": p.location,
                "name": p.name,
                "value_type": p.value_type,
                "required": bool(p.required),
                "sensitive": bool(p.sensitive),
                "source": p.source,
                "example_redacted": "••••" if p.sensitive else p.example_redacted,
                "fingerprint": p.fingerprint,
            }
            for p in params
        ],
        "stored_requests": [
            {
                "source_id": r.id,
                "name": r.name,
                "method": r.method,
                "url": redact_url(r.url),
                "public_headers": _loads(r.headers_json, {}),
                "secret_headers_omitted": True,
                "body_omitted": True,
                "source": r.source,
                "policy_class": r.policy_class,
            }
            for r in requests
        ],
        "request_revision_metadata": [
            {
                "stored_request_source_id": r.stored_request_id,
                "revision_no": r.revision_no,
                "name": r.name,
                "method": r.method,
                "url": redact_url(r.url),
                "policy_class": r.policy_class,
                "change_note": r.change_note,
                "headers_omitted": True,
                "body_omitted": True,
            }
            for r in request_revisions
        ],
        "screenshot_metadata": [
            {
                "finding_source_id": a.finding_id,
                "label": a.label,
                "mime_type": a.mime_type,
                "file_sha256": a.file_sha256,
                "size_bytes": a.size_bytes,
                "sort_order": a.sort_order,
                "annotation_json": a.annotation_json,
                "binary_omitted": True,
            }
            for a in attachments
        ],
        "identities": [
            {
                "source_id": i.id,
                "name": i.name,
                "role": i.role,
                "credentials_omitted": True,
                "notes_omitted": True,
            }
            for i in identities
        ],
        "findings": [
            {
                "source_id": f.id,
                "title": f.title,
                "severity": f.severity,
                "target": redact_url(f.target),
                "description": f.description,
                "recommendation": f.recommendation,
                "source": f.source,
                "fingerprint": f.fingerprint,
                "vuln_type": f.vuln_type,
                "parameter": f.parameter,
                "cwe_id": f.cwe_id,
                "owasp_category": f.owasp_category,
                "txb02_category": f.txb02_category,
                "finding_state": f.finding_state,
                "verification_state": f.verification_state,
                "reopened_count": f.reopened_count,
                "raw_evidence_omitted": True,
            }
            for f in findings
        ],
        "finding_lifecycles": [
            {
                "source_id": l.id,
                "finding_source_id": l.finding_id,
                "status": l.status,
                "owner": l.owner,
                "priority": l.priority,
                "retest_status": l.retest_status,
                "remediation_note_omitted": True,
            }
            for l in lifecycles
        ],
        "authorization_cases": [
            {
                "source_id": c.id,
                "stored_request_source_id": c.stored_request_id,
                "test_type": c.test_type,
                "baseline_identity_source_id": c.baseline_identity_id,
                "comparison_identity_source_id": c.comparison_identity_id,
                "expected_owner_identity_source_id": c.expected_owner_identity_id,
                "finding_source_id": c.finding_id,
                "status": c.status,
                "classification": c.classification,
                "confidence": c.confidence,
                "object_label": c.object_label,
                "replay_bodies_omitted": True,
            }
            for c in cases
        ],
    }


def export_project_zip(db: Session, project: Project) -> bytes:
    manifest = export_manifest(db, project)
    data = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", data)
        zf.writestr(
            "README.txt",
            (
                "SnowEdge V1.7.0 sanitized project export.\n"
                "This package intentionally excludes identity credentials, secret request headers, "
                "request bodies, raw evidence, screenshot binaries and remediation-note bodies. Request revision and screenshot annotation metadata may be included without secret/binary content.\n"
            ).encode("utf-8"),
        )
    return bio.getvalue()


def parse_project_zip(data: bytes) -> dict:
    if len(data) > MAX_IMPORT_BYTES:
        raise ValueError("Import package exceeds the 10 MB sanitized-project limit.")
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            names = set(zf.namelist())
            if "manifest.json" not in names:
                raise ValueError("manifest.json is missing.")
            info = zf.getinfo("manifest.json")
            if info.file_size > MAX_IMPORT_BYTES:
                raise ValueError("manifest.json is too large.")
            manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
    except zipfile.BadZipFile as exc:
        raise ValueError("Invalid project ZIP.") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid manifest JSON.") from exc

    if manifest.get("schema") not in SUPPORTED_PORTABLE_SCHEMAS:
        raise ValueError("Unsupported project export schema.")
    for key in [
        "assets", "services", "endpoints", "endpoint_parameters", "stored_requests",
        "identities", "findings", "finding_lifecycles", "authorization_cases",
        "request_revision_metadata", "screenshot_metadata", "technology_fingerprints",
    ]:
        value = manifest.get(key, [])
        if not isinstance(value, list) or len(value) > MAX_RECORDS_PER_COLLECTION:
            raise ValueError(f"Invalid or oversized collection: {key}.")
    return manifest


def import_project_manifest(db: Session, manifest: dict) -> Project:
    meta = manifest.get("project") or {}
    scope_text = str(meta.get("scope_text", "")).strip()
    if not scope_text:
        raise ValueError("Imported project has no scope.")

    project = Project(
        name=(str(meta.get("name", "Imported Project")) + "（导入）")[:200],
        scope_text=scope_text,
        client_name=str(meta.get("client_name", ""))[:240],
        environment=str(meta.get("environment", "test"))[:80],
        engagement_type=str(meta.get("engagement_type", "authorized_pentest"))[:80],
        status="preparing",
        start_date=str(meta.get("start_date", ""))[:32],
        end_date=str(meta.get("end_date", ""))[:32],
        authorization_note=(
            str(meta.get("authorization_note", ""))[:8000]
            + "\n[Imported sanitized package: credentials/evidence bodies were intentionally omitted.]"
        ).strip(),
        testers_json=json.dumps(meta.get("testers", [])[:50], ensure_ascii=False),
        template_slug=str(meta.get("template_slug", "web-api"))[:80],
    )
    db.add(project)
    db.flush()

    asset_map = {}
    for row in manifest.get("assets", []):
        asset = Asset(project_id=project.id, target=str(row.get("target", ""))[:500], kind=str(row.get("kind", "host"))[:50])
        db.add(asset); db.flush()
        asset_map[row.get("source_id")] = asset.id

    for row in manifest.get("services", []):
        asset_id = asset_map.get(row.get("asset_source_id"))
        if not asset_id:
            continue
        db.add(Service(
            asset_id=asset_id,
            port=int(row.get("port", 0) or 0),
            protocol=str(row.get("protocol", "tcp"))[:20],
            name=str(row.get("name", ""))[:100],
            banner="",
        ))

    endpoint_map = {}
    for row in manifest.get("endpoints", []):
        asset_id = asset_map.get(row.get("asset_source_id"))
        if not asset_id:
            continue
        endpoint = Endpoint(
            asset_id=asset_id,
            url=str(row.get("url", ""))[:1000],
            method=str(row.get("method", "GET"))[:16],
            status_code=row.get("status_code"),
            normalized_path=str(row.get("normalized_path", ""))[:1000],
            fingerprint=str(row.get("fingerprint", ""))[:80],
            content_type=str(row.get("content_type", ""))[:200],
            auth_observed=1 if row.get("auth_observed") else 0,
            source="sanitized_import",
        )
        db.add(endpoint); db.flush()
        endpoint_map[row.get("source_id")] = endpoint.id

    for row in manifest.get("technology_fingerprints", []):
        asset_id = asset_map.get(row.get("asset_source_id"))
        if not asset_id:
            continue
        db.add(TechnologyFingerprint(
            project_id=project.id, asset_id=asset_id, endpoint_id=endpoint_map.get(row.get("endpoint_source_id")),
            category=str(row.get("category","technology"))[:80], product=str(row.get("product","Imported Technology"))[:200],
            version=str(row.get("version",""))[:100], confidence=max(1,min(int(row.get("confidence",70) or 70),100)),
            detection_mode="historical_import", rule_id=str(row.get("rule_id",""))[:120], evidence_source="sanitized_import",
            evidence_summary_json="{}",
        ))

    for row in manifest.get("endpoint_parameters", []):
        endpoint_id = endpoint_map.get(row.get("endpoint_source_id"))
        if not endpoint_id:
            continue
        db.add(EndpointParameter(
            endpoint_id=endpoint_id,
            location=str(row.get("location", "query"))[:40],
            name=str(row.get("name", ""))[:300],
            value_type=str(row.get("value_type", "unknown"))[:80],
            required=1 if row.get("required") else 0,
            sensitive=1 if row.get("sensitive") else 0,
            source="sanitized_import",
            example_redacted="••••" if row.get("sensitive") else str(row.get("example_redacted", ""))[:500],
            fingerprint=str(row.get("fingerprint", ""))[:80],
        ))

    request_map = {}
    for row in manifest.get("stored_requests", []):
        req = StoredRequest(
            project_id=project.id,
            name=str(row.get("name", "Imported Request"))[:240],
            method=str(row.get("method", "GET"))[:16],
            url=str(row.get("url", ""))[:2000],
            headers_json=json.dumps(row.get("public_headers", {}), ensure_ascii=False),
            secret_headers_encrypted="",
            body="",
            source="sanitized_import",
            policy_class=str(row.get("policy_class", "READ_ONLY"))[:50],
        )
        db.add(req); db.flush()
        request_map[row.get("source_id")] = req.id

    identity_map = {}
    for row in manifest.get("identities", []):
        identity = Identity(
            project_id=project.id,
            name=str(row.get("name", "Imported Identity"))[:120],
            role=str(row.get("role", "User"))[:80],
            headers_encrypted="",
            cookies_encrypted="",
            notes="Imported without credentials; configure authorized session material before replay.",
        )
        db.add(identity); db.flush()
        identity_map[row.get("source_id")] = identity.id

    finding_map = {}
    for row in manifest.get("findings", []):
        finding = Finding(
            project_id=project.id,
            title=str(row.get("title", "Imported Finding"))[:300],
            severity=str(row.get("severity", "info"))[:30],
            target=str(row.get("target", ""))[:1000],
            description=str(row.get("description", "")),
            recommendation=str(row.get("recommendation", "")),
            source="sanitized_import",
            fingerprint=str(row.get("fingerprint", ""))[:80],
            dedupe_status="unique",
            vuln_type=str(row.get("vuln_type", ""))[:160],
            parameter=str(row.get("parameter", ""))[:300],
            cwe_id=str(row.get("cwe_id", ""))[:32],
            owasp_category=str(row.get("owasp_category", ""))[:80],
            txb02_category=str(row.get("txb02_category", ""))[:180],
            finding_state=str(row.get("finding_state", "candidate"))[:60],
            verification_state="unverified",
            reopened_count=int(row.get("reopened_count", 0) or 0),
        )
        db.add(finding); db.flush()
        ensure_finding_metadata(db, finding)
        finding_map[row.get("source_id")] = finding.id

    for row in manifest.get("finding_lifecycles", []):
        finding_id = finding_map.get(row.get("finding_source_id"))
        if not finding_id:
            continue
        db.add(FindingLifecycle(
            project_id=project.id,
            finding_id=finding_id,
            status=str(row.get("status", "open"))[:80],
            owner=str(row.get("owner", ""))[:180],
            priority=str(row.get("priority", "normal"))[:40],
            remediation_note="",
            retest_status="not_queued",
        ))

    for row in manifest.get("authorization_cases", []):
        request_id = request_map.get(row.get("stored_request_source_id"))
        if not request_id:
            continue
        db.add(AuthorizationCase(
            project_id=project.id,
            stored_request_id=request_id,
            test_type=str(row.get("test_type", "horizontal"))[:50],
            baseline_identity_id=identity_map.get(row.get("baseline_identity_source_id")),
            comparison_identity_id=identity_map.get(row.get("comparison_identity_source_id")),
            expected_owner_identity_id=identity_map.get(row.get("expected_owner_identity_source_id")),
            finding_id=finding_map.get(row.get("finding_source_id")),
            status="historical_import",
            classification=str(row.get("classification", "needs_review"))[:100],
            confidence=int(row.get("confidence", 0) or 0),
            object_label=str(row.get("object_label", ""))[:300],
            summary_json=json.dumps({"imported_sanitized": True}, ensure_ascii=False),
            ai_review_json="{}",
        ))

    db.commit()
    db.refresh(project)
    return project
