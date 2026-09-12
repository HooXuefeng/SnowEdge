from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import parse_qsl, urlparse

from sqlalchemy.orm import Session

from ..models import Asset, Endpoint, EndpointParameter, StoredRequest
from .secret_store import decrypt_json
from .evidence_safety import redact_url

DYNAMIC_SEGMENT_RE = re.compile(r"^(?:\d{2,}|[0-9a-fA-F]{16,}|[0-9a-fA-F-]{24,})$")
SENSITIVE_NAMES = {
    "password", "passwd", "pwd",
    "token", "access_token", "id_token", "refresh_token", "jwt",
    "auth", "authorization", "cookie",
    "session", "sessionid", "sid", "sso",
    "code", "ticket",
    "secret", "credential",
    "api_key", "apikey", "key",
}


def normalize_path(path: str) -> str:
    parts = []
    for part in (path or "/").split("/"):
        if DYNAMIC_SEGMENT_RE.match(part):
            parts.append("{id}")
        else:
            parts.append(part)
    result = "/".join(parts)
    return result if result.startswith("/") else "/" + result


def endpoint_fingerprint(method: str, url: str) -> str:
    parsed = urlparse(url)
    raw = "\x1f".join([
        method.upper(),
        (parsed.hostname or "").lower(),
        normalize_path(parsed.path),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def parameter_fingerprint(endpoint_fp: str, location: str, name: str) -> str:
    raw = "\x1f".join([endpoint_fp, location.lower(), name.lower()])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _is_sensitive_name(name: str) -> bool:
    normalized = str(name or "").lower().replace("[", ".").replace("]", "")
    parts = [part for part in normalized.split(".") if part]
    return any(part in SENSITIVE_NAMES for part in parts)


def _value_type(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    text = str(value)
    if text.isdigit():
        return "integer"
    return "string"


def _redacted_example(name: str, value) -> str:
    if _is_sensitive_name(name):
        return "••••"
    text = str(value)
    if len(text) > 80:
        text = text[:77] + "..."
    return text


def _asset_for_url(db: Session, project_id: int, url: str) -> Asset:
    parsed = urlparse(url)
    host = parsed.hostname or url
    asset = (
        db.query(Asset)
        .filter(Asset.project_id == project_id, Asset.target == host)
        .first()
    )
    if not asset:
        asset = Asset(project_id=project_id, target=host, kind="hostname")
        db.add(asset)
        db.flush()
    return asset


def _upsert_parameter(
    db: Session,
    endpoint: Endpoint,
    location: str,
    name: str,
    value,
    source: str,
) -> EndpointParameter:
    fp = parameter_fingerprint(endpoint.fingerprint, location, name)
    row = (
        db.query(EndpointParameter)
        .filter(
            EndpointParameter.endpoint_id == endpoint.id,
            EndpointParameter.fingerprint == fp,
        )
        .first()
    )
    if not row:
        row = EndpointParameter(
            endpoint_id=endpoint.id,
            location=location,
            name=name[:300],
            value_type=_value_type(value),
            required=0,
            sensitive=1 if _is_sensitive_name(name) else 0,
            source=source[:100],
            example_redacted=_redacted_example(name, value)[:500],
            fingerprint=fp,
        )
        db.add(row)
    else:
        row.value_type = _value_type(value)
        row.sensitive = 1 if _is_sensitive_name(name) else row.sensitive
        row.source = source[:100] or row.source
        row.example_redacted = _redacted_example(name, value)[:500]
        from ..models import _utcnow
        row.last_seen_at = _utcnow()
    return row


def _json_fields(prefix: str, value, out: list[tuple[str, object]], depth: int = 0):
    if depth > 5:
        return
    if isinstance(value, dict):
        for key, child in list(value.items())[:100]:
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(child, (dict, list)):
                _json_fields(path, child, out, depth + 1)
            else:
                out.append((path, child))
    elif isinstance(value, list):
        for child in value[:3]:
            _json_fields(prefix + "[]", child, out, depth + 1)


def sync_stored_request_endpoint(db: Session, stored: StoredRequest) -> Endpoint:
    asset = _asset_for_url(db, stored.project_id, stored.url)
    fp = endpoint_fingerprint(stored.method, stored.url)
    parsed = urlparse(stored.url)
    endpoint = (
        db.query(Endpoint)
        .filter(Endpoint.asset_id == asset.id, Endpoint.fingerprint == fp)
        .first()
    )
    if not endpoint:
        endpoint = Endpoint(
            asset_id=asset.id,
            url=redact_url(stored.url),
            method=stored.method,
            normalized_path=normalize_path(parsed.path),
            fingerprint=fp,
            source=stored.source or "stored_request",
            auth_observed=1 if bool(stored.secret_headers_encrypted) else 0,
        )
        db.add(endpoint)
        db.flush()
    else:
        endpoint.url = redact_url(stored.url)
        endpoint.method = stored.method
        endpoint.normalized_path = normalize_path(parsed.path)
        endpoint.source = stored.source or endpoint.source
        endpoint.auth_observed = max(endpoint.auth_observed, 1 if bool(stored.secret_headers_encrypted) else 0)
        from ..models import _utcnow
        endpoint.last_seen_at = _utcnow()

    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        _upsert_parameter(db, endpoint, "query", key, value, stored.source or "stored_request")

    try:
        public_headers = json.loads(stored.headers_json or "{}")
    except Exception:
        public_headers = {}
    if isinstance(public_headers, dict):
        for key, value in list(public_headers.items())[:100]:
            _upsert_parameter(db, endpoint, "header", str(key), value, stored.source or "stored_request")

    secret_headers = decrypt_json(stored.secret_headers_encrypted, {})
    if isinstance(secret_headers, dict):
        for key in list(secret_headers.keys())[:100]:
            _upsert_parameter(db, endpoint, "header", str(key), "••••", stored.source or "stored_request")

    body = stored.body or ""
    if body:
        try:
            parsed_body = json.loads(body)
        except Exception:
            parsed_body = None
        if parsed_body is not None:
            fields: list[tuple[str, object]] = []
            _json_fields("", parsed_body, fields)
            for name, value in fields[:200]:
                _upsert_parameter(db, endpoint, "body", name, value, stored.source or "stored_request")

    db.commit()
    db.refresh(endpoint)
    return endpoint


def sync_project_endpoint_inventory(db: Session, project_id: int) -> dict:
    stored_requests = (
        db.query(StoredRequest)
        .filter(StoredRequest.project_id == project_id)
        .order_by(StoredRequest.id.asc())
        .all()
    )
    touched = []
    for stored in stored_requests:
        touched.append(sync_stored_request_endpoint(db, stored).id)

    assets = db.query(Asset).filter(Asset.project_id == project_id).all()
    asset_ids = [a.id for a in assets] or [-1]
    endpoints = db.query(Endpoint).filter(Endpoint.asset_id.in_(asset_ids)).all()
    for endpoint in endpoints:
        if not endpoint.normalized_path or not endpoint.fingerprint:
            parsed = urlparse(endpoint.url)
            endpoint.normalized_path = normalize_path(parsed.path)
            endpoint.fingerprint = endpoint_fingerprint(endpoint.method, endpoint.url)
    db.commit()

    endpoint_ids = [e.id for e in endpoints] or [-1]
    return {
        "endpoints": len(endpoints),
        "parameters": db.query(EndpointParameter).filter(EndpointParameter.endpoint_id.in_(endpoint_ids)).count(),
        "touched_from_requests": len(set(touched)),
    }


def endpoint_parameters(db: Session, endpoint_ids: list[int]) -> dict[int, list[EndpointParameter]]:
    rows = (
        db.query(EndpointParameter)
        .filter(EndpointParameter.endpoint_id.in_(endpoint_ids or [-1]))
        .order_by(EndpointParameter.endpoint_id.asc(), EndpointParameter.location.asc(), EndpointParameter.name.asc())
        .all()
    )
    result: dict[int, list[EndpointParameter]] = {}
    for row in rows:
        result.setdefault(row.endpoint_id, []).append(row)
    return result
