from __future__ import annotations

import json
import time
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx
from sqlalchemy.orm import Session

from ..config import settings
from ..models import AgentEvent, AgentRun, Evidence, Identity, ReplayResult, StoredRequest, StoredRequestRevision, Task
from ..policy import PolicyClass
from ..scope import target_in_scope
from .secret_store import decrypt_json, encrypt_json, split_sensitive_headers
from .secret_vault import identity_material
from .evidence_safety import redact_url
from .network_routes import httpx_proxy_url

SAFE_NATIVE_METHODS = {"GET", "HEAD"}


@dataclass
class ParsedRawRequest:
    method: str
    url: str
    headers: dict[str, str]
    body: str


def parse_raw_http_request(raw: str, scheme: str = "https") -> ParsedRawRequest:
    normalized = raw.replace("\r\n", "\n")
    head, _, body = normalized.partition("\n\n")
    lines = [line for line in head.split("\n") if line.strip()]
    if not lines:
        raise ValueError("Raw request is empty.")
    request_line = lines[0].strip().split()
    if len(request_line) < 2:
        raise ValueError("Invalid request line.")
    method = request_line[0].upper()
    target = request_line[1]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()

    if target.startswith("http://") or target.startswith("https://"):
        url = target
    else:
        host = next((v for k, v in headers.items() if k.lower() == "host"), "")
        if not host:
            raise ValueError("Host header is required for origin-form requests.")
        scheme = scheme if scheme in {"http", "https"} else "https"
        url = f"{scheme}://{host}{target if target.startswith('/') else '/' + target}"
    return ParsedRawRequest(method=method, url=url, headers=headers, body=body)


def request_policy(method: str, explicit_read_only: bool = False) -> str:
    method = method.upper()
    if method in SAFE_NATIVE_METHODS or explicit_read_only:
        return PolicyClass.READ_ONLY.value
    return PolicyClass.STATE_CHANGE.value

def parse_header_lines(raw: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in (raw or "").replace("\r\n", "\n").split("\n"):
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        if key:
            headers[key] = value.strip()
    return headers


def request_raw_text(stored: StoredRequest, *, include_masked_secrets: bool = True) -> str:
    parsed = urlparse(redact_url(stored.url))
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    public_headers = json.loads(stored.headers_json or "{}")
    lines = [f"{stored.method} {target} HTTP/1.1"]
    if parsed.netloc:
        lines.append(f"Host: {parsed.netloc}")
    for key, value in public_headers.items():
        if str(key).lower() == "host":
            continue
        lines.append(f"{key}: {value}")
    if include_masked_secrets:
        secrets = decrypt_json(stored.secret_headers_encrypted, {})
        if isinstance(secrets, dict):
            for key in secrets:
                lines.append(f"{key}: ••••")
    lines.append("")
    if stored.body:
        lines.append(stored.body)
    return "\n".join(lines)


def _preserve_redacted_query_values(original_url: str, edited_url: str) -> str:
    original = urlparse(original_url)
    edited = urlparse(edited_url)
    original_values = {}
    for key, value in parse_qsl(original.query, keep_blank_values=True):
        original_values.setdefault(key, []).append(value)

    seen = {}
    pairs = []
    for key, value in parse_qsl(edited.query, keep_blank_values=True):
        index = seen.get(key, 0)
        seen[key] = index + 1
        if value == "••••":
            candidates = original_values.get(key, [])
            if index < len(candidates):
                value = candidates[index]
        pairs.append((key, value))
    query = urlencode(pairs, doseq=True)
    return urlunparse(edited._replace(query=query))


def _next_revision_no(db: Session, stored_request_id: int) -> int:
    row = (
        db.query(StoredRequestRevision.revision_no)
        .filter(StoredRequestRevision.stored_request_id == stored_request_id)
        .order_by(StoredRequestRevision.revision_no.desc())
        .first()
    )
    return (int(row[0]) + 1) if row else 1


def snapshot_request_revision(
    db: Session,
    stored: StoredRequest,
    *,
    change_note: str = "",
) -> StoredRequestRevision:
    revision = StoredRequestRevision(
        project_id=stored.project_id,
        stored_request_id=stored.id,
        revision_no=_next_revision_no(db, stored.id),
        name=stored.name,
        method=stored.method,
        url=stored.url,
        headers_json=stored.headers_json,
        secret_headers_encrypted=stored.secret_headers_encrypted,
        body=stored.body,
        policy_class=stored.policy_class,
        change_note=(change_note or "")[:500],
    )
    db.add(revision)
    db.commit()
    db.refresh(revision)
    return revision


def update_stored_request(
    db: Session,
    stored: StoredRequest,
    *,
    name: str,
    method: str,
    url: str,
    headers_text: str,
    body: str,
    change_note: str = "",
) -> StoredRequest:
    method = (method or stored.method).upper().strip()
    if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
        raise ValueError("Unsupported HTTP method.")
    url = _preserve_redacted_query_values(stored.url, (url or "").strip())
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Request URL must be a valid HTTP/HTTPS URL.")

    incoming = parse_header_lines(headers_text)
    public_headers, new_secret_headers = split_sensitive_headers(incoming)
    existing_secrets = decrypt_json(stored.secret_headers_encrypted, {})
    if not isinstance(existing_secrets, dict):
        existing_secrets = {}
    existing_secrets.update(new_secret_headers)

    stored.name = (name or f"{method} {url}")[:240]
    stored.method = method
    stored.url = url.strip()
    stored.headers_json = json.dumps(public_headers, ensure_ascii=False)
    stored.secret_headers_encrypted = encrypt_json(existing_secrets) if existing_secrets else ""
    stored.body = body or ""
    # Editing never upgrades a state-changing method to READ_ONLY.
    stored.policy_class = request_policy(method, explicit_read_only=False)
    db.commit()
    db.refresh(stored)
    snapshot_request_revision(db, stored, change_note=change_note or "Edited in Request Workspace 2.0")
    from .endpoint_inventory import sync_stored_request_endpoint
    sync_stored_request_endpoint(db, stored)
    return stored


def restore_request_revision(
    db: Session,
    stored: StoredRequest,
    revision: StoredRequestRevision,
) -> StoredRequest:
    if revision.stored_request_id != stored.id or revision.project_id != stored.project_id:
        raise ValueError("Revision does not belong to this request.")
    stored.name = revision.name
    stored.method = revision.method
    stored.url = revision.url
    stored.headers_json = revision.headers_json
    stored.secret_headers_encrypted = revision.secret_headers_encrypted
    stored.body = revision.body
    stored.policy_class = revision.policy_class
    db.commit()
    db.refresh(stored)
    snapshot_request_revision(db, stored, change_note=f"Restored from revision #{revision.revision_no}")
    from .endpoint_inventory import sync_stored_request_endpoint
    sync_stored_request_endpoint(db, stored)
    return stored


def request_revisions(db: Session, stored_request_id: int, limit: int = 30) -> list[StoredRequestRevision]:
    return (
        db.query(StoredRequestRevision)
        .filter(StoredRequestRevision.stored_request_id == stored_request_id)
        .order_by(StoredRequestRevision.revision_no.desc())
        .limit(max(1, min(limit, 100)))
        .all()
    )


def create_stored_request(
    db: Session,
    project_id: int,
    name: str,
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: str = "",
    source: str = "manual",
    explicit_read_only: bool = False,
) -> StoredRequest:
    headers = headers or {}
    public_headers, secret_headers = split_sensitive_headers(headers)
    req = StoredRequest(
        project_id=project_id,
        name=(name or f"{method.upper()} {url}")[:240],
        method=method.upper(),
        url=url,
        headers_json=json.dumps(public_headers, ensure_ascii=False),
        secret_headers_encrypted=encrypt_json(secret_headers) if secret_headers else "",
        body=body,
        source=source[:80],
        policy_class=request_policy(method, explicit_read_only),
    )
    db.add(req)
    db.commit()
    db.refresh(req)
    from .endpoint_inventory import sync_stored_request_endpoint
    sync_stored_request_endpoint(db, req)
    snapshot_request_revision(db, req, change_note=f"Created from {source}")
    return req


def _identity_headers(db: Session, identity: Identity | None) -> dict[str, str]:
    headers, cookies = identity_material(db, identity)
    result = dict(headers)
    if cookies:
        result["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    return result


def _latest_agent(db: Session, project_id: int):
    return db.query(AgentRun).filter(AgentRun.project_id == project_id).order_by(AgentRun.id.desc()).first()


async def replay_request(
    db: Session,
    project_scope: list[str],
    stored: StoredRequest,
    identity: Identity | None = None,
) -> ReplayResult:
    if not target_in_scope(stored.url, project_scope):
        raise ValueError("Replay blocked: URL is outside authorized scope.")
    if stored.policy_class != PolicyClass.READ_ONLY.value:
        raise ValueError("Replay blocked: request is not classified READ_ONLY.")

    public_headers = json.loads(stored.headers_json or "{}")
    secret_headers = decrypt_json(stored.secret_headers_encrypted, {})
    headers = {str(k): str(v) for k, v in public_headers.items()}
    headers.update({str(k): str(v) for k, v in secret_headers.items()} if isinstance(secret_headers, dict) else {})
    headers.update(_identity_headers(db, identity))
    headers.pop("Host", None)
    headers.pop("host", None)
    headers.setdefault("User-Agent", "SnowEdge/1.7.0 Authorized-Replay")

    task = Task(
        project_id=stored.project_id,
        action="request_replay",
        target=stored.url,
        policy_class=PolicyClass.READ_ONLY.value,
        status="running",
        detail=f"Manual replay of stored request #{stored.id}",
    )
    db.add(task)
    db.commit()
    db.refresh(task)

    started = time.perf_counter()
    result = ReplayResult(
        project_id=stored.project_id,
        stored_request_id=stored.id,
        identity_id=identity.id if identity else None,
        status="running",
        request_headers_json=json.dumps({k: ("••••" if k.lower() in {"authorization","cookie","x-api-key","api-key","x-auth-token","x-access-token"} else v) for k,v in headers.items()}, ensure_ascii=False),
    )
    db.add(result)
    db.commit()
    db.refresh(result)

    try:
        proxy_url = httpx_proxy_url(db, stored.project_id)
        async with httpx.AsyncClient(follow_redirects=False, verify=False, timeout=settings.request_timeout_seconds, proxy=proxy_url) as client:
            response = await client.request(
                stored.method,
                stored.url,
                headers=headers,
                content=stored.body.encode("utf-8") if stored.body else None,
            )
        elapsed = int((time.perf_counter() - started) * 1000)
        body = response.content[: settings.max_response_body_bytes].decode("utf-8", errors="replace")
        final_url = str(response.url)
        if response.is_redirect and response.headers.get("location"):
            candidate = urljoin(final_url, response.headers["location"])
            if not target_in_scope(candidate, project_scope):
                result.error = "Redirect destination outside scope; redirect was not followed."
        safe_response_headers = {
            k: ("•••• protected ••••" if k.lower() == "set-cookie" else v)
            for k, v in response.headers.items()
        }
        result.status = "done"
        result.status_code = response.status_code
        result.final_url = final_url
        result.response_headers_json = json.dumps(safe_response_headers, ensure_ascii=False)
        result.response_body = body
        result.elapsed_ms = elapsed
        task.status = "done"
        task.detail = f"HTTP {response.status_code} in {elapsed} ms"
        evidence = Evidence(
            task_id=task.id,
            kind="request_replay_result",
            content=json.dumps({
                "stored_request_id": stored.id,
                "identity_id": identity.id if identity else None,
                "method": stored.method,
                "url": stored.url,
                "status_code": response.status_code,
                "elapsed_ms": elapsed,
                "response_headers": safe_response_headers,
                "response_body": body,
            }, ensure_ascii=False, indent=2),
        )
        db.add(evidence)

        agent = _latest_agent(db, stored.project_id)
        if agent:
            db.add(AgentEvent(
                agent_run_id=agent.id,
                event_type="evidence",
                stage="request_validation",
                title=f"Request replay #{result.id}",
                detail=f"{stored.method} {stored.url} returned HTTP {response.status_code} using identity {identity.name if identity else 'Anonymous'}.",
                policy_class=PolicyClass.READ_ONLY.value,
                status="done",
            ))
    except Exception as exc:
        elapsed = int((time.perf_counter() - started) * 1000)
        result.status = "error"
        result.error = f"{type(exc).__name__}: {exc}"
        result.elapsed_ms = elapsed
        task.status = "error"
        task.detail = result.error
    db.commit()
    db.refresh(result)
    return result
