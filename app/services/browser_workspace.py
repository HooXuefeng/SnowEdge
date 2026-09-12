from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
from difflib import SequenceMatcher
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from sqlalchemy.orm import Session

from ..config import settings
from ..models import BrowserArtifact, BrowserEvent, BrowserSession, Evidence, Identity, Task
from ..scope import target_in_scope
from .personal_settings import runtime_tool_path
from .network_routes import playwright_proxy
from .secret_vault import identity_material
from .secret_store import decrypt_json, SENSITIVE_HEADER_NAMES

MAX_DOM_TEXT = 120_000
MAX_CONSOLE_TEXT = 4_000
SAFE_NAV_METHODS = {"GET", "HEAD"}
SENSITIVE_QUERY_NAMES = {
    "token", "access_token", "id_token", "refresh_token", "auth", "authorization",
    "code", "ticket", "apikey", "api_key", "key", "session", "sessionid", "sid",
    "jwt", "sso", "credential", "secret",
}


def redact_url(url: str) -> str:
    try:
        parsed = urlparse(url)
        if not parsed.query:
            return url
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        safe = []
        for key, value in pairs:
            if key.lower().strip() in SENSITIVE_QUERY_NAMES:
                safe.append((key, "••••"))
            else:
                safe.append((key, value))
        return urlunparse(parsed._replace(query=urlencode(safe, doseq=True)))
    except Exception:
        return url


def _scope_rules(project) -> list[str]:
    return [x.strip() for x in project.scope_text.splitlines() if x.strip()]


def redact_headers(headers: dict | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in (headers or {}).items():
        name = str(key)
        if name.lower().strip() in SENSITIVE_HEADER_NAMES:
            result[name] = "•••• protected ••••"
        else:
            result[name] = str(value)[:4000]
    return result


def _safe_json(data) -> str:
    return json.dumps(data, ensure_ascii=False, default=str)


def _artifact_dir(project_id: int, session_id: int) -> Path:
    base = Path(settings.browser_artifact_dir).expanduser()
    if not base.is_absolute():
        base = Path.cwd() / base
    path = base / f"project_{project_id}" / f"session_{session_id}"
    path.mkdir(parents=True, exist_ok=True)
    return path.resolve()


def _system_browser_candidates() -> list[Path]:
    candidates: list[Path] = []
    preferred = runtime_tool_path("browser")
    if preferred:
        candidates.append(Path(preferred))
    for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome", "msedge"):
        found = shutil.which(name)
        if found:
            candidates.append(Path(found))

    if os.name == "nt":
        roots = [
            os.environ.get("PROGRAMFILES"),
            os.environ.get("PROGRAMFILES(X86)"),
            os.environ.get("LOCALAPPDATA"),
        ]
        suffixes = [
            r"Google\Chrome\Application\chrome.exe",
            r"Microsoft\Edge\Application\msedge.exe",
            r"Chromium\Application\chrome.exe",
        ]
        for base in roots:
            if not base:
                continue
            for suffix in suffixes:
                candidates.append(Path(base) / suffix)

    seen = set()
    result = []
    for p in candidates:
        try:
            resolved = str(p.resolve())
        except Exception:
            resolved = str(p)
        if resolved in seen:
            continue
        seen.add(resolved)
        if p.exists():
            result.append(p)
    return result


async def browser_runtime_status() -> dict:
    try:
        import playwright  # noqa: F401
        from playwright.async_api import async_playwright
    except Exception as exc:
        return {
            "available": False,
            "playwright_installed": False,
            "browser_available": False,
            "detail": f"Playwright package is unavailable: {type(exc).__name__}: {exc}",
            "system_browser": str(_system_browser_candidates()[0]) if _system_browser_candidates() else "",
        }

    system = _system_browser_candidates()
    return {
        "available": True,
        "playwright_installed": True,
        "browser_available": bool(system),
        "detail": "Playwright is installed. Bundled Chromium is attempted first; system Chromium/Chrome/Edge is used as fallback.",
        "system_browser": str(system[0]) if system else "",
    }


def _identity_context(db: Session, identity: Identity | None, target_url: str) -> tuple[dict[str, str], list[dict]]:
    headers, cookies = identity_material(db, identity)
    safe_headers = {str(k):str(v) for k,v in headers.items() if str(k).lower().strip() not in {"host","content-length","cookie"}}
    cookie_rows = [{"name":str(name),"value":str(value),"url":target_url} for name,value in cookies.items()]
    return safe_headers, cookie_rows


def _persist_event(
    db: Session,
    project_id: int,
    session_id: int,
    event_type: str,
    *,
    method: str = "",
    url: str = "",
    resource_type: str = "",
    status_code: int | None = None,
    detail: dict | None = None,
    in_scope: bool = True,
) -> BrowserEvent:
    row = BrowserEvent(
        project_id=project_id,
        browser_session_id=session_id,
        event_type=event_type,
        method=method[:20],
        url=redact_url(url)[:2200],
        resource_type=resource_type[:80],
        status_code=status_code,
        detail_json=_safe_json(detail or {}),
        in_scope=1 if in_scope else 0,
    )
    db.add(row)
    db.flush()
    return row


async def capture_browser_session(
    db: Session,
    project,
    session: BrowserSession,
    identity: Identity | None = None,
) -> BrowserSession:
    rules = _scope_rules(project)
    if not target_in_scope(session.target_url, rules):
        raise ValueError("Browser navigation target is outside the project's authorized scope.")
    if urlparse(session.target_url).scheme not in {"http", "https"}:
        raise ValueError("Browser Workspace only supports HTTP(S) navigation.")

    task = Task(
        project_id=project.id,
        action="browser_observe",
        target=session.target_url,
        policy_class="READ_ONLY",
        status="running",
        detail=f"Observe-only browser session #{session.id}",
    )
    db.add(task)
    session.status = "running"
    db.commit()
    db.refresh(task)

    try:
        from playwright.async_api import async_playwright
    except Exception as exc:
        session.status = "unavailable"
        session.error = (
            "Playwright is not installed. Install project dependencies and a Chromium browser "
            f"before running Browser Workspace. ({type(exc).__name__}: {exc})"
        )
        task.status = "error"
        task.detail = session.error
        db.commit()
        return session

    network_rows: list[dict] = []
    console_rows: list[dict] = []
    blocked_rows: list[dict] = []
    route_rows: list[dict] = []
    websocket_rows: list[dict] = []
    document_security_headers: dict[str, str] = {}
    screenshot_path = ""
    browser_name = ""
    context = None
    browser = None
    pw = None

    try:
        pw = await async_playwright().start()

        launch_errors = []
        try:
            browser = await pw.chromium.launch(
                headless=settings.browser_headless,
                args=["--disable-dev-shm-usage"],
            )
            browser_name = "playwright-chromium"
        except Exception as exc:
            launch_errors.append(f"bundled Chromium: {type(exc).__name__}: {exc}")
            for candidate in _system_browser_candidates():
                try:
                    browser = await pw.chromium.launch(
                        headless=settings.browser_headless,
                        executable_path=str(candidate),
                        args=["--disable-dev-shm-usage"],
                    )
                    browser_name = candidate.name
                    break
                except Exception as sub_exc:
                    launch_errors.append(f"{candidate}: {type(sub_exc).__name__}: {sub_exc}")

        if browser is None:
            raise RuntimeError("No usable Chromium runtime. " + " | ".join(launch_errors[-3:]))

        identity_headers, identity_cookies = _identity_context(db, identity, session.target_url)
        browser_proxy = playwright_proxy(db, project.id)
        context = await browser.new_context(
            ignore_https_errors=True,
            extra_http_headers=identity_headers,
            viewport={"width": 1440, "height": 960},
            proxy=browser_proxy,
        )
        if identity_cookies:
            await context.add_cookies(identity_cookies)

        page = await context.new_page()

        async def route_handler(route):
            request = route.request
            url = request.url
            if url.startswith(("data:", "blob:", "about:")):
                await route.continue_()
                return
            allowed = target_in_scope(url, rules)
            if not allowed:
                detail = {
                    "reason": "blocked_out_of_scope",
                    "resource_type": request.resource_type,
                }
                _persist_event(
                    db, project.id, session.id, "blocked_out_of_scope",
                    method=request.method,
                    url=url,
                    resource_type=request.resource_type,
                    detail=detail,
                    in_scope=False,
                )
                blocked_rows.append({"method": request.method, "url": url, **detail})
                await route.abort("blockedbyclient")
                return
            await route.continue_()

        await page.route("**/*", route_handler)

        def on_request(request):
            if request.url.startswith(("data:", "blob:", "about:")):
                return
            allowed = target_in_scope(request.url, rules)
            headers = redact_headers(request.headers)
            detail = {
                "headers": headers,
                "post_data_omitted": bool(request.post_data),
                "is_navigation_request": request.is_navigation_request(),
            }
            row = {
                "method": request.method,
                "url": redact_url(request.url),
                "resource_type": request.resource_type,
                "in_scope": allowed,
            }
            network_rows.append(row)
            _persist_event(
                db, project.id, session.id, "request",
                method=request.method,
                url=request.url,
                resource_type=request.resource_type,
                detail=detail,
                in_scope=allowed,
            )

        def on_response(response):
            request = response.request
            if response.url.startswith(("data:", "blob:", "about:")):
                return
            allowed = target_in_scope(response.url, rules)
            if allowed and request.resource_type == "document":
                for key in (
                    "content-security-policy", "content-security-policy-report-only",
                    "strict-transport-security", "x-frame-options",
                    "x-content-type-options", "referrer-policy", "permissions-policy",
                ):
                    value = response.headers.get(key)
                    if value:
                        document_security_headers[key] = value[:4000]
            _persist_event(
                db, project.id, session.id, "response",
                method=request.method,
                url=response.url,
                resource_type=request.resource_type,
                status_code=response.status,
                detail={"headers": redact_headers(response.headers)},
                in_scope=allowed,
            )

        def on_console(message):
            text = message.text[:MAX_CONSOLE_TEXT]
            console_rows.append({"type": message.type, "text": text})
            _persist_event(
                db, project.id, session.id, "console",
                detail={"type": message.type, "text": text},
            )

        def on_frame_navigated(frame):
            try:
                if frame != page.main_frame:
                    return
                url = frame.url
                if not url or url.startswith(("about:", "data:", "blob:")):
                    return
                row = {"url": redact_url(url), "in_scope": target_in_scope(url, rules)}
                if route_rows and route_rows[-1]["url"] == row["url"]:
                    return
                route_rows.append(row)
                _persist_event(
                    db, project.id, session.id, "route_change",
                    method="GET", url=url, resource_type="document",
                    detail={"main_frame": True}, in_scope=row["in_scope"],
                )
            except Exception:
                return

        def on_websocket(ws):
            meta = {
                "url": redact_url(ws.url),
                "frames_sent": 0,
                "frames_received": 0,
                "bytes_sent": 0,
                "bytes_received": 0,
                "closed": False,
            }
            websocket_rows.append(meta)
            _persist_event(
                db, project.id, session.id, "websocket_open",
                method="WS", url=ws.url, resource_type="websocket",
                detail={"payload_content_persisted": False},
                in_scope=target_in_scope(ws.url, rules),
            )

            def _payload_len(payload):
                if isinstance(payload, bytes):
                    return len(payload)
                return len(str(payload).encode("utf-8", errors="replace"))

            def sent(payload):
                length = _payload_len(payload)
                meta["frames_sent"] += 1
                meta["bytes_sent"] += length
                _persist_event(
                    db, project.id, session.id, "websocket_frame_sent",
                    method="WS", url=ws.url, resource_type="websocket",
                    detail={"length": length, "payload_omitted": True},
                    in_scope=target_in_scope(ws.url, rules),
                )

            def received(payload):
                length = _payload_len(payload)
                meta["frames_received"] += 1
                meta["bytes_received"] += length
                _persist_event(
                    db, project.id, session.id, "websocket_frame_received",
                    method="WS", url=ws.url, resource_type="websocket",
                    detail={"length": length, "payload_omitted": True},
                    in_scope=target_in_scope(ws.url, rules),
                )

            def closed():
                meta["closed"] = True
                _persist_event(
                    db, project.id, session.id, "websocket_close",
                    method="WS", url=ws.url, resource_type="websocket",
                    detail={"payload_content_persisted": False},
                    in_scope=target_in_scope(ws.url, rules),
                )

            ws.on("framesent", sent)
            ws.on("framereceived", received)
            ws.on("close", closed)

        page.on("request", on_request)
        page.on("response", on_response)
        page.on("console", on_console)
        page.on("framenavigated", on_frame_navigated)
        page.on("websocket", on_websocket)

        await page.goto(
            session.target_url,
            wait_until="domcontentloaded",
            timeout=int(settings.browser_navigation_timeout_seconds * 1000),
        )
        if settings.browser_post_load_wait_ms > 0:
            await page.wait_for_timeout(settings.browser_post_load_wait_ms)

        final_url = page.url
        if not target_in_scope(final_url, rules):
            raise ValueError("Browser was redirected outside authorized scope.")

        title = await page.title()

        forms = await page.locator("form").evaluate_all(
            """els => els.slice(0,100).map((f, i) => ({
                index: i,
                action: f.action || '',
                method: (f.method || 'get').toUpperCase(),
                inputs: Array.from(f.querySelectorAll('input,select,textarea,button')).slice(0,80).map(el => ({
                    tag: el.tagName,
                    type: el.getAttribute('type') || '',
                    name: el.getAttribute('name') || '',
                    id: el.id || ''
                }))
            }))"""
        )
        scripts = await page.locator("script[src]").evaluate_all(
            "els => els.slice(0,200).map(s => s.src)"
        )
        links = await page.locator("a[href]").evaluate_all(
            "els => els.slice(0,300).map(a => a.href)"
        )
        links = [redact_url(str(link)) for link in links]

        try:
            storage_metadata = await page.evaluate(
                """() => ({
                    localStorageKeys: Object.keys(window.localStorage || {}).slice(0, 150),
                    sessionStorageKeys: Object.keys(window.sessionStorage || {}).slice(0, 150)
                })"""
            )
        except Exception:
            storage_metadata = {"localStorageKeys": [], "sessionStorageKeys": []}

        cookie_metadata = []
        try:
            for cookie in await context.cookies():
                cookie_metadata.append({
                    "name": cookie.get("name", ""),
                    "domain": cookie.get("domain", ""),
                    "path": cookie.get("path", ""),
                    "expires": cookie.get("expires", -1),
                    "httpOnly": bool(cookie.get("httpOnly")),
                    "secure": bool(cookie.get("secure")),
                    "sameSite": cookie.get("sameSite", ""),
                    "value_omitted": True,
                })
        except Exception:
            cookie_metadata = []

        dom_text = await page.content()
        if len(dom_text) > MAX_DOM_TEXT:
            dom_text = dom_text[:MAX_DOM_TEXT] + "\n<!-- truncated -->"

        dom_sha256 = hashlib.sha256(dom_text.encode("utf-8", errors="replace")).hexdigest()
        previous_dom_sha256 = ""
        dom_similarity = None
        previous_session = (
            db.query(BrowserSession)
            .filter(
                BrowserSession.project_id == project.id,
                BrowserSession.id < session.id,
                BrowserSession.target_url == session.target_url,
                BrowserSession.status == "done",
            )
            .order_by(BrowserSession.id.desc())
            .first()
        )
        if previous_session:
            previous_dom = (
                db.query(BrowserArtifact)
                .filter(
                    BrowserArtifact.browser_session_id == previous_session.id,
                    BrowserArtifact.artifact_type == "dom_snapshot",
                )
                .order_by(BrowserArtifact.id.desc())
                .first()
            )
            if previous_dom:
                previous_dom_sha256 = hashlib.sha256(
                    (previous_dom.content_text or "").encode("utf-8", errors="replace")
                ).hexdigest()
                dom_similarity = round(
                    SequenceMatcher(
                        None,
                        (previous_dom.content_text or "")[:30000],
                        dom_text[:30000],
                    ).ratio() * 100,
                    1,
                )

        art_dir = _artifact_dir(project.id, session.id)
        screenshot_file = art_dir / "page.png"
        await page.screenshot(path=str(screenshot_file), full_page=True)
        screenshot_path = str(screenshot_file)

        screenshot = BrowserArtifact(
            project_id=project.id,
            browser_session_id=session.id,
            artifact_type="screenshot",
            label=f"Browser session #{session.id} screenshot",
            file_path=screenshot_path,
            metadata_json=_safe_json({"url": final_url, "title": title}),
        )
        db.add(screenshot)

        dom_art = BrowserArtifact(
            project_id=project.id,
            browser_session_id=session.id,
            artifact_type="dom_snapshot",
            label=f"DOM snapshot · {title}"[:300],
            content_text=dom_text,
            metadata_json=_safe_json({
                "url": final_url,
                "truncated": len(dom_text) >= MAX_DOM_TEXT,
                "forms": forms,
                "scripts": scripts,
                "links": links,
                "dom_sha256": dom_sha256,
                "previous_dom_sha256": previous_dom_sha256,
                "dom_similarity": dom_similarity,
            }),
        )
        db.add(dom_art)

        runtime_meta = {
            "route_timeline": route_rows[:100],
            "websockets": websocket_rows[:50],
            "storage": storage_metadata,
            "cookies": cookie_metadata[:150],
            "document_security_headers": document_security_headers,
            "dom_sha256": dom_sha256,
            "previous_dom_sha256": previous_dom_sha256,
            "dom_similarity": dom_similarity,
            "secrets_persisted": False,
            "websocket_payloads_persisted": False,
        }
        runtime_art = BrowserArtifact(
            project_id=project.id,
            browser_session_id=session.id,
            artifact_type="runtime_metadata",
            label=f"Runtime metadata · {title}"[:300],
            content_text=_safe_json(runtime_meta),
            metadata_json=_safe_json({
                "routes": len(route_rows),
                "websockets": len(websocket_rows),
                "local_storage_keys": len(storage_metadata.get("localStorageKeys", [])),
                "session_storage_keys": len(storage_metadata.get("sessionStorageKeys", [])),
                "cookies": len(cookie_metadata),
            }),
        )
        db.add(runtime_art)

        summary = {
            "requests": sum(1 for x in network_rows if x["in_scope"]),
            "blocked_out_of_scope": len(blocked_rows),
            "xhr_fetch": sum(
                1 for x in network_rows
                if x["in_scope"] and x["resource_type"] in {"xhr", "fetch"}
            ),
            "documents": sum(1 for x in network_rows if x["resource_type"] == "document"),
            "forms": len(forms),
            "scripts": len(scripts),
            "links": len(links),
            "console_messages": len(console_rows),
            "route_changes": len(route_rows),
            "websockets": len(websocket_rows),
            "local_storage_keys": len(storage_metadata.get("localStorageKeys", [])),
            "session_storage_keys": len(storage_metadata.get("sessionStorageKeys", [])),
            "cookie_metadata": len(cookie_metadata),
            "csp_observed": bool(document_security_headers.get("content-security-policy")),
            "dom_changed": bool(previous_dom_sha256 and previous_dom_sha256 != dom_sha256),
            "dom_similarity": dom_similarity,
            "identity_id": identity.id if identity else None,
            "identity_name": identity.name if identity else "Anonymous",
            "secrets_rendered_in_event_ui": False,
        }

        session.status = "done"
        session.final_url = final_url
        session.title = title[:500]
        session.browser_name = browser_name[:120]
        session.summary_json = _safe_json(summary)
        task.status = "done"
        task.detail = (
            f"Browser observed {summary['requests']} in-scope request(s), "
            f"{summary['xhr_fetch']} XHR/Fetch, {summary['forms']} form(s); "
            f"blocked {summary['blocked_out_of_scope']} out-of-scope request(s)."
        )

        evidence = Evidence(
            task_id=task.id,
            kind="browser_observation_summary",
            content=json.dumps({
                "browser_session_id": session.id,
                "target_url": session.target_url,
                "final_url": final_url,
                "title": title,
                "summary": summary,
                "screenshot_artifact": str(screenshot_file.name),
                "form_metadata": forms,
                "scripts": scripts[:100],
                "route_timeline": route_rows[:50],
                "websocket_metadata": websocket_rows[:20],
                "storage_keys": storage_metadata,
                "cookie_metadata": cookie_metadata[:100],
                "document_security_headers": document_security_headers,
                "dom_sha256": dom_sha256,
                "previous_dom_sha256": previous_dom_sha256,
                "dom_similarity": dom_similarity,
            }, ensure_ascii=False, indent=2),
        )
        db.add(evidence)
        db.commit()
        return session

    except Exception as exc:
        session.status = "error"
        if browser_name:
            session.browser_name = browser_name[:120]
        session.error = f"{type(exc).__name__}: {exc}"
        task.status = "error"
        task.detail = session.error
        db.commit()
        return session

    finally:
        try:
            if context is not None:
                await context.close()
        except Exception:
            pass
        try:
            if browser is not None:
                await browser.close()
        except Exception:
            pass
        try:
            if pw is not None:
                await pw.stop()
        except Exception:
            pass
