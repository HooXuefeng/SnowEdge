from __future__ import annotations
from urllib.parse import urljoin
import httpx
from .utils import clipped_text
from ..scope import target_in_scope

REDIRECT_CODES = {301, 302, 303, 307, 308}

def safe_redirect_url(current_url: str, location: str, scope_rules: list[str]) -> str | None:
    candidate = urljoin(current_url, location)
    return candidate if target_in_scope(candidate, scope_rules) else None

async def probe_http(
    url: str,
    timeout: float,
    max_body: int,
    scope_rules: list[str],
    max_redirects: int = 5,
    proxy_url: str | None = None,
) -> dict:
    result = {"url": url, "ok": False, "history": []}
    current = url

    async with httpx.AsyncClient(
        follow_redirects=False,
        verify=False,
        timeout=timeout,
        headers={"User-Agent": "SnowEdge/1.7.0 Authorized-Security-Test"},
        proxy=proxy_url,
    ) as client:
        try:
            for _ in range(max_redirects + 1):
                if not target_in_scope(current, scope_rules):
                    result["error"] = "Redirect blocked: destination is outside authorized scope."
                    result["blocked_url"] = current
                    return result

                r = await client.get(current)
                result["history"].append({"status_code": r.status_code, "url": str(r.url)})

                if r.status_code in REDIRECT_CODES and r.headers.get("location"):
                    next_url = safe_redirect_url(str(r.url), r.headers["location"], scope_rules)
                    if not next_url:
                        result.update({
                            "ok": True,
                            "final_url": str(r.url),
                            "status_code": r.status_code,
                            "headers": dict(r.headers),
                            "body": clipped_text(r.content, max_body),
                            "redirect_blocked": True,
                            "blocked_location": r.headers["location"],
                        })
                        return result
                    current = next_url
                    continue

                result.update({
                    "ok": True,
                    "final_url": str(r.url),
                    "status_code": r.status_code,
                    "headers": dict(r.headers),
                    "body": clipped_text(r.content, max_body),
                })
                return result

            result["error"] = f"Maximum redirects exceeded ({max_redirects})."
        except Exception as exc:
            result["error"] = f"{type(exc).__name__}: {exc}"

    return result
