from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import httpx

from ..scope import target_in_scope

API_PATTERNS = [
    re.compile(r"(?P<quote>[\"'`])(?P<path>/(?:api|rest|graphql|v\d+|auth|user|users|account|accounts|admin|order|orders|report|reports|file|files)[A-Za-z0-9_./?&={}\-:$]*)\1", re.I),
    re.compile(r"(?P<quote>[\"'`])(?P<path>https?://[^\"'`\s]+)\1", re.I),
]
SOURCE_MAP_RE = re.compile(r"sourceMappingURL\s*=\s*([^\s*]+)", re.I)


class DiscoveryParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[dict] = []
        self.meta_generators: list[str] = []

    def handle_starttag(self, tag, attrs):
        data = dict(attrs)
        if tag == "a" and data.get("href"):
            self.links.append(data["href"])
        elif tag == "script" and data.get("src"):
            self.scripts.append(data["src"])
        elif tag == "form":
            self.forms.append({
                "action": data.get("action", ""),
                "method": (data.get("method") or "GET").upper(),
            })
        elif tag == "meta" and (data.get("name") or "").lower() == "generator":
            if data.get("content"):
                self.meta_generators.append(data["content"])


def _clip(content: bytes, limit: int = 500_000) -> str:
    return content[:limit].decode("utf-8", errors="replace")


def _extract_routes(text: str, source_url: str, scope_rules: list[str]) -> list[dict]:
    found: dict[tuple[str, str], dict] = {}

    for pattern in API_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group("path")
            absolute = urljoin(source_url, value)
            parsed = urlparse(value)
            if parsed.scheme and not target_in_scope(absolute, scope_rules):
                continue
            path = value if value.startswith("/") else absolute
            found[("UNKNOWN", path)] = {
                "method": "UNKNOWN",
                "path": path,
                "source": source_url,
                "confidence": "medium",
            }

    for match in re.finditer(r"fetch\(\s*[\"'`]([^\"'`]+)[\"'`]", text, re.I):
        value = match.group(1)
        absolute = urljoin(source_url, value)
        if not urlparse(value).scheme or target_in_scope(absolute, scope_rules):
            path = value if value.startswith("/") else absolute
            found[("GET", path)] = {
                "method": "GET", "path": path, "source": source_url, "confidence": "high"
            }

    for match in re.finditer(r"axios\.(get|post|put|patch|delete)\(\s*[\"'`]([^\"'`]+)[\"'`]", text, re.I):
        method, value = match.group(1).upper(), match.group(2)
        absolute = urljoin(source_url, value)
        if not urlparse(value).scheme or target_in_scope(absolute, scope_rules):
            path = value if value.startswith("/") else absolute
            found[(method, path)] = {
                "method": method, "path": path, "source": source_url, "confidence": "high"
            }

    return list(found.values())


def _fingerprint(headers: dict[str, str], body: str, generators: list[str]) -> list[str]:
    tech = set()
    lowered = {k.lower(): v for k, v in headers.items()}
    joined = " ".join([
        lowered.get("server", ""),
        lowered.get("x-powered-by", ""),
        " ".join(generators),
        body[:120000],
    ]).lower()
    for needle, label in {
        "nginx": "Nginx",
        "apache": "Apache HTTP Server",
        "iis": "Microsoft IIS",
        "express": "Express",
        "__next_data__": "Next.js",
        "react": "React",
        "vue": "Vue.js",
        "angular": "Angular",
        "wordpress": "WordPress",
        "laravel": "Laravel",
        "django": "Django",
        "spring": "Spring",
    }.items():
        if needle in joined:
            tech.add(label)
    for item in generators:
        if item.strip():
            tech.add(item.strip())
    return sorted(tech)


async def discover_web(
    start_url: str,
    scope_rules: list[str],
    timeout: float = 8.0,
    max_pages: int = 20,
    max_scripts: int = 30,
    proxy_url: str | None = None,
) -> dict:
    if not target_in_scope(start_url, scope_rules):
        return {"ok": False, "error": "Start URL is outside scope."}

    visited = set()
    queue = [start_url]
    pages, scripts, routes = [], [], []
    technologies = set()
    script_urls = []
    headers = {"User-Agent": "SnowEdge/1.7.0 Authorized-Web-Discovery"}

    async with httpx.AsyncClient(
        follow_redirects=False, verify=False, timeout=timeout, headers=headers, proxy=proxy_url
    ) as client:
        while queue and len(visited) < max_pages:
            url = queue.pop(0)
            if url in visited or not target_in_scope(url, scope_rules):
                continue
            visited.add(url)

            try:
                r = await client.get(url)
            except Exception as exc:
                pages.append({"url": url, "error": f"{type(exc).__name__}: {exc}"})
                continue

            ctype = r.headers.get("content-type", "")
            item = {"url": str(r.url), "status_code": r.status_code, "content_type": ctype}

            if "text/html" in ctype.lower():
                text = _clip(r.content)
                parser = DiscoveryParser()
                try:
                    parser.feed(text)
                except Exception:
                    pass

                item.update({"links": len(parser.links), "scripts": len(parser.scripts), "forms": parser.forms})
                technologies.update(_fingerprint(dict(r.headers), text, parser.meta_generators))

                for href in parser.links:
                    candidate = urljoin(str(r.url), href)
                    parsed = urlparse(candidate)
                    if parsed.scheme in {"http", "https"} and target_in_scope(candidate, scope_rules):
                        normalized = parsed._replace(fragment="").geturl()
                        if normalized not in visited and normalized not in queue and len(queue) < max_pages * 3:
                            queue.append(normalized)

                for src in parser.scripts:
                    candidate = urljoin(str(r.url), src)
                    if target_in_scope(candidate, scope_rules) and candidate not in script_urls:
                        script_urls.append(candidate)

                for form in parser.forms:
                    if form.get("action"):
                        absolute = urljoin(str(r.url), form["action"])
                        if target_in_scope(absolute, scope_rules):
                            routes.append({
                                "method": form.get("method", "GET"),
                                "path": absolute,
                                "source": str(r.url),
                                "confidence": "high",
                            })

            pages.append(item)

        for script_url in script_urls[:max_scripts]:
            try:
                r = await client.get(script_url)
            except Exception as exc:
                scripts.append({"url": script_url, "error": f"{type(exc).__name__}: {exc}"})
                continue

            text = _clip(r.content)
            script_routes = _extract_routes(text, script_url, scope_rules)
            routes.extend(script_routes)

            source_maps = []
            for m in SOURCE_MAP_RE.finditer(text[-12000:]):
                candidate = urljoin(script_url, m.group(1).strip())
                if target_in_scope(candidate, scope_rules):
                    source_maps.append(candidate)

            scripts.append({
                "url": script_url,
                "status_code": r.status_code,
                "content_type": r.headers.get("content-type", ""),
                "size": len(r.content),
                "route_candidates": len(script_routes),
                "source_maps": source_maps,
            })

    dedup = {}
    for route in routes:
        key = (route.get("method", "UNKNOWN"), route.get("path", ""))
        if key[1]:
            dedup[key] = route

    return {
        "ok": True,
        "start_url": start_url,
        "pages": pages,
        "scripts": scripts,
        "routes": list(dedup.values()),
        "technologies": sorted(technologies),
        "limits": {"max_pages": max_pages, "max_scripts": max_scripts},
    }
