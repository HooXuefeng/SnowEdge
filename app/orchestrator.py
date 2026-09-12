from __future__ import annotations

import copy
import json
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from .ai.factory import get_ai_provider
from .config import settings
from .models import (
    AgentEvent,
    AgentRun,
    Asset,
    Endpoint,
    Project,
    RouteCandidate,
    Service,
    Task,
    WebArtifact,
)
from .policy import classify_action, is_auto_allowed
from .scope import normalize_host, target_in_scope
from .scanners.headers import analyze_headers
from .scanners.http_probe import probe_http
from .scanners.ports import scan_ports
from .scanners.tls import analyze_tls
from .scanners.web_discovery import discover_web
from .services.finding_service import add_task_evidence, create_finding
from .services.network_routes import active_route, httpx_proxy_url
from .skills.analysis import coverage_snapshot, guardrail_snapshot
from .skills.registry import enabled_skills, skill_ai_context
from .skills.runtime import capability_enabled, finish_skill_run, start_skill_run


def scope_rules(project: Project) -> list[str]:
    return [x.strip() for x in project.scope_text.splitlines() if x.strip()]


def _task(db: Session, project_id: int, action: str, target: str, status: str, detail: str = "") -> Task:
    task = Task(
        project_id=project_id,
        action=action,
        target=target,
        policy_class=classify_action(action).value,
        status=status,
        detail=detail,
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


def _finish_task(db: Session, task: Task, status: str, detail: str = ""):
    task.status = status
    task.detail = detail
    db.commit()


def _agent_event(
    db: Session,
    run: AgentRun,
    title: str,
    detail: str,
    stage: str,
    event_type: str = "observation",
    policy_class: str = "READ_ONLY",
    status: str = "done",
):
    run.stage = stage
    db.add(AgentEvent(
        agent_run_id=run.id,
        event_type=event_type,
        stage=stage,
        title=title[:300],
        detail=detail,
        policy_class=policy_class,
        status=status,
    ))
    db.commit()


def _ai_context(context: dict) -> dict:
    data = copy.deepcopy(context)
    if not settings.ai_include_response_body:
        http = data.get("http")
        if isinstance(http, dict) and "body" in http:
            body = http.pop("body")
            http["body_omitted_from_ai"] = True
            http["body_length_chars"] = len(body) if isinstance(body, str) else 0

    discovery = data.get("discovery")
    if isinstance(discovery, dict):
        data["discovery"] = {
            "ok": discovery.get("ok"),
            "start_url": discovery.get("start_url"),
            "technologies": discovery.get("technologies", []),
            "page_count": len(discovery.get("pages", [])),
            "script_count": len(discovery.get("scripts", [])),
            "route_candidates": discovery.get("routes", [])[:100],
        }
    return data


def _persist_discovery(db: Session, asset: Asset, result: dict):
    if not result.get("ok"):
        return

    for page in result.get("pages", []):
        url = page.get("url")
        if not url:
            continue
        exists = db.query(WebArtifact).filter(
            WebArtifact.asset_id == asset.id,
            WebArtifact.url == url,
            WebArtifact.artifact_type == "page",
        ).first()
        if not exists:
            db.add(WebArtifact(
                asset_id=asset.id,
                url=url,
                artifact_type="page",
                source_url=result.get("start_url", ""),
                status_code=page.get("status_code"),
                content_type=page.get("content_type", ""),
                metadata_json=json.dumps(page, ensure_ascii=False),
            ))

        ep = db.query(Endpoint).filter(
            Endpoint.asset_id == asset.id,
            Endpoint.url == url,
            Endpoint.method == "GET",
        ).first()
        if not ep:
            db.add(Endpoint(
                asset_id=asset.id,
                url=url,
                method="GET",
                status_code=page.get("status_code"),
            ))

    for script in result.get("scripts", []):
        url = script.get("url")
        if not url:
            continue
        exists = db.query(WebArtifact).filter(
            WebArtifact.asset_id == asset.id,
            WebArtifact.url == url,
            WebArtifact.artifact_type == "javascript",
        ).first()
        if not exists:
            db.add(WebArtifact(
                asset_id=asset.id,
                url=url,
                artifact_type="javascript",
                source_url=result.get("start_url", ""),
                status_code=script.get("status_code"),
                content_type=script.get("content_type", ""),
                metadata_json=json.dumps(script, ensure_ascii=False),
            ))

        for map_url in script.get("source_maps", []):
            map_exists = db.query(WebArtifact).filter(
                WebArtifact.asset_id == asset.id,
                WebArtifact.url == map_url,
                WebArtifact.artifact_type == "source_map_reference",
            ).first()
            if not map_exists:
                db.add(WebArtifact(
                    asset_id=asset.id,
                    url=map_url,
                    artifact_type="source_map_reference",
                    source_url=url,
                    metadata_json=json.dumps({"referenced_by": url}, ensure_ascii=False),
                ))

    for route in result.get("routes", []):
        path = route.get("path")
        method = route.get("method", "UNKNOWN")
        if not path:
            continue
        exists = db.query(RouteCandidate).filter(
            RouteCandidate.asset_id == asset.id,
            RouteCandidate.path == path,
            RouteCandidate.method == method,
        ).first()
        if not exists:
            db.add(RouteCandidate(
                asset_id=asset.id,
                path=path,
                method=method,
                source=route.get("source", ""),
                confidence=route.get("confidence", "medium"),
                metadata_json=json.dumps(route, ensure_ascii=False),
            ))

    if result.get("technologies"):
        db.add(WebArtifact(
            asset_id=asset.id,
            url=result.get("start_url", ""),
            artifact_type="technology_snapshot",
            source_url=result.get("start_url", ""),
            metadata_json=json.dumps({"technologies": result.get("technologies", [])}, ensure_ascii=False),
        ))
    db.commit()


async def run_authorized_scan(db: Session, project: Project, target: str) -> dict:
    rules = scope_rules(project)
    if not target_in_scope(target, rules):
        raise ValueError("Target is outside the project's authorized scope.")

    existing_count = db.query(Task).filter(Task.project_id == project.id).count()
    if existing_count >= settings.max_project_tasks:
        raise ValueError("Project task limit reached.")

    selected = enabled_skills(db, project.id)
    selected_names = [skill.name for skill in selected]
    selected_slugs = [skill.slug for skill in selected]

    run = AgentRun(
        project_id=project.id,
        target=target,
        mission=(
            "Execute the project's selected safe Skills against the authorized target, "
            "collect evidence, and keep every action behind deterministic Scope/Policy enforcement."
        ),
        stage="skill_planning",
        status="running",
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    _agent_event(
        db, run,
        "Skill plan compiled",
        f"{len(selected_slugs)} selected skill(s): {', '.join(selected_slugs) if selected_slugs else 'none'}.",
        "skill_planning",
        "plan",
        "READ_ONLY",
    )

    host = normalize_host(target)
    is_ip = False
    try:
        import ipaddress
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass

    asset = db.query(Asset).filter(Asset.project_id == project.id, Asset.target == host).first()
    if not asset:
        asset = Asset(project_id=project.id, target=host, kind="ip" if is_ip else "hostname")
        db.add(asset)
        db.commit()
        db.refresh(asset)

    route_profile = active_route(db, project.id)
    proxy_url = httpx_proxy_url(db, project.id)
    context = {
        "target": target,
        "host": host,
        "selected_skills": selected_slugs,
        "skill_execution": {},
        "network_route": {
            "name": route_profile.name if route_profile else "Direct",
            "route_type": route_profile.route_type if route_profile else "direct",
            "proxy_enabled": bool(proxy_url),
        },
    }

    parsed = urlparse(target if "://" in target else "")
    url = target if parsed.scheme in ("http", "https") else f"http://{host}"
    http_result: dict = {}
    final_url = url

    try:
        # 1) Safe reconnaissance skill.
        if capability_enabled(db, project.id, "port_scan") and is_auto_allowed("port_scan") and not proxy_url:
            sr = start_skill_run(db, project.id, "port_scan", host, run, "recon")
            try:
                _agent_event(db, run, "Port reconnaissance", f"Running constrained TCP reconnaissance against {host}.", "recon", "action", "LOW_RISK_VALIDATE", "running")
                task = _task(db, project.id, "port_scan", host, "running")
                port_result = await scan_ports(host)
                context["ports"] = port_result
                add_task_evidence(db, task, "port_scan_result", port_result)

                for service in port_result.get("services", []):
                    exists = db.query(Service).filter(
                        Service.asset_id == asset.id,
                        Service.port == service["port"],
                        Service.protocol == service.get("protocol", "tcp"),
                    ).first()
                    if not exists:
                        db.add(Service(
                            asset_id=asset.id,
                            port=service["port"],
                            protocol=service.get("protocol", "tcp"),
                            name=service.get("name", "unknown"),
                            banner=service.get("banner", ""),
                        ))
                db.commit()
                _finish_task(db, task, "done", f"{len(port_result.get('services', []))} open service(s)")
                finish_skill_run(db, sr, "done", {"services": len(port_result.get("services", []))}, run)
                context["skill_execution"]["port_scan"] = "done"
            except Exception as exc:
                finish_skill_run(db, sr, "error", {"error": f"{type(exc).__name__}: {exc}"}, run)
                raise

        if capability_enabled(db, project.id, "port_scan") and proxy_url:
            context["skill_execution"]["port_scan"] = "skipped_route_unsupported"
            _agent_event(
                db, run, "Port reconnaissance skipped",
                "The selected Network Route Profile is non-direct. V1.7.0 will not silently bypass it with a direct TCP/Nmap scan.",
                "recon", "observation", "READ_ONLY", "done",
            )

        # Derive a likely web URL from observed ports only when the user supplied no scheme.
        if parsed.scheme not in ("http", "https"):
            open_ports = {x.get("port") for x in context.get("ports", {}).get("services", [])}
            url = f"https://{host}" if 443 in open_ports else f"http://{host}"

        if not target_in_scope(url, rules):
            raise ValueError("Derived URL is outside authorized scope.")

        # 2) HTTP baseline. If disabled, later web skills are skipped instead of silently probing.
        if capability_enabled(db, project.id, "http_probe") and is_auto_allowed("http_probe"):
            sr = start_skill_run(db, project.id, "http_probe", url, run, "web_baseline")
            try:
                _agent_event(db, run, "HTTP baseline", f"Collecting a read-only HTTP baseline from {url}.", "web_baseline", "action")
                task = _task(db, project.id, "http_probe", url, "running")
                http_result = await probe_http(
                    url,
                    settings.request_timeout_seconds,
                    settings.max_response_body_bytes,
                    rules,
                    proxy_url=proxy_url,
                )
                context["http"] = http_result
                add_task_evidence(db, task, "http_request", {
                    "method": "GET",
                    "url": url,
                    "headers": {"User-Agent": "SnowEdge/1.7.0 Persistent-Assessment"},
                    "body": None,
                })
                add_task_evidence(db, task, "http_response", http_result)
                _finish_task(db, task, "done" if http_result.get("ok") else "error", http_result.get("error", ""))
                finish_skill_run(
                    db, sr,
                    "done" if http_result.get("ok") else "error",
                    {"status_code": http_result.get("status_code"), "final_url": http_result.get("final_url", url)},
                    run,
                )
                context["skill_execution"]["http_probe"] = "done" if http_result.get("ok") else "error"
            except Exception as exc:
                finish_skill_run(db, sr, "error", {"error": f"{type(exc).__name__}: {exc}"}, run)
                raise

        if http_result.get("ok"):
            final_url = http_result.get("final_url", url)
            existing_ep = db.query(Endpoint).filter(
                Endpoint.asset_id == asset.id,
                Endpoint.url == final_url,
                Endpoint.method == "GET",
            ).first()
            if not existing_ep:
                db.add(Endpoint(
                    asset_id=asset.id,
                    url=final_url,
                    method="GET",
                    status_code=http_result.get("status_code"),
                ))
                db.commit()

            # 3) Header review is separately selectable.
            if capability_enabled(db, project.id, "headers_check"):
                sr = start_skill_run(db, project.id, "headers_check", final_url, run, "configuration_review")
                scheme = urlparse(final_url).scheme
                header_findings = analyze_headers(http_result.get("headers", {}), scheme)
                for item in header_findings:
                    create_finding(
                        db=db,
                        project_id=project.id,
                        title=item["title"],
                        severity=item["severity"],
                        target=final_url,
                        description=item["description"],
                        recommendation=item["recommendation"],
                        source="headers_check",
                        evidence_kind="http_response_headers",
                        evidence_content=http_result.get("headers", {}),
                    )
                finish_skill_run(db, sr, "done", {"observations": len(header_findings)}, run)
                context["skill_execution"]["headers_check"] = "done"

            if http_result.get("redirect_blocked"):
                create_finding(
                    db=db,
                    project_id=project.id,
                    title="Out-of-scope redirect blocked by orchestrator",
                    severity="info",
                    target=final_url,
                    description="The target attempted to redirect outside configured authorization scope. The redirect was not followed.",
                    recommendation="Review the redirect as contextual information and expand scope only when explicitly authorized.",
                    source="scope_engine",
                    evidence_kind="redirect",
                    evidence_content={"source": final_url, "location": http_result.get("blocked_location")},
                )

            # 4) Web discovery and JS static analysis are separately selectable.
            if capability_enabled(db, project.id, "web_discovery"):
                js_enabled = capability_enabled(db, project.id, "js_static_analysis")
                sr = start_skill_run(db, project.id, "web_discovery", final_url, run, "web_discovery")
                _agent_event(
                    db, run,
                    "Attack-surface discovery",
                    f"Crawling in-scope HTML. JavaScript static analysis={'enabled' if js_enabled else 'disabled'}.",
                    "web_discovery",
                    "action",
                )
                task = _task(db, project.id, "web_discovery", final_url, "running")
                discovery = await discover_web(
                    final_url,
                    rules,
                    timeout=settings.request_timeout_seconds,
                    max_pages=20,
                    max_scripts=30 if js_enabled else 0,
                    proxy_url=proxy_url,
                )
                context["discovery"] = discovery
                add_task_evidence(db, task, "web_discovery_result", discovery)
                _persist_discovery(db, asset, discovery)
                _finish_task(
                    db, task,
                    "done" if discovery.get("ok") else "error",
                    f"{len(discovery.get('pages', []))} pages, {len(discovery.get('scripts', []))} scripts, {len(discovery.get('routes', []))} routes",
                )
                finish_skill_run(db, sr, "done" if discovery.get("ok") else "error", {
                    "pages": len(discovery.get("pages", [])),
                    "scripts": len(discovery.get("scripts", [])),
                    "routes": len(discovery.get("routes", [])),
                    "js_static_analysis": js_enabled,
                }, run)
                context["skill_execution"]["web_discovery"] = "done"

                if js_enabled:
                    js_sr = start_skill_run(db, project.id, "js_static_analysis", final_url, run, "js_analysis")
                    map_refs = sum(len(x.get("source_maps", [])) for x in discovery.get("scripts", []))
                    finish_skill_run(db, js_sr, "done", {
                        "scripts": len(discovery.get("scripts", [])),
                        "route_candidates": len(discovery.get("routes", [])),
                        "source_map_references": map_refs,
                    }, run)
                    context["skill_execution"]["js_static_analysis"] = "done"
                    if map_refs:
                        create_finding(
                            db=db,
                            project_id=project.id,
                            title="JavaScript source map reference discovered",
                            severity="info",
                            target=final_url,
                            description=f"The authorized static analysis found {map_refs} source-map reference(s).",
                            recommendation="Review whether production source maps are required and whether they expose unintended implementation detail.",
                            source="web_discovery",
                            evidence_kind="source_map_references",
                            evidence_content=[
                                {"script": x.get("url"), "source_maps": x.get("source_maps", [])}
                                for x in discovery.get("scripts", []) if x.get("source_maps")
                            ],
                        )

        # 5) TLS review.
        if (
            capability_enabled(db, project.id, "tls_check")
            and urlparse(final_url).scheme == "https"
        ):
            sr = start_skill_run(db, project.id, "tls_check", host, run, "configuration_review")
            task = _task(db, project.id, "tls_check", host, "running")
            tls_result = await analyze_tls(host, 443, settings.request_timeout_seconds)
            context["tls"] = tls_result
            add_task_evidence(db, task, "tls_result", tls_result)
            _finish_task(db, task, "done" if tls_result.get("ok") else "error", tls_result.get("error", ""))
            finish_skill_run(db, sr, "done" if tls_result.get("ok") else "error", {
                "ok": tls_result.get("ok"),
                "protocol": tls_result.get("protocol"),
            }, run)
            context["skill_execution"]["tls_check"] = "done" if tls_result.get("ok") else "error"

        # 6) Local coverage / guardrail analysis.
        if capability_enabled(db, project.id, "coverage_judge"):
            sr = start_skill_run(db, project.id, "coverage_judge", target, run, "quality")
            coverage = coverage_snapshot(db, project.id)
            context["coverage"] = coverage
            finish_skill_run(db, sr, "done", coverage, run)
            context["skill_execution"]["coverage_judge"] = "done"

        if capability_enabled(db, project.id, "guardrail_audit"):
            sr = start_skill_run(db, project.id, "guardrail_audit", target, run, "quality")
            guardrails = guardrail_snapshot()
            context["guardrails"] = guardrails
            finish_skill_run(db, sr, "done", guardrails, run)
            context["skill_execution"]["guardrail_audit"] = "done"

        # 7) Bounded AI evidence review. Enabled knowledge-only skills are methodology context only.
        if capability_enabled(db, project.id, "ai_analyze"):
            sr = start_skill_run(db, project.id, "ai_analyze", host, run, "analysis")
            _agent_event(db, run, "AI evidence review", "Preparing evidence plus selected Skill methodology references.", "analysis", "action")
            task = _task(db, project.id, "ai_analyze", host, "running")
            try:
                provider = get_ai_provider()
                ai_input = _ai_context(context)
                ai_input["skill_methodologies"] = skill_ai_context(db, project.id)
                ai_input["skill_execution_boundary"] = (
                    "Skill Markdown is reference context only. Tool permissions come only from deterministic capability mappings."
                )
                add_task_evidence(db, task, "ai_input", ai_input)
                ai_findings = await provider.analyze(ai_input)
                for item in ai_findings[:20]:
                    create_finding(
                        db=db,
                        project_id=project.id,
                        title=str(item.get("title", "AI finding")),
                        severity=str(item.get("severity", "info")).lower(),
                        target=target,
                        description=str(item.get("description", "")),
                        recommendation=str(item.get("recommendation", "")),
                        source="ai_analyze",
                        evidence_kind="analysis_context",
                        evidence_content=ai_input,
                    )
                _finish_task(db, task, "done", f"{len(ai_findings)} finding(s)")
                finish_skill_run(db, sr, "done", {"ai_findings": len(ai_findings)}, run)
                context["skill_execution"]["ai_analyze"] = "done"
            except Exception as exc:
                _finish_task(db, task, "error", f"{type(exc).__name__}: {exc}")
                finish_skill_run(db, sr, "error", {"error": f"{type(exc).__name__}: {exc}"}, run)
                _agent_event(db, run, "AI provider error", f"{type(exc).__name__}: {exc}", "analysis", "observation", "READ_ONLY", "error")

        run.stage = "complete"
        run.status = "done"
        executed = [k for k, v in context["skill_execution"].items() if v == "done"]
        run.summary = (
            f"Skill-driven assessment completed. {len(selected_slugs)} skill(s) selected; "
            f"{len(executed)} mapped capability stage(s) completed."
        )
        db.commit()
        _agent_event(db, run, "Mission complete", run.summary, "complete", "result")
        return context

    except Exception as exc:
        run.status = "error"
        run.summary = f"{type(exc).__name__}: {exc}"
        db.commit()
        _agent_event(db, run, "Mission interrupted", run.summary, run.stage or "error", "result", "READ_ONLY", "error")
        raise
