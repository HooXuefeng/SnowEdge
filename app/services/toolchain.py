from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit
from xml.etree import ElementTree

from sqlalchemy.orm import Session

from ..models import AppPreference, Asset, Endpoint, Evidence, Service
from ..scope import normalize_host, target_in_scope
from .evidence_chain import ensure_evidence_integrity
from .evidence_safety import safe_evidence_text
from .finding_service import create_finding


MAX_TOOL_OUTPUT = 8 * 1024 * 1024
MAX_RECORDS = 10_000


@dataclass(frozen=True)
class ToolDefinition:
    id: str
    name: str
    phase: str
    description: str
    executables: tuple[str, ...]
    version_args: tuple[str, ...]
    output_format: str
    result_types: tuple[str, ...]
    homepage: str
    accepts_ports: bool = False
    needs_url: bool = False


CATALOG = (
    ToolDefinition("nmap", "Nmap", "端口与服务", "服务版本、端口和 CPE 识别", ("nmap.exe", "nmap"), ("--version",), "xml", ("Asset", "Service", "Evidence"), "https://nmap.org/", True),
    ToolDefinition("subfinder", "Subfinder", "资产发现", "被动子域名发现", ("subfinder.exe", "subfinder"), ("-version",), "jsonl", ("Asset", "Evidence"), "https://github.com/projectdiscovery/subfinder"),
    ToolDefinition("naabu", "Naabu", "端口与服务", "快速端口存活探测", ("naabu.exe", "naabu"), ("-version",), "jsonl", ("Asset", "Service", "Evidence"), "https://github.com/projectdiscovery/naabu", True),
    ToolDefinition("httpx", "httpx", "Web 探测", "HTTP 存活、标题和技术信息", ("httpx.exe", "httpx"), ("-version",), "jsonl", ("Asset", "Endpoint", "Evidence"), "https://github.com/projectdiscovery/httpx"),
    ToolDefinition("katana", "Katana", "Web 发现", "页面、路径、JS 与接口发现", ("katana.exe", "katana"), ("-version",), "jsonl", ("Endpoint", "Evidence"), "https://github.com/projectdiscovery/katana", needs_url=True),
    ToolDefinition("nuclei", "Nuclei", "规则检测", "模板检测并保留可追溯结果", ("nuclei.exe", "nuclei"), ("-version",), "jsonl", ("Finding", "Evidence"), "https://github.com/projectdiscovery/nuclei", needs_url=True),
)
CATALOG_BY_ID = {tool.id: tool for tool in CATALOG}

PLANS = {
    "infrastructure": {"name": "基础设施识别", "description": "Naabu 端口预探测 + Nmap 服务识别", "tools": ("naabu", "nmap")},
    "web": {"name": "Web 深度评估", "description": "httpx 存活与指纹 + Katana 路径发现 + Nuclei 规则检测", "tools": ("httpx", "katana", "nuclei")},
    "surface": {"name": "外部资产发现", "description": "Subfinder 子域名发现 + httpx Web 探测", "tools": ("subfinder", "httpx")},
    "full": {"name": "单目标综合评估", "description": "端口、服务、Web、路径与规则检测", "tools": ("naabu", "nmap", "httpx", "katana", "nuclei")},
}


def _preference_key(tool_id: str) -> str:
    return f"toolchain:path:{tool_id}"


def configured_path(db: Session, tool_id: str) -> str:
    row = db.query(AppPreference).filter_by(key=_preference_key(tool_id)).first()
    if not row:
        return ""
    try:
        return str(json.loads(row.value_json).get("path") or "")
    except (TypeError, ValueError):
        return ""


def save_configured_path(db: Session, tool_id: str, path: str) -> None:
    if tool_id not in CATALOG_BY_ID:
        raise ValueError("未知工具。")
    value = path.strip()
    if value:
        candidate = Path(value).expanduser()
        if not candidate.is_absolute() or not candidate.is_file():
            raise ValueError("工具路径必须是已存在的可执行文件绝对路径。")
        value = str(candidate.resolve())
    row = db.query(AppPreference).filter_by(key=_preference_key(tool_id)).first()
    if not row:
        row = AppPreference(key=_preference_key(tool_id))
        db.add(row)
    row.value_json = json.dumps({"path": value}, ensure_ascii=False)
    db.commit()


def resolve_executable(db: Session, tool_id: str) -> str:
    tool = CATALOG_BY_ID.get(tool_id)
    if not tool:
        return ""
    custom = configured_path(db, tool_id)
    if custom and Path(custom).is_file():
        return custom
    for name in tool.executables:
        found = shutil.which(name)
        if found:
            return str(Path(found).resolve())
    return ""


def _version(executable: str, args: tuple[str, ...]) -> str:
    if not executable:
        return ""
    try:
        completed = subprocess.run(
            [executable, *args], capture_output=True, text=True, timeout=3,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        output = (completed.stdout or completed.stderr or "").strip()
        return re.sub(r"\s+", " ", output)[:180]
    except (OSError, subprocess.SubprocessError):
        return ""


def tool_status(db: Session, tool: ToolDefinition) -> dict:
    executable = resolve_executable(db, tool.id)
    data = asdict(tool)
    data.update(installed=bool(executable), executable=executable, version=_version(executable, tool.version_args))
    return data


def catalog_status(db: Session) -> list[dict]:
    # Resolve preferences before entering worker threads; SQLAlchemy sessions are
    # intentionally kept on their request thread.
    rows = []
    for tool in CATALOG:
        executable = resolve_executable(db, tool.id)
        data = asdict(tool)
        data.update(installed=bool(executable), executable=executable, version="")
        rows.append(data)
    with ThreadPoolExecutor(max_workers=min(6, len(rows))) as pool:
        versions = list(pool.map(lambda pair: _version(pair[0], pair[1]), [(row["executable"], CATALOG_BY_ID[row["id"]].version_args) for row in rows]))
    for row, version in zip(rows, versions):
        row["version"] = version
    return rows


def build_command(tool_id: str, executable: str, target: str, ports: list[int]) -> list[str]:
    if tool_id == "nmap":
        return [executable, "-Pn", "-sV", "--version-light", "-p", ",".join(map(str, ports)), "-oX", "-", normalize_host(target)]
    if tool_id == "subfinder":
        return [executable, "-silent", "-json", "-d", normalize_host(target)]
    if tool_id == "naabu":
        return [executable, "-silent", "-json", "-host", normalize_host(target), "-p", ",".join(map(str, ports))]
    if tool_id == "httpx":
        return [executable, "-silent", "-json", "-u", target, "-title", "-tech-detect", "-status-code"]
    if tool_id == "katana":
        return [executable, "-silent", "-jsonl", "-u", target, "-depth", "2"]
    if tool_id == "nuclei":
        return [executable, "-silent", "-jsonl", "-u", target, "-rate-limit", "25", "-bulk-size", "10"]
    raise ValueError("该工具尚未提供受控执行适配器。")


async def _read_limited(stream: asyncio.StreamReader, limit: int) -> bytes:
    data = bytearray()
    while True:
        chunk = await stream.read(65_536)
        if not chunk:
            return bytes(data)
        data.extend(chunk)
        if len(data) > limit:
            raise ValueError("工具输出超过 8 MB 限制，任务已停止；请缩小目标范围。")


async def _run_process(command: list[str], should_stop=None) -> tuple[int, str, str]:
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    stdout_task = asyncio.create_task(_read_limited(process.stdout, MAX_TOOL_OUTPUT))
    stderr_task = asyncio.create_task(_read_limited(process.stderr, 512 * 1024))
    try:
        while process.returncode is None:
            for reader in (stdout_task, stderr_task):
                if reader.done() and not reader.cancelled() and reader.exception():
                    process.kill(); await process.wait(); raise reader.exception()
            if should_stop and should_stop():
                process.kill(); await process.wait()
                raise RuntimeError("工具进程已按任务中心请求停止。")
            try:
                await asyncio.wait_for(process.wait(), timeout=0.5)
            except asyncio.TimeoutError:
                pass
        stdout, stderr = await asyncio.gather(stdout_task, stderr_task)
        code = process.returncode
        return code, stdout.decode("utf-8", "replace"), stderr.decode("utf-8", "replace")
    except BaseException:
        if process.returncode is None:
            process.kill()
            await process.wait()
        for reader in (stdout_task, stderr_task):
            if not reader.done():
                reader.cancel()
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
        raise


def _json_lines(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
        if len(rows) >= MAX_RECORDS:
            break
    return rows


def _integer(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _cwe_text(value) -> str:
    values = value if isinstance(value, list) else [value]
    return ",".join(str(item) for item in values if item not in (None, ""))[:32]


def parse_tool_output(tool_id: str, output: str) -> dict:
    result = {"assets": [], "services": [], "endpoints": [], "findings": [], "record_count": 0}
    if tool_id == "nmap":
        if "<!DOCTYPE" in output.upper():
            raise ValueError("Nmap XML 包含不允许的文档类型。")
        root = ElementTree.fromstring(output)
        for host in root.findall("host")[:MAX_RECORDS]:
            address = host.find("address")
            if address is None or not address.get("addr"):
                continue
            target = address.get("addr")
            result["assets"].append({"target": target, "kind": "host"})
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port.find("service")
                result["services"].append({
                    "target": target, "port": int(port.get("portid", "0")),
                    "protocol": port.get("protocol", "tcp"),
                    "name": service.get("name", "unknown") if service is not None else "unknown",
                    "banner": " ".join(filter(None, [service.get("product", "") if service is not None else "", service.get("version", "") if service is not None else "", service.get("extrainfo", "") if service is not None else ""])),
                })
        result["record_count"] = len(result["assets"]) + len(result["services"])
        return result

    rows = _json_lines(output)
    result["record_count"] = len(rows)
    for row in rows:
        if tool_id == "subfinder":
            target = row.get("host") or row.get("name") or row.get("input")
            if target:
                result["assets"].append({"target": target, "kind": "domain"})
        elif tool_id == "naabu":
            target = row.get("host") or row.get("ip")
            port = _integer(row.get("port"))
            if target and port and 1 <= port <= 65535:
                result["assets"].append({"target": target, "kind": "host"})
                result["services"].append({"target": target, "port": port, "protocol": row.get("protocol") or "tcp", "name": "unknown", "banner": ""})
        elif tool_id == "httpx":
            url = row.get("url") or row.get("input")
            if url:
                result["assets"].append({"target": normalize_host(url), "kind": "host"})
                result["endpoints"].append({"target": normalize_host(url), "url": url, "method": "GET", "status_code": _integer(row.get("status_code")), "content_type": row.get("content_type", ""), "fingerprint": ", ".join(row.get("tech", []) if isinstance(row.get("tech"), list) else [])[:80]})
        elif tool_id == "katana":
            request = row.get("request") if isinstance(row.get("request"), dict) else {}
            response = row.get("response") if isinstance(row.get("response"), dict) else {}
            url = request.get("endpoint") or row.get("url") or row.get("endpoint")
            if url:
                result["assets"].append({"target": normalize_host(url), "kind": "host"})
                result["endpoints"].append({"target": normalize_host(url), "url": url, "method": request.get("method") or "GET", "status_code": _integer(response.get("status_code"))})
        elif tool_id == "nuclei":
            info = row.get("info") if isinstance(row.get("info"), dict) else {}
            classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
            target = row.get("matched-at") or row.get("url") or row.get("host") or ""
            severity = str(info.get("severity") or "info").lower()
            if severity not in {"critical", "high", "medium", "low", "info"}:
                severity = "info"
            result["findings"].append({
                "title": info.get("name") or row.get("template-id") or "Nuclei 检测结果",
                "severity": severity, "target": target,
                "description": info.get("description") or "Nuclei 模板匹配，需结合现有证据人工确认。",
                "recommendation": info.get("remediation") or "核对模板结果并按对应组件安全建议修复。",
                "vuln_type": row.get("template-id", ""),
                "cwe_id": _cwe_text(classification.get("cwe-id")),
                "raw": row,
            })
    return result


def _asset(db: Session, project_id: int, target: str, kind: str) -> Asset:
    row = db.query(Asset).filter_by(project_id=project_id, target=target).first()
    if not row:
        row = Asset(project_id=project_id, target=target[:500], kind=kind[:50])
        db.add(row); db.flush()
    return row


def ingest_tool_output(db: Session, project, job, tool_id: str, output: str, stderr: str = "") -> dict:
    parsed = parse_tool_output(tool_id, output)
    asset_ids: set[int] = set(); service_ids: set[int] = set(); endpoint_ids: set[int] = set(); finding_ids: set[int] = set()
    for item in parsed["assets"]:
        if item["target"] and target_in_scope(item["target"], project.scope_text.splitlines()):
            asset_ids.add(_asset(db, project.id, item["target"], item["kind"]).id)
    for item in parsed["services"]:
        if not target_in_scope(item["target"], project.scope_text.splitlines()):
            continue
        asset = _asset(db, project.id, item["target"], "host")
        row = db.query(Service).filter_by(asset_id=asset.id, port=item["port"], protocol=item["protocol"]).first()
        if not row:
            row = Service(asset_id=asset.id, port=item["port"], protocol=item["protocol"]); db.add(row)
        row.name = item["name"][:100]; row.banner = item["banner"][:5000]; db.flush(); service_ids.add(row.id)
    for item in parsed["endpoints"]:
        if not target_in_scope(item["url"], project.scope_text.splitlines()):
            continue
        asset = _asset(db, project.id, item["target"], "host")
        method = str(item.get("method") or "GET")[:16].upper()
        row = db.query(Endpoint).filter_by(asset_id=asset.id, url=item["url"][:1000], method=method).first()
        if not row:
            row = Endpoint(asset_id=asset.id, url=item["url"][:1000], method=method, source=f"toolchain:{tool_id}"); db.add(row)
        row.status_code = item.get("status_code"); row.content_type = str(item.get("content_type") or "")[:200]; row.fingerprint = str(item.get("fingerprint") or "")[:80]; db.flush(); endpoint_ids.add(row.id)
    db.commit()
    for item in parsed["findings"]:
        if not item["target"] or not target_in_scope(item["target"], project.scope_text.splitlines()):
            continue
        finding = create_finding(db, project.id, item["title"], item["severity"], item["target"], item["description"], item["recommendation"], "nuclei_import", "nuclei_result", item["raw"], vuln_type=item["vuln_type"], cwe_id=item["cwe_id"], finding_state="candidate")
        finding_ids.add(finding.id)
    content, redaction = safe_evidence_text({"tool": tool_id, "stdout": output[:1_000_000], "stderr": stderr[:100_000], "truncated": len(output) > 1_000_000})
    evidence = Evidence(project_id=project.id, job_id=job.id, source_type="external_tool", source_id=job.id, kind=f"tool_{tool_id}_output", content=content, redaction_state=redaction)
    db.add(evidence); db.commit(); ensure_evidence_integrity(db, evidence)
    return {"tool": tool_id, "records": parsed["record_count"], "assets": len(asset_ids), "services": len(service_ids), "endpoints": len(endpoint_ids), "findings": len(finding_ids), "finding_ids": sorted(finding_ids), "evidence_id": evidence.id}


async def run_external_tool(db: Session, job, project, payload: dict) -> dict:
    tool_id = str(payload.get("tool_id") or "")
    tool = CATALOG_BY_ID.get(tool_id)
    if not tool:
        raise ValueError("未知或未启用的工具适配器。")
    db.refresh(project)
    rules = [rule.strip() for rule in project.scope_text.splitlines() if rule.strip()]
    if not target_in_scope(job.target, rules):
        raise ValueError("工具任务已停止：目标不在项目当前授权范围。")
    executable = resolve_executable(db, tool_id)
    if not executable:
        raise ValueError(f"未找到 {tool.name}，请先在工具链页面配置可执行文件路径。")
    ports = [int(value) for value in payload.get("ports", [])][:1024]
    command = build_command(tool_id, executable, job.target, ports)
    def should_stop():
        db.refresh(job, attribute_names=["status"])
        return job.status in {"cancel_requested", "pause_requested", "cancelled"}
    code, stdout, stderr = await _run_process(command, should_stop)
    if code != 0 and not stdout.strip():
        raise RuntimeError(f"{tool.name} 退出代码 {code}：{stderr.strip()[:1000] or '没有输出'}")
    result = ingest_tool_output(db, project, job, tool_id, stdout, stderr)
    result.update(exit_code=code, executable=Path(executable).name)
    return result
