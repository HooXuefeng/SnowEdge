from __future__ import annotations
import asyncio
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from ..services.personal_settings import runtime_tool_path

COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443]

def _nmap_scan(target: str, executable: str = "nmap") -> list[dict]:
    cmd = [executable, "-sT", "-Pn", "--top-ports", "50", "-T3", "-oX", "-", target]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    if proc.returncode not in (0, 1):
        raise RuntimeError(proc.stderr.strip() or "nmap failed")

    root = ET.fromstring(proc.stdout)
    services = []
    for port in root.findall(".//port"):
        state = port.find("state")
        if state is None or state.attrib.get("state") != "open":
            continue
        service = port.find("service")
        services.append({
            "port": int(port.attrib["portid"]),
            "protocol": port.attrib.get("protocol", "tcp"),
            "name": service.attrib.get("name", "unknown") if service is not None else "unknown",
            "banner": " ".join(
                x for x in [
                    service.attrib.get("product", "") if service is not None else "",
                    service.attrib.get("version", "") if service is not None else "",
                    service.attrib.get("extrainfo", "") if service is not None else "",
                ] if x
            ),
        })
    return services

def _connect_scan(target: str) -> list[dict]:
    services = []
    for port in COMMON_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.35)
        try:
            if s.connect_ex((target, port)) == 0:
                services.append({"port": port, "protocol": "tcp", "name": "unknown", "banner": ""})
        finally:
            s.close()
    return services

async def scan_ports(target: str) -> dict:
    try:
        preferred = runtime_tool_path("nmap")
        nmap_exec = preferred if preferred and Path(preferred).exists() else (shutil.which("nmap") or "")
        if nmap_exec:
            services = await asyncio.to_thread(_nmap_scan, target, nmap_exec)
            return {"ok": True, "engine": "nmap", "services": services}
        services = await asyncio.to_thread(_connect_scan, target)
        return {"ok": True, "engine": "tcp-connect-fallback", "services": services}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "services": []}
