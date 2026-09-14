from __future__ import annotations
import asyncio
import socket
import ssl
from datetime import datetime, timezone

def _tls_sync(host: str, port: int, timeout: float) -> dict:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            cert = s.getpeercert()
            cipher = s.cipher()
            return {
                "ok": True,
                "protocol": s.version(),
                "cipher": cipher[0] if cipher else None,
                "cipher_bits": cipher[2] if cipher else None,
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "notBefore": cert.get("notBefore"),
                "notAfter": cert.get("notAfter"),
                "subjectAltName": cert.get("subjectAltName"),
            }

async def analyze_tls(host: str, port: int = 443, timeout: float = 5.0) -> dict:
    try:
        return await asyncio.to_thread(_tls_sync, host, port, timeout)
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
