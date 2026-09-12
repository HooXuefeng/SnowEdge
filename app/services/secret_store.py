from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from ..config import settings

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-access-token",
}


def _fernet() -> Fernet:
    digest = hashlib.sha256(settings.app_secret_key.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_json(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False).encode("utf-8")
    return _fernet().encrypt(payload).decode("ascii")


def decrypt_json(token: str, default=None):
    if not token:
        return {} if default is None else default
    try:
        raw = _fernet().decrypt(token.encode("ascii"))
        return json.loads(raw.decode("utf-8"))
    except (InvalidToken, ValueError, json.JSONDecodeError):
        return {} if default is None else default


def split_sensitive_headers(headers: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    public, secret = {}, {}
    for key, value in headers.items():
        if key.lower().strip() in SENSITIVE_HEADER_NAMES:
            secret[key] = value
        else:
            public[key] = value
    return public, secret


def mask_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 6:
        return "••••••"
    return f"{value[:2]}••••{value[-2:]}"


def masked_header_summary(encrypted: str) -> list[dict[str, str]]:
    data = decrypt_json(encrypted, {})
    if not isinstance(data, dict):
        return []
    return [{"name": str(k), "value": mask_secret(str(v))} for k, v in data.items()]


def masked_cookie_summary(encrypted: str) -> list[dict[str, str]]:
    data = decrypt_json(encrypted, {})
    if not isinstance(data, dict):
        return []
    return [{"name": str(k), "value": mask_secret(str(v))} for k, v in data.items()]
