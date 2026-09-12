from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, quote_plus, urlparse, urlunparse

SENSITIVE_KEYS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "api-key", "apikey", "x-auth-token", "x-access-token",
    "password", "passwd", "pwd", "secret", "credential",
    "token", "access_token", "id_token", "refresh_token", "jwt",
    "ticket", "code", "session", "sessionid", "sid", "key",
}

HEADER_RE = re.compile(
    r"(?im)^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|apikey|x-auth-token|x-access-token)\s*:\s*.*$"
)
ESCAPED_HEADER_RE = re.compile(
    r"(?i)(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|apikey|x-auth-token|x-access-token)\s*:\s*.*?(?=\\n|$)"
)
JSON_SECRET_RE = re.compile(
    r'(?i)("(?:password|passwd|pwd|secret|credential|token|access_token|id_token|refresh_token|jwt|ticket|session|sessionid|sid|api_key|apikey)"\s*:\s*)"[^"]*"'
)
QUERY_RE = re.compile(
    r"(?i)([?&](?:token|access_token|id_token|refresh_token|jwt|ticket|code|session|sessionid|sid|api_key|apikey|key|secret|credential)=)([^&#\s]+)"
)



def redact_url(url: str) -> str:
    try:
        parsed=urlparse(str(url or ""))
        if not parsed.scheme and not parsed.netloc:return str(url or "")
        pairs=[]
        for key,value in parse_qsl(parsed.query,keep_blank_values=True):
            safe_value="••••" if key.lower() in SENSITIVE_KEYS else value
            pairs.append(f"{quote_plus(key)}={safe_value if safe_value == '••••' else quote_plus(safe_value)}")
        return urlunparse(parsed._replace(query="&".join(pairs)))
    except Exception:return str(url or "")

def redact_text(text: str) -> tuple[str, bool]:
    original = text or ""
    value = HEADER_RE.sub(lambda m: f"{m.group(1)}: ••••", original)
    value = ESCAPED_HEADER_RE.sub(lambda m: f"{m.group(1)}: ••••", value)
    value = JSON_SECRET_RE.sub(r'\1"••••"', value)
    value = QUERY_RE.sub(lambda m: m.group(1) + "••••", value)
    return value, value != original


def redact_object(value):
    changed = False

    def walk(obj, key_hint: str = ""):
        nonlocal changed
        if isinstance(obj, dict):
            result = {}
            for key, child in obj.items():
                key_text = str(key)
                if key_text.lower() in SENSITIVE_KEYS:
                    result[key] = "••••"
                    if child != "••••":
                        changed = True
                else:
                    result[key] = walk(child, key_text)
            return result
        if isinstance(obj, list):
            return [walk(child, key_hint) for child in obj]
        if isinstance(obj, str):
            redacted, text_changed = redact_text(obj)
            changed = changed or text_changed
            return redacted
        return obj

    return walk(value), changed


def safe_evidence_text(value) -> tuple[str, str]:
    """Return a display/persistence-safe Evidence representation.

    This is intentionally lossy for common credentials. Evidence that requires
    exact raw secret material should be kept in a separately authorized secret
    store rather than in the normal Evidence table.
    """
    if isinstance(value, (dict, list)):
        redacted, changed = redact_object(value)
        return json.dumps(redacted, ensure_ascii=False, default=str), ("redacted" if changed else "clean")

    if isinstance(value, str):
        redacted, changed = redact_text(value)
        return redacted, ("redacted" if changed else "clean")

    text = str(value)
    redacted, changed = redact_text(text)
    return redacted, ("redacted" if changed else "clean")
