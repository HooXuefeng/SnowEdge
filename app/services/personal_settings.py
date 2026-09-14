from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.orm import Session

from ..config import settings
from ..models import AppPreference
from .secret_store import decrypt_json, encrypt_json

KEY = "personal_config"

DEFAULTS = {
    "setup_completed": False,
    "default_template": "web-api",
    "backup_enabled": True,
    "backup_interval_hours": 24,
    "backup_retention": 7,
    "backup_dir": "./backups",
    "browser_path": "",
    "nmap_path": "",
    "ai_provider": "",
    "ai_api_base": "",
    "ai_model": "",
    "ai_api_key_revoked": False,
}


def get_personal_settings(db: Session) -> dict:
    row = db.query(AppPreference).filter(AppPreference.key == KEY).first()
    data = dict(DEFAULTS)
    if row:
        try:
            stored = json.loads(row.value_json or "{}")
            if isinstance(stored, dict):
                data.update(stored)
        except Exception:
            pass
        secret = decrypt_json(row.secret_encrypted, {})
        data["ai_api_key_configured"] = bool((secret.get("ai_api_key") if isinstance(secret, dict) else '') or (settings.ai_api_key if not data.get('ai_api_key_revoked') else ''))
        data["burp_ingest_token_configured"] = bool(secret.get("burp_ingest_token")) if isinstance(secret, dict) else False
    else:
        data["ai_api_key_configured"] = bool(settings.ai_api_key)
        data["burp_ingest_token_configured"] = False
    return data


def save_personal_settings(
    db: Session,
    values: dict,
    *,
    ai_api_key: str | None = None,
    burp_ingest_token: str | None = None,
) -> dict:
    row = db.query(AppPreference).filter(AppPreference.key == KEY).first()
    if not row:
        row = AppPreference(key=KEY)
        db.add(row)
        db.flush()

    current = dict(DEFAULTS)
    try:
        existing = json.loads(row.value_json or "{}")
        if isinstance(existing, dict):
            current.update(existing)
    except Exception:
        pass
    current.update({k: v for k, v in values.items() if k in DEFAULTS})
    row.value_json = json.dumps(current, ensure_ascii=False)

    if ai_api_key is not None or burp_ingest_token is not None:
        old_secret = decrypt_json(row.secret_encrypted, {})
        if not isinstance(old_secret, dict):
            old_secret = {}
        if ai_api_key is not None:
            if ai_api_key.strip():
                old_secret["ai_api_key"] = ai_api_key.strip()
                current['ai_api_key_revoked']=False
            elif ai_api_key == "":
                old_secret.pop("ai_api_key", None)
                current['ai_api_key_revoked']=True
        if burp_ingest_token is not None:
            if burp_ingest_token.strip():
                old_secret["burp_ingest_token"] = burp_ingest_token.strip()
            elif burp_ingest_token == "":
                old_secret.pop("burp_ingest_token", None)
        row.secret_encrypted = encrypt_json(old_secret)
        row.value_json = json.dumps(current,ensure_ascii=False)

    from ..models import _utcnow
    row.updated_at = _utcnow()
    db.commit()
    return get_personal_settings(db)

def ai_runtime_settings(db: Session) -> dict:
    personal = get_personal_settings(db)
    row = db.query(AppPreference).filter(AppPreference.key == KEY).first()
    secret = decrypt_json(row.secret_encrypted, {}) if row else {}
    return {
        "provider": personal.get("ai_provider") or settings.ai_provider,
        "api_base": personal.get("ai_api_base") or settings.ai_api_base,
        "model": personal.get("ai_model") or settings.ai_model,
        "api_key": (secret.get("ai_api_key") if isinstance(secret, dict) else "") or (settings.ai_api_key if not personal.get('ai_api_key_revoked') else ''),
    }


def resolved_backup_dir(db: Session) -> Path:
    data = get_personal_settings(db)
    raw = str(data.get("backup_dir") or "./backups").strip()
    path = Path(raw).expanduser()
    if not path.is_absolute(): path = Path.cwd() / path
    return path.resolve()


def runtime_tool_path(name: str) -> str:
    try:
        from ..db import SessionLocal
        db = SessionLocal()
        try:
            prefs = get_personal_settings(db)
            if name == "browser": return str(prefs.get("browser_path") or "").strip()
            if name == "nmap": return str(prefs.get("nmap_path") or "").strip()
            return ""
        finally:
            db.close()
    except Exception:
        return ""


def burp_ingest_token(db: Session) -> str:
    row = db.query(AppPreference).filter(AppPreference.key == KEY).first()
    if not row:
        return ""
    secret = decrypt_json(row.secret_encrypted, {})
    if not isinstance(secret, dict):
        return ""
    return str(secret.get("burp_ingest_token") or "")
