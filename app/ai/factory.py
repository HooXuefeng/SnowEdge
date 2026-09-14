from .mock import MockProvider
from .openai_compatible import OpenAICompatibleProvider
from ..config import settings


def _runtime_config() -> dict:
    fallback = {"provider": settings.ai_provider, "api_base": settings.ai_api_base, "api_key": settings.ai_api_key, "model": settings.ai_model}
    try:
        from ..db import SessionLocal
        from ..services.personal_settings import ai_runtime_settings
        db = SessionLocal()
        try:
            return ai_runtime_settings(db)
        finally:
            db.close()
    except Exception:
        return fallback


def get_ai_provider():
    cfg = _runtime_config()
    if cfg.get("provider") == "openai_compatible":
        return OpenAICompatibleProvider(cfg.get("api_base", ""), cfg.get("api_key", ""), cfg.get("model", ""))
    return MockProvider()


def current_ai_provider_name() -> str:
    return str(_runtime_config().get("provider") or "mock")
