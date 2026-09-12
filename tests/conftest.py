"""Never run application tests against the user's workspace database."""
import os
import tempfile
from pathlib import Path

import pytest

_sandbox = tempfile.TemporaryDirectory(prefix="aipw-tests-", ignore_cleanup_errors=True)
_root = Path(_sandbox.name)
os.environ.update({
    "DATABASE_URL": f"sqlite:///{(_root / 'tests.db').as_posix()}",
    "APP_SECRET_KEY": "isolated-test-key-not-for-user-data",
    "AI_PROVIDER": "mock", "AI_API_KEY": "", "AI_API_BASE": "", "AI_MODEL": "",
    "BROWSER_ARTIFACT_DIR": str(_root / "browser"),
    "EVIDENCE_ARTIFACT_DIR": str(_root / "evidence"),
    "RESTORE_PENDING_DIR": str(_root / "restore"),
    "JOB_EMBEDDED_WORKERS": "0",
    "LOCAL_ALLOWED_HOSTS": "127.0.0.1,localhost,::1,testserver",
})


def pytest_sessionfinish(session, exitstatus):
    from app.db import engine
    engine.dispose()


@pytest.fixture(autouse=True)
def isolate_background_backups(monkeypatch):
    import app.main
    # Explicit backup service tests still execute; page tests cannot start disk backups.
    monkeypatch.setattr(app.main, "run_due_backups_once", lambda: {"created": [], "errors": []})
    from app.services import personal_settings
    monkeypatch.setitem(personal_settings.DEFAULTS, "backup_dir", str(_root / "backups"))
