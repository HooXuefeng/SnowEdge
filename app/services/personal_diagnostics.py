from __future__ import annotations
import importlib.util, shutil, sys
from pathlib import Path
from sqlalchemy import text
from sqlalchemy.orm import Session
from ..config import settings
from ..models import JobWorker
from .personal_settings import ai_runtime_settings, get_personal_settings, resolved_backup_dir

def _check(name,ok,detail,level="ok"): return {"name":name,"ok":bool(ok),"detail":detail,"level":level if ok else "warn"}

def diagnostic_snapshot(db: Session) -> dict:
    checks=[]
    checks.append(_check("Python",sys.version_info >= (3,11),sys.version.split()[0]))
    try:
        value=db.execute(text("SELECT 1")).scalar(); checks.append(_check("数据库",value==1,f"{db.bind.dialect.name} · 连接正常"))
    except Exception as exc: checks.append(_check("数据库",False,f"{type(exc).__name__}: {exc}"))
    try:
        rev=db.execute(text("SELECT version_num FROM alembic_version LIMIT 1")).scalar(); checks.append(_check("数据库迁移",bool(rev),str(rev or "未初始化")))
    except Exception: checks.append(_check("数据库迁移",False,"alembic_version 不可用"))
    workers=db.query(JobWorker).all(); online=[w for w in workers if w.status=="online"]
    checks.append(_check("Worker",bool(online) or settings.job_immediate_accelerator,f"在线 {len(online)} · Web Accelerator {'开启' if settings.job_immediate_accelerator else '关闭'}"))
    playwright=importlib.util.find_spec("playwright") is not None; checks.append(_check("Playwright",playwright,"已安装" if playwright else "未安装"))
    prefs=get_personal_settings(db); browser_path=str(prefs.get("browser_path") or "").strip(); cands=[browser_path] if browser_path else []
    cands += [shutil.which("chromium") or "",shutil.which("chromium-browser") or "",shutil.which("google-chrome") or "",shutil.which("msedge") or ""]
    browser=next((x for x in cands if x and Path(x).exists()),""); checks.append(_check("Chromium/Chrome",bool(browser),browser or "未自动发现；Browser Workspace 可能不可用"))
    nmap_pref=str(prefs.get("nmap_path") or "").strip(); nmap=nmap_pref if nmap_pref and Path(nmap_pref).exists() else (shutil.which("nmap") or "")
    checks.append(_check("Nmap",bool(nmap),nmap or "未安装；系统会继续使用安全的 TCP connect fallback"))
    ai=ai_runtime_settings(db); ai_ok=ai["provider"]=="mock" or bool(ai["api_base"] and ai["api_key"] and ai["model"]); checks.append(_check("AI Provider",ai_ok,f"{ai['provider']} · {ai['model'] or 'mock/local'}"))
    secret_ok=settings.app_secret_key != "CHANGE-ME-IN-PRODUCTION" and len(settings.app_secret_key)>=16; checks.append(_check("APP_SECRET_KEY",secret_ok,"已配置" if secret_ok else "仍为默认/过短；Identity 与个人 API Key 不应在此状态长期使用"))
    try:
        backup_dir=resolved_backup_dir(db); backup_dir.mkdir(parents=True,exist_ok=True); test=backup_dir/".write-test"; test.write_text("ok",encoding="utf-8"); test.unlink(missing_ok=True); checks.append(_check("备份目录",True,str(backup_dir)))
    except Exception as exc: checks.append(_check("备份目录",False,f"{type(exc).__name__}: {exc}"))
    artifact_dir=Path(settings.evidence_artifact_dir).expanduser()
    try: artifact_dir.mkdir(parents=True,exist_ok=True); checks.append(_check("截图证据目录",True,str(artifact_dir.resolve())))
    except Exception as exc: checks.append(_check("截图证据目录",False,f"{type(exc).__name__}: {exc}"))
    return {"checks":checks,"ok":sum(1 for x in checks if x["ok"]),"warning":sum(1 for x in checks if not x["ok"]),"total":len(checks),"ai":{k:v for k,v in ai.items() if k != "api_key"},"preferences":prefs}
