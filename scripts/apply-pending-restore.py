from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import json,os,shutil,sqlite3,tempfile,zipfile
from sqlalchemy.engine import make_url
from app.config import settings
from app.services.full_backup import decrypt_full_backup
from app.services.secret_store import decrypt_json


def safe_extract(zf:zipfile.ZipFile,dst:Path):
    for info in zf.infolist():
        p=Path(info.filename)
        if p.is_absolute() or ".." in p.parts:raise RuntimeError("Unsafe archive path")
        if info.filename not in {"workspace.sqlite3","metadata.json","config.json"} and not (p.parts and p.parts[0] in {"evidence_artifacts","browser_artifacts"}):continue
        zf.extract(info,dst)

def set_env_secret(secret:str):
    env=Path.cwd()/".env"; lines=env.read_text(encoding="utf-8").splitlines() if env.exists() else []
    out=[];found=False
    for line in lines:
        if line.startswith("APP_SECRET_KEY="):out.append("APP_SECRET_KEY="+secret);found=True
        else:out.append(line)
    if not found:out.append("APP_SECRET_KEY="+secret)
    env.write_text("\n".join(out)+"\n",encoding="utf-8")

def main():
    pending=Path(settings.restore_pending_dir).expanduser(); pending=(pending if pending.is_absolute() else Path.cwd()/pending).resolve()
    meta_file=pending/"pending.json"
    if not meta_file.exists():print("No pending restore.");return 0
    meta=json.loads(meta_file.read_text(encoding="utf-8")); pw=decrypt_json(meta.get("password_encrypted",""),{}).get("password","")
    if not pw:raise RuntimeError("Pending restore password cannot be decrypted with current APP_SECRET_KEY.")
    backup=pending/meta.get("backup_file","workspace.snowedgebackup")
    with tempfile.TemporaryDirectory(prefix="snowedge-restore-") as td:
        td=Path(td); archive=td/"workspace.zip"; extract=td/"extract";extract.mkdir()
        decrypt_full_backup(backup,archive,pw)
        with zipfile.ZipFile(archive) as zf:safe_extract(zf,extract)
        cfg=json.loads((extract/"config.json").read_text(encoding="utf-8")); restored_secret=str(cfg.get("app_secret_key") or "")
        if len(restored_secret)<16:raise RuntimeError("Backup APP_SECRET_KEY is missing/invalid.")
        url=make_url(settings.database_url)
        if url.get_backend_name()!="sqlite" or not url.database:raise RuntimeError("Pending full restore only supports SQLite.")
        db_path=Path(url.database).expanduser().resolve(); db_path.parent.mkdir(parents=True,exist_ok=True)
        if db_path.exists():shutil.copy2(db_path,db_path.with_suffix(db_path.suffix+".pre_restore"))
        shutil.copy2(extract/"workspace.sqlite3",db_path)
        current_evidence=Path(settings.evidence_artifact_dir).expanduser(); current_evidence=(current_evidence if current_evidence.is_absolute() else Path.cwd()/current_evidence).resolve()
        current_browser=Path(settings.browser_artifact_dir).expanduser(); current_browser=(current_browser if current_browser.is_absolute() else Path.cwd()/current_browser).resolve()
        for name,dst in (("evidence_artifacts",current_evidence),("browser_artifacts",current_browser)):
            src=extract/name
            if dst.exists():shutil.rmtree(dst,ignore_errors=True)
            if src.exists():shutil.copytree(src,dst)
        # Rebase absolute artifact paths when a full backup is restored into another installation directory.
        old_evidence=str(cfg.get("evidence_artifact_dir") or "")
        old_browser=str(cfg.get("browser_artifact_dir") or "")
        con=sqlite3.connect(str(db_path))
        try:
            tables={r[0] for r in con.execute("select name from sqlite_master where type='table'")}
            if "evidence_attachments" in tables and old_evidence:
                rows=con.execute("select id,file_path from evidence_attachments").fetchall()
                for rid,path in rows:
                    if path and str(path).startswith(old_evidence):
                        new=str(current_evidence/Path(str(path)).relative_to(old_evidence));con.execute("update evidence_attachments set file_path=? where id=?",(new,rid))
            if "browser_artifacts" in tables and old_browser:
                rows=con.execute("select id,file_path from browser_artifacts where file_path is not null and file_path != ''").fetchall()
                for rid,path in rows:
                    if path and str(path).startswith(old_browser):
                        new=str(current_browser/Path(str(path)).relative_to(old_browser));con.execute("update browser_artifacts set file_path=? where id=?",(new,rid))
            if "backup_records" in tables:
                con.execute("update backup_records set status='historical_missing' where status='done'")
            con.commit()
        finally:con.close()
        set_env_secret(restored_secret)
    shutil.rmtree(pending,ignore_errors=True);print("Pending V1.6 full restore applied.");return 0

if __name__=="__main__":raise SystemExit(main())
