from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import sqlite3
import struct
import tempfile
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from ..config import settings
from ..models import BackupRecord, Project, _utcnow
from .personal_backup import _safe_name
from .personal_settings import resolved_backup_dir
from .secret_store import encrypt_json

MAGIC = b"SNOWBK16"
FORMAT = "snowedge-full-backup/1.6"
SUPPORTED_FORMATS = {FORMAT, "ai-pentest-workspace-full-backup/1.6"}
CHUNK = 1024 * 1024


def _sha256_file(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk=f.read(CHUNK)
            if not chunk: break
            h.update(chunk)
    return h.hexdigest()


def _sqlite_path() -> Path:
    url = make_url(settings.database_url)
    if url.get_backend_name() != "sqlite" or not url.database or url.database == ":memory:":
        raise ValueError("Encrypted Full Backup 当前仅支持默认个人 SQLite 工作区。PostgreSQL 请使用数据库原生备份。")
    return Path(url.database).expanduser().resolve()


def _artifact_path(raw: str) -> Path:
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return path.resolve()


def _snapshot_sqlite(destination: Path) -> None:
    source = _sqlite_path()
    if not source.exists():
        raise FileNotFoundError(source)
    source_conn = sqlite3.connect(str(source))
    target_conn = sqlite3.connect(str(destination))
    try:
        source_conn.backup(target_conn)
        target_conn.commit()
    finally:
        target_conn.close(); source_conn.close()


def _derive(password: str, salt: bytes) -> bytes:
    if len(password) < 10:
        raise ValueError("完整备份密码至少 10 个字符。")
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode("utf-8"))


def _encrypt_file(src: Path, dst: Path, password: str, zip_sha256: str) -> dict:
    salt=os.urandom(16); nonce=os.urandom(12); key=_derive(password,salt)
    header={
        "format":FORMAT,"cipher":"AES-256-GCM","kdf":"scrypt","n":2**15,"r":8,"p":1,
        "salt":base64.b64encode(salt).decode(),"nonce":base64.b64encode(nonce).decode(),
        "zip_sha256":zip_sha256,"created_at":_utcnow().isoformat(),
    }
    header_bytes=json.dumps(header,ensure_ascii=False,separators=(",",":")).encode("utf-8")
    encryptor=Cipher(algorithms.AES(key),modes.GCM(nonce)).encryptor(); encryptor.authenticate_additional_data(header_bytes)
    with src.open("rb") as inp, dst.open("wb") as out:
        out.write(MAGIC); out.write(struct.pack(">I",len(header_bytes))); out.write(header_bytes)
        while True:
            chunk=inp.read(CHUNK)
            if not chunk: break
            out.write(encryptor.update(chunk))
        out.write(encryptor.finalize()); out.write(encryptor.tag)
    return header


def decrypt_full_backup(src: Path, dst_zip: Path, password: str) -> dict:
    total=src.stat().st_size
    if total < len(MAGIC)+4+16: raise ValueError("备份文件太短或损坏。")
    with src.open("rb") as inp:
        if inp.read(len(MAGIC)) not in {MAGIC,b"AIPWBK16"}: raise ValueError("不是兼容的 SnowEdge 完整备份。")
        header_len=struct.unpack(">I",inp.read(4))[0]
        if header_len <= 0 or header_len > 64*1024: raise ValueError("备份头无效。")
        header_bytes=inp.read(header_len); header=json.loads(header_bytes.decode("utf-8"))
        if header.get("format") not in SUPPORTED_FORMATS: raise ValueError("完整备份格式不受支持。")
        salt=base64.b64decode(header["salt"]); nonce=base64.b64decode(header["nonce"]); key=_derive(password,salt)
        cipher_start=len(MAGIC)+4+header_len; cipher_len=total-cipher_start-16
        if cipher_len < 0: raise ValueError("备份密文长度无效。")
        inp.seek(total-16); tag=inp.read(16); inp.seek(cipher_start)
        decryptor=Cipher(algorithms.AES(key),modes.GCM(nonce,tag)).decryptor(); decryptor.authenticate_additional_data(header_bytes)
        remaining=cipher_len
        with dst_zip.open("wb") as out:
            while remaining:
                chunk=inp.read(min(CHUNK,remaining)); remaining-=len(chunk)
                if not chunk: raise ValueError("备份密文被截断。")
                out.write(decryptor.update(chunk))
            try: out.write(decryptor.finalize())
            except Exception as exc: raise ValueError("密码错误或备份完整性校验失败。") from exc
    digest=_sha256_file(dst_zip)
    if digest != header.get("zip_sha256"): raise ValueError("解密成功但 ZIP SHA256 不匹配。")
    return header


def _write_zip(zip_path: Path, db_snapshot: Path) -> str:
    meta={"format":FORMAT,"version":"1.7.0","database":"workspace.sqlite3","app_secret_included":True}
    config={"app_secret_key":settings.app_secret_key,"evidence_artifact_dir":str(_artifact_path(settings.evidence_artifact_dir)),"browser_artifact_dir":str(_artifact_path(settings.browser_artifact_dir))}
    with zipfile.ZipFile(zip_path,"w",compression=zipfile.ZIP_DEFLATED,compresslevel=6) as zf:
        zf.write(db_snapshot,"workspace.sqlite3")
        zf.writestr("metadata.json",json.dumps(meta,ensure_ascii=False,indent=2))
        zf.writestr("config.json",json.dumps(config,ensure_ascii=False))
        for prefix, raw in (("evidence_artifacts",settings.evidence_artifact_dir),("browser_artifacts",settings.browser_artifact_dir)):
            base=_artifact_path(raw)
            if not base.exists(): continue
            for file in base.rglob("*"):
                if file.is_file():
                    zf.write(file,Path(prefix)/file.relative_to(base))
    return _sha256_file(zip_path)


def create_full_workspace_backup(db: Session, project: Project, password: str) -> BackupRecord:
    directory=resolved_backup_dir(db); directory.mkdir(parents=True,exist_ok=True)
    stamp=_utcnow().strftime("%Y%m%d_%H%M%S_%f")
    final=directory/f"FULL_{_safe_name(project.name)}_{project.id}_{stamp}.snowedgebackup"
    with tempfile.TemporaryDirectory(prefix="snowedge-v16-") as td:
        td=Path(td); snap=td/"workspace.sqlite3"; archive=td/"workspace.zip"
        _snapshot_sqlite(snap); zip_sha=_write_zip(archive,snap); header=_encrypt_file(archive,final,password,zip_sha)
    payload_sha=_sha256_file(final)
    row=BackupRecord(project_id=project.id,backup_type="encrypted_full",file_path=str(final),file_sha256=payload_sha,
        size_bytes=final.stat().st_size,status="done",detail_json=json.dumps({"format":FORMAT,"cipher":"AES-256-GCM","scope":"workspace"},ensure_ascii=False))
    db.add(row);db.commit();db.refresh(row);return row


def validate_full_backup(path: Path, password: str) -> dict:
    with tempfile.TemporaryDirectory(prefix="snowedge-validate-") as td:
        out=Path(td)/"restore.zip"; header=decrypt_full_backup(path,out,password)
        with zipfile.ZipFile(out) as zf:
            names=set(zf.namelist())
            if not {"workspace.sqlite3","metadata.json","config.json"} <= names: raise ValueError("完整备份缺少数据库或配置。")
            meta=json.loads(zf.read("metadata.json"))
        return {"header":header,"metadata":meta,"entries":len(names)}


def stage_full_restore(uploaded_path: Path, password: str) -> dict:
    info=validate_full_backup(uploaded_path,password)
    pending=_artifact_path(settings.restore_pending_dir); pending.mkdir(parents=True,exist_ok=True)
    target=pending/"workspace.snowedgebackup"; shutil.copy2(uploaded_path,target)
    payload={"format":FORMAT,"backup_file":"workspace.snowedgebackup","password_encrypted":encrypt_json({"password":password}),"staged_at":_utcnow().isoformat()}
    (pending/"pending.json").write_text(json.dumps(payload,ensure_ascii=False,indent=2),encoding="utf-8")
    return {"pending_dir":str(pending),"backup_file":str(target),**info}
