import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.db import Base, SessionLocal, engine
from app.main import app
from app.models import BrowserSession, Identity, PersistentJob, Project, SecretVaultItem, StoredRequest, WorkspaceDraft
from app.services.full_backup import create_full_workspace_backup, decrypt_full_backup, stage_full_restore, validate_full_backup
from app.services.global_search import global_search
from app.services.personal_settings import save_personal_settings
from app.services.recovery import recovery_snapshot, resume_safe_recovery
from app.services.secret_vault import create_vault_item, identity_material, item_summary
from app.services.workspace_drafts import delete_draft, load_draft, save_draft


def test_v16_vault_encrypts_http_identity_and_identity_uses_it():
    Base.metadata.create_all(bind=engine)
    db=SessionLocal()
    try:
        p=Project(name='V16 Vault',scope_text='api.example.test');db.add(p);db.commit();db.refresh(p)
        item=create_vault_item(db,label='User A Vault',secret_type='http_identity',project_id=p.id,
            value={'headers':{'Authorization':'Bearer VAULT-HEADER-SECRET'},'cookies':{'sid':'VAULT-COOKIE-SECRET'}})
        assert 'VAULT-HEADER-SECRET' not in item.value_encrypted
        assert 'VAULT-COOKIE-SECRET' not in item.value_encrypted
        ident=Identity(project_id=p.id,name='User A',role='User',vault_item_id=item.id)
        db.add(ident);db.commit();db.refresh(ident)
        headers,cookies=identity_material(db,ident)
        assert headers['Authorization']=='Bearer VAULT-HEADER-SECRET'
        assert cookies['sid']=='VAULT-COOKIE-SECRET'
        db.refresh(item);assert item.last_used_at is not None
        summary=item_summary(item)
        assert all('VAULT-HEADER-SECRET' not in x for x in summary['fields'])
    finally: db.close()


def test_v16_request_draft_is_encrypted_at_rest():
    Base.metadata.create_all(bind=engine)
    db=SessionLocal()
    try:
        p=Project(name='V16 Draft',scope_text='api.example.test');db.add(p);db.commit();db.refresh(p)
        r=StoredRequest(project_id=p.id,name='Draft',method='GET',url='https://api.example.test/',headers_json='{}',secret_headers_encrypted='',body='',source='manual',policy_class='READ_ONLY')
        db.add(r);db.commit();db.refresh(r)
        content={'name':'Draft','method':'GET','url':'https://api.example.test/?ticket=DRAFT-QUERY-SECRET','headers_text':'Authorization: Bearer DRAFT-AUTH-SECRET','body':'{"token":"DRAFT-BODY-SECRET"}','change_note':'qa'}
        row=save_draft(db,p.id,'stored_request',r.id,content)
        assert 'DRAFT-AUTH-SECRET' not in row.content_json
        assert 'DRAFT-BODY-SECRET' not in row.content_json
        loaded=load_draft(db,p.id,'stored_request',r.id)
        assert loaded['content']['headers_text'].endswith('DRAFT-AUTH-SECRET')
        assert delete_draft(db,p.id,'stored_request',r.id) is True
        assert load_draft(db,p.id,'stored_request',r.id) is None
    finally: db.close()


def test_v16_global_search_redacts_secret_query_values():
    Base.metadata.create_all(bind=engine)
    db=SessionLocal()
    try:
        p=Project(name='V16 Search',scope_text='api.example.test');db.add(p);db.commit();db.refresh(p)
        r=StoredRequest(project_id=p.id,name='Order Lookup',method='GET',url='https://api.example.test/orders?ticket=SEARCH-TICKET-SECRET',headers_json='{}',secret_headers_encrypted='',body='',source='manual',policy_class='READ_ONLY')
        db.add(r);db.commit()
        rows=global_search(db,'Order',p.id)
        assert rows
        serialized=json.dumps(rows,ensure_ascii=False)
        assert 'SEARCH-TICKET-SECRET' not in serialized
        assert '••••' in serialized
    finally: db.close()


def test_v16_recovery_resume_only_safe_existing_jobs_and_lists_drafts():
    Base.metadata.create_all(bind=engine)
    db=SessionLocal()
    try:
        p=Project(name='V16 Recovery',scope_text='api.example.test');db.add(p);db.commit();db.refresh(p)
        j=PersistentJob(project_id=p.id,kind='endpoint_sync',target='project:endpoints',payload_json='{}',scope_snapshot_json='[]',scope_hash='x'*64,status='retry_wait',priority=10,max_attempts=1,timeout_seconds=30)
        db.add(j);db.commit();db.refresh(j)
        save_draft(db,p.id,'stored_request',999,{'name':'recovery draft'})
        snap=recovery_snapshot(db)
        assert any(x.id==j.id for x in snap['jobs'])
        assert len(snap['drafts'])>=1
        result=resume_safe_recovery(db)
        db.refresh(j)
        assert j.status=='queued'
        assert j.id in result['resumed_jobs']
    finally: db.close()


def test_v16_encrypted_full_backup_wrong_password_rejected_and_staging_password_not_plaintext(tmp_path, monkeypatch):
    Base.metadata.create_all(bind=engine)
    source_db=tmp_path/'source.db'
    con=sqlite3.connect(source_db);con.execute('create table qa(id integer primary key, value text)');con.execute('insert into qa(value) values (?)',('BACKUP-DB-SECRET',));con.commit();con.close()
    evidence=tmp_path/'evidence';evidence.mkdir();(evidence/'proof.txt').write_text('FULL-EVIDENCE-SECRET',encoding='utf-8')
    browser=tmp_path/'browser';browser.mkdir();(browser/'dom.txt').write_text('BROWSER-ARTIFACT-QA',encoding='utf-8')
    backups=tmp_path/'backups';pending=tmp_path/'pending'
    monkeypatch.setattr('app.services.full_backup.settings.database_url',f'sqlite:///{source_db}')
    monkeypatch.setattr('app.services.full_backup.settings.evidence_artifact_dir',str(evidence))
    monkeypatch.setattr('app.services.full_backup.settings.browser_artifact_dir',str(browser))
    monkeypatch.setattr('app.services.full_backup.settings.restore_pending_dir',str(pending))
    monkeypatch.setattr('app.services.personal_settings.DEFAULTS', {**__import__('app.services.personal_settings',fromlist=['DEFAULTS']).DEFAULTS,'backup_dir':str(backups)})
    db=SessionLocal()
    try:
        save_personal_settings(db,{'backup_dir':str(backups),'backup_enabled':False,'ai_provider':'mock'})
        p=Project(name='V16 Full Backup',scope_text='example.test');db.add(p);db.commit();db.refresh(p)
        rec=create_full_workspace_backup(db,p,'correct-horse-battery-staple')
        backup=Path(rec.file_path);assert backup.exists() and backup.suffix=='.snowedgebackup'
        raw=backup.read_bytes()
        assert b'BACKUP-DB-SECRET' not in raw and b'FULL-EVIDENCE-SECRET' not in raw
        with pytest.raises(ValueError): validate_full_backup(backup,'wrong-password-123')
        info=validate_full_backup(backup,'correct-horse-battery-staple')
        assert info['metadata']['format']=='snowedge-full-backup/1.6'
        staged=stage_full_restore(backup,'correct-horse-battery-staple')
        pending_text=(pending/'pending.json').read_text(encoding='utf-8')
        assert 'correct-horse-battery-staple' not in pending_text
        assert (pending/'workspace.snowedgebackup').exists()
    finally: db.close()


def test_v16_ui_routes_and_ctrl_k_markers():
    Base.metadata.create_all(bind=engine)
    db=SessionLocal()
    try:
        p=Project(name='V16 UI',scope_text='example.test');db.add(p);db.commit();db.refresh(p);pid=p.id
    finally: db.close()
    with TestClient(app) as c:
        for url,marker in [('/vault','Secret Vault'),('/recovery','恢复中心'),(f'/projects/{pid}/backups','Encrypted Full Backup'),('/', 'Ctrl K')]:
            r=c.get(url);assert r.status_code==200,(url,r.status_code,r.text[:300]);assert marker in r.text,(url,marker)


def test_v16_launcher_is_real_windows_gui_exe_and_supervisor_present():
    root=Path(__file__).resolve().parents[1]
    assert (root/'scripts/personal-supervisor.py').exists()
    assert 'restore_pending' in (root/'scripts/apply-pending-restore.py').read_text(encoding='utf-8')


def test_built_desktop_launcher_binary():
    root=Path(__file__).resolve().parents[1]
    exe=root/'SnowEdge.exe'
    if not exe.is_file():
        pytest.skip('Build the Windows desktop launcher to verify the executable')
    assert exe.exists() and exe.stat().st_size>10_000
    assert exe.read_bytes()[:2]==b'MZ'
    assert (root/'scripts/personal-supervisor.py').exists()
    assert 'restore_pending' in (root/'scripts/apply-pending-restore.py').read_text(encoding='utf-8')


def test_v16_v15_database_migrates_to_v16_head(tmp_path):
    db_path=tmp_path/'v15.db'
    sql=(
        "CREATE TABLE projects (id INTEGER PRIMARY KEY, name VARCHAR(200), scope_text TEXT, client_name VARCHAR(240), environment VARCHAR(80), engagement_type VARCHAR(80), status VARCHAR(60), start_date VARCHAR(32), end_date VARCHAR(32), authorization_note TEXT, testers_json TEXT, template_slug VARCHAR(80), created_at DATETIME);"
        "CREATE TABLE identities (id INTEGER PRIMARY KEY, project_id INTEGER, name VARCHAR(120), role VARCHAR(80), headers_encrypted TEXT, cookies_encrypted TEXT, notes TEXT, created_at DATETIME);"
        "CREATE TABLE backup_records (id INTEGER PRIMARY KEY, project_id INTEGER, backup_type VARCHAR(60), file_path VARCHAR(2000), file_sha256 VARCHAR(64), size_bytes INTEGER, status VARCHAR(60), created_at DATETIME);"
        "CREATE TABLE evidence_attachments (id INTEGER PRIMARY KEY, project_id INTEGER, finding_id INTEGER, evidence_id INTEGER, attachment_type VARCHAR(60), label VARCHAR(300), file_path VARCHAR(2000), mime_type VARCHAR(100), file_sha256 VARCHAR(64), size_bytes INTEGER, sort_order INTEGER, annotation_json TEXT, created_at DATETIME);"
        "CREATE TABLE stored_request_revisions (id INTEGER PRIMARY KEY, project_id INTEGER, stored_request_id INTEGER, revision_no INTEGER, name VARCHAR(240), method VARCHAR(16), url VARCHAR(2000), headers_json TEXT, secret_headers_encrypted TEXT, body TEXT, policy_class VARCHAR(50), change_note VARCHAR(500), created_at DATETIME);"
        "CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL);INSERT INTO alembic_version(version_num) VALUES('v1_5_workflow2');"
    )
    con=sqlite3.connect(db_path);con.executescript(sql);con.commit();con.close()
    env=os.environ.copy();env['DATABASE_URL']=f'sqlite:///{db_path}'
    code=("from sqlalchemy import inspect\nfrom app.db import engine\nfrom app.schema_migrations import ensure_schema_current\nensure_schema_current()\ni=inspect(engine)\n"
          "assert {'secret_vault_items','workspace_drafts','recovery_events'} <= set(i.get_table_names())\n"
          "assert 'vault_item_id' in {c['name'] for c in i.get_columns('identities')}\n"
          "assert 'detail_json' in {c['name'] for c in i.get_columns('backup_records')}\n"
          "with engine.connect() as c: rev=c.exec_driver_sql('SELECT version_num FROM alembic_version').scalar()\nassert rev=='v1_8_toolchain_runs'\nprint(rev)\n")
    r=subprocess.run([sys.executable,'-c',code],cwd=str(Path(__file__).resolve().parents[1]),env=env,capture_output=True,text=True,timeout=120)
    assert r.returncode==0,r.stdout+r.stderr
    assert 'v1_8_toolchain_runs' in r.stdout
