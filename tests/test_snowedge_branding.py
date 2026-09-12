import hashlib
import io
import json
import zipfile
import pytest
from pathlib import Path
from app.config import default_database_url


def test_new_database_name_and_existing_workspace_compatibility(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert default_database_url()=='sqlite:///./snowedge.db'
    (tmp_path/'ai_pentest.db').write_bytes(b'legacy fixture')
    assert default_database_url()=='sqlite:///./ai_pentest.db'
    assert (tmp_path/'ai_pentest.db').read_bytes()==b'legacy fixture'


def test_legacy_encrypted_backup_remains_readable(tmp_path,monkeypatch):
    from app.services import full_backup as service
    original=tmp_path/'source.zip';original.write_bytes(b'isolated legacy backup fixture')
    encrypted=tmp_path/'old.aipwbak';restored=tmp_path/'restored.zip'
    with monkeypatch.context() as patch:
        patch.setattr(service,'MAGIC',b'AIPWBK16')
        patch.setattr(service,'FORMAT','ai-pentest-workspace-full-backup/1.6')
        service._encrypt_file(original,encrypted,'fixture-password-123',hashlib.sha256(original.read_bytes()).hexdigest())
    service.decrypt_full_backup(encrypted,restored,'fixture-password-123')
    assert restored.read_bytes()==original.read_bytes()
    assert service.MAGIC==b'SNOWBK16' and service.FORMAT.startswith('snowedge-')


def test_legacy_portable_schema_is_accepted():
    from app.services.project_portability import parse_project_zip,PORTABLE_SCHEMA
    archive=io.BytesIO()
    with zipfile.ZipFile(archive,'w') as z:
        z.writestr('manifest.json',json.dumps({'schema':'ai-pentest-workspace-project/1.6.2','project':{'name':'old'}}))
    assert parse_project_zip(archive.getvalue())['schema']=='ai-pentest-workspace-project/1.6.2'
    assert PORTABLE_SCHEMA=='snowedge-project/1.6.2'


def test_product_templates_and_burp_package_use_snowedge():
    root=Path(__file__).resolve().parents[1]
    for file in (root/'app/templates').glob('*.html'):
        text=file.read_text(encoding='utf-8').lower()
        assert 'ai pentest workspace' not in text and 'ai_pentest' not in text,file


def test_built_burp_package_uses_snowedge():
    root=Path(__file__).resolve().parents[1]
    package=root/'integrations/burp-extension/dist/SnowEdge-Burp-1.0.0.jar'
    if not package.is_file():
        pytest.skip('Build the Burp extension to verify the packaged binary')
    with zipfile.ZipFile(package) as archive:
        content=archive.read('burp/BurpExtender.class')
        assert b'SnowEdge' in content and b'X-SnowEdge-Token' in content
        assert b'AI Pentest Workspace' not in content
