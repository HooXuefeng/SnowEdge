"""Allowlisted release build. Never copies or deletes workspace state."""
import argparse
import hashlib
import json
import shutil
import zipfile
from datetime import datetime
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
VERSION='1.7.2'
TREES={'app':{'.py','.html','.css','.js','.svg','.png','.ico'},'migrations':{'.py','.mako'},'skills/builtin':{'.md','.json','.yaml','.yml'}}
FILES=['run.py','worker.py','alembic.ini','scripts/desktop-server.py','scripts/db-upgrade.py','scripts/apply-pending-restore.py','tools/setup-runtime.ps1',
       'Microsoft.Web.WebView2.Core.dll','Microsoft.Web.WebView2.WinForms.dll','WebView2Loader.dll','SnowEdge.exe.config',
       'docs/DESKTOP.md','docs/SCAN_CENTER.md','docs/V1.7.0.md','docs/V1.7.1.md','docs/V1.7.2.md','integrations/burp-extension/dist/SnowEdge-Burp-1.0.0.jar','integrations/burp-extension/README.md']
FORBIDDEN={'.env','.venv','.runtime','backups','qa','tests','__pycache__','.pytest_cache','.git','node_modules','browser_artifacts','evidence_artifacts','restore_pending'}

def release_files(root):
    for name in FILES:
        path=root/name
        if not path.is_file():raise RuntimeError(f'Missing release input: {name}')
        yield path, name
    for directory,suffixes in TREES.items():
        for path in sorted((root/directory).rglob('*')):
            if path.is_file() and path.suffix.lower() in suffixes and not set(path.relative_to(root).parts)&FORBIDDEN:
                if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):raise RuntimeError('Release input must not be a symlink')
                yield path,path.relative_to(root).as_posix()
    exe=root/'SnowEdge.exe'
    if not exe.is_file():raise RuntimeError('Build the desktop launcher first')
    yield exe,'SnowEdge.exe'

def build(output):
    output=output.resolve();output.mkdir(parents=True,exist_ok=True)
    stamp=datetime.now().strftime('%Y%m%d-%H%M%S')
    stage=output/f'SnowEdge-{VERSION}-{stamp}'
    stage.mkdir()  # Refuse reuse: stale user files can never enter this build.
    manifest=[]
    for source,relative in release_files(ROOT):
        destination=stage/relative;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,destination)
        manifest.append({'path':relative,'sha256':hashlib.sha256(destination.read_bytes()).hexdigest(),'bytes':destination.stat().st_size})
    requirements=[line for line in (ROOT/'requirements.txt').read_text().splitlines() if not line.lower().startswith('pytest')]
    (stage/'requirements.txt').write_text('\n'.join(requirements)+'\n',encoding='utf-8')
    (stage/'README.txt').write_text('雪锋 SnowEdge V1.7.2\n\n双击 SnowEdge.exe。首次启动需要 Python 3.11+、网络和 WebView2；程序自动在本机创建运行环境。\n本包不包含 .env、预制虚拟环境、数据库、备份、日志或历史项目。首次运行自动生成独立应用密钥。\n\n已有用户请先保留整个原工作目录及备份，勿删除原 .env 或 .runtime/app-secret，否则已有加密数据可能无法解密。\n功能边界与配置见 docs/SCAN_CENTER.md。\n',encoding='utf-8')
    for name in ('requirements.txt','README.txt'):
        path=stage/name
        manifest.append({'path':name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'bytes':path.stat().st_size})
    (stage/'release-manifest.json').write_text(json.dumps({'version':VERSION,'files':manifest},ensure_ascii=False,indent=2),encoding='utf-8')
    files=list(stage.rglob('*'))
    for path in files:
        parts=set(path.relative_to(stage).parts)
        if parts&FORBIDDEN or path.suffix.lower() in {'.db','.sqlite','.sqlite3','.log','.pdb','.pyc','.bak'}:raise RuntimeError('Forbidden release artifact')
    archive=Path(str(stage)+'.zip')
    with zipfile.ZipFile(archive,'x',zipfile.ZIP_DEFLATED,compresslevel=9) as bundle:
        for path in files:
            if path.is_file():bundle.write(path,stage.name+'/'+path.relative_to(stage).as_posix())
    return {'folder':str(stage),'zip':str(archive),'bytes':archive.stat().st_size,'files':sum(p.is_file() for p in files)}

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,default=ROOT/'dist');args=parser.parse_args()
    print(json.dumps(build(args.output),ensure_ascii=False))
