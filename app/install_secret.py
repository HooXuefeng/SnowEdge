"""An installation gets its own key; configured legacy keys remain untouched."""
import os
import secrets
import time
from pathlib import Path

def installation_secret():
    root=Path(os.environ.get('SNOWEDGE_STATE_DIR','.runtime'))
    root.mkdir(parents=True,exist_ok=True)
    path=root/'app-secret'
    try:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    except FileExistsError:
        for _ in range(20):
            key=path.read_text(encoding='ascii').strip()
            if len(key)>=64:return key
            time.sleep(.05)
        raise RuntimeError('应用密钥文件不完整，请从备份恢复；不会自动覆盖已有密钥。')
    else:
        key=secrets.token_hex(32)
        with os.fdopen(fd,'w',encoding='ascii') as stream:
            stream.write(key);stream.flush();os.fsync(stream.fileno())
        return key
