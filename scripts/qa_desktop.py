"""Native desktop smoke check with isolated data and an unused loopback port."""
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import sys
import urllib.request

ROOT = Path(os.environ.get('SNOWEDGE_QA_ROOT', str(Path(__file__).resolve().parents[1])))
LAUNCHER = ROOT / 'SnowEdge.exe'

with tempfile.TemporaryDirectory(prefix="desktop-qa-", ignore_cleanup_errors=True) as scratch:
    tmp = Path(scratch)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = os.environ.copy()
    env.update(DATABASE_URL=f"sqlite:///{(tmp/'desktop.db').as_posix()}", APP_SECRET_KEY="desktop-qa-only",
               AI_PROVIDER="mock", AI_API_KEY="", AI_API_BASE="", RESTORE_PENDING_DIR=str(tmp/'restore'),
               EVIDENCE_ARTIFACT_DIR=str(tmp/'evidence'), BROWSER_ARTIFACT_DIR=str(tmp/'browser'), DESKTOP_PORT=str(port), DESKTOP_PROFILE=str(tmp/'profile'))
    settings = ROOT/'.runtime/desktop-size.txt'
    old = settings.read_bytes() if settings.exists() else None
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0
    proc = subprocess.Popen([str(LAUNCHER), '--smoke'], cwd=ROOT, env=env, startupinfo=startup)
    try:
        code = proc.wait(timeout=100)
        assert code == 0, f"Desktop failed ({code}); see .runtime/desktop.log"
        with socket.socket() as sock:
            assert sock.connect_ex(('127.0.0.1', port)) != 0, "Owned service survived window close"
        assert (ROOT/'.runtime/desktop-smoke.png').exists()
        print('PASS: native WebView2, isolated backend startup, page load, zoom selection, screenshot, owned backend exit.')
        # Reusing a service must not transfer ownership to the desktop window.
        external = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', str(port)], cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            for _ in range(100):
                try:
                    urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health',timeout=.5).close()
                    break
                except Exception:
                    time.sleep(.2)
            else:
                raise AssertionError('External service did not start')
            proc = subprocess.Popen([str(LAUNCHER), '--smoke'], cwd=ROOT, env=env, startupinfo=startup)
            assert proc.wait(timeout=60) == 0
            assert external.poll() is None
            urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health',timeout=2).close()
            print('PASS: closing a reused desktop session leaves the existing service running.')
        finally:
            external.terminate(); external.wait(timeout=15)
        owner = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], creationflags=subprocess.CREATE_NO_WINDOW)
        owned = subprocess.Popen([sys.executable, str(ROOT/'scripts/desktop-server.py'), '--parent', str(owner.pid), '--port', str(port), '--stop-file', str(tmp/'crash.stop')],cwd=ROOT,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            for _ in range(100):
                try:
                    urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health',timeout=.5).close();break
                except Exception:time.sleep(.2)
            else:raise AssertionError('Owned backend did not start')
            owner.terminate();owner.wait(timeout=10)
            assert owned.wait(timeout=25) == 0
            print('PASS: owner crash triggers backend shutdown without a stop file.')
        finally:
            for child in (owner,owned):
                if child.poll() is None:child.terminate();child.wait(timeout=10)
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=10)
            time.sleep(3)
        if old is None:
            settings.unlink(missing_ok=True)
        else:
            settings.write_bytes(old)
