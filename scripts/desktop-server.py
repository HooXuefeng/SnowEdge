"""Owned desktop backend. Existing services are never stopped by this process."""
from __future__ import annotations

import argparse
import ctypes
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


def watch_owner(parent_pid, stop_file, shutdown):
    """Hold a handle to the original parent, avoiding PID reuse on Windows."""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel.OpenProcess(0x00100000, False, parent_pid)
    try:
        while handle and not stop_file.exists():
            if kernel.WaitForSingleObject(handle, 500) != 258:
                break
        shutdown.set()
    finally:
        if handle:
            kernel.CloseHandle(handle)


def prepare(shutdown):
    for name in ("apply-pending-restore.py", "db-upgrade.py"):
        if shutdown.is_set():
            return False
        proc = subprocess.Popen(
            [sys.executable, str(ROOT / "scripts" / name)], cwd=ROOT,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        while proc.poll() is None:
            if shutdown.wait(.2):
                # Let an in-progress migration/restore finish before exiting.
                proc.wait()
                return False
        if proc.returncode:
            raise RuntimeError(f"Desktop preparation failed: {name}")
    return not shutdown.is_set()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--parent", required=True, type=int)
    parser.add_argument("--stop-file", required=True, type=Path)
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    os.chdir(ROOT)
    sys.path.insert(0, str(ROOT))
    shutdown = threading.Event()
    threading.Thread(target=watch_owner, args=(args.parent, args.stop_file, shutdown), daemon=True).start()
    # Reserve the port before any database preparation. Never race a second server.
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    try:
        sock.bind(("127.0.0.1", args.port))
        if not prepare(shutdown):
            return
        os.environ["JOB_EMBEDDED_WORKERS"] = "2"
        os.environ["JOB_IMMEDIATE_ACCELERATOR"] = "false"
        import uvicorn
        server = uvicorn.Server(uvicorn.Config("app.main:app", host="127.0.0.1", port=args.port, timeout_graceful_shutdown=15))

        def stop_server():
            shutdown.wait()
            server.should_exit = True

        threading.Thread(target=stop_server, daemon=True).start()
        if not shutdown.is_set():
            server.run(sockets=[sock])
    finally:
        sock.close()
        args.stop_file.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
