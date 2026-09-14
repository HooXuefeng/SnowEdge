from __future__ import annotations

import argparse
import asyncio
import os
import signal
import socket

from app.schema_migrations import ensure_schema_current
from app.services.job_engine import worker_loop


async def _run(worker_id: str) -> None:
    loop = asyncio.get_running_loop()
    task = asyncio.create_task(worker_loop(worker_id))

    def request_stop() -> None:
        if not task.done():
            task.cancel()

    signals=[signal.SIGINT,signal.SIGTERM]
    if hasattr(signal,"SIGBREAK"): signals.append(signal.SIGBREAK)
    for sig in signals:
        try:
            loop.add_signal_handler(sig, request_stop)
        except (NotImplementedError, RuntimeError):
            # Windows event loops may not support add_signal_handler.
            try:
                signal.signal(sig, lambda *_: request_stop())
            except Exception:
                pass

    try:
        await task
    except asyncio.CancelledError:
        pass


def main():
    parser = argparse.ArgumentParser(description="SnowEdge dedicated job worker")
    parser.add_argument("--name", default="", help="Stable worker name")
    args = parser.parse_args()
    ensure_schema_current()
    worker_id = args.name.strip() or f"{socket.gethostname()}-{os.getpid()}"
    asyncio.run(_run(worker_id))


if __name__ == "__main__":
    main()
