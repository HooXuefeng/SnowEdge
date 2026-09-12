# Web / Worker / PostgreSQL Deployment

## Local SQLite compatibility mode

Existing behavior remains available:

```bat
start.bat
```

With the default accelerator enabled, the persisted job may be executed by the Web process for convenience.

## Local separated mode

```bat
start-all.bat
```

This starts:

```text
Web
Worker
```

and sets:

```text
JOB_EMBEDDED_WORKERS=0
JOB_IMMEDIATE_ACCELERATOR=false
```

## Worker only

```bat
start-worker.bat
```

or:

```bash
python worker.py --name worker-01
```

## Docker / PostgreSQL

The Compose file refuses to start until `POSTGRES_PASSWORD`, `DATABASE_URL` and `APP_SECRET_KEY` are supplied. Copy `.env.docker.example` to a private local `.env`, replace every placeholder, and do not commit that `.env`.

Then:

```bash
docker compose up --build
```

Services:

```text
postgres
web
worker
```

Database URL:

```text
postgresql+psycopg://user:password@postgres:5432/database
```

## Recommended production settings

```text
APP_SECRET_KEY=<long random secret>
JOB_EMBEDDED_WORKERS=0
JOB_IMMEDIATE_ACCELERATOR=false
JOB_LEASE_SECONDS=45
JOB_HEARTBEAT_SECONDS=10
```

Use the same `APP_SECRET_KEY` for Web and Worker instances that must read the same encrypted authorized test identities.

## Scale-out

For multiple workers, prefer PostgreSQL.

Each worker needs a unique stable name:

```bash
python worker.py --name worker-01
python worker.py --name worker-02
```

The PostgreSQL queue path uses row locking with `SKIP LOCKED`.

## Current QA statement

V1.3 completed a real separate-process Worker E2E on SQLite.

The hosted QA environment did not provide a PostgreSQL server, so the release does not claim a live PostgreSQL service E2E.
