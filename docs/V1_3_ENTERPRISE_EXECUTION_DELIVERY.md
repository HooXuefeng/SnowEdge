# V1.3 Enterprise Execution & Delivery

<p align="center"><img src="../app/static/brand/snowedge-app.png" width="96" alt="SnowEdge"></p>

## Architecture

```text
Browser
   ↓
FastAPI Web
   ↓
PersistentJob
   ↓
Database
   ↓
Dedicated Worker
   ↓
Scope / Policy recheck
   ↓
Handler
   ↓
Task / Request / Response / Evidence
   ↓
Finding / Proof / Report
```

The database remains the durable job source of truth.

## Job ownership

A running job has:

```text
worker_id
lease_token
heartbeat_at
lease_expires_at
```

The worker refreshes its lease periodically.

A job is recoverable only after its lease expires.

### SQLite

SQLite remains appropriate for one-machine use.

Claiming uses an atomic conditional update:

```text
UPDATE persistent_jobs
SET status = running, ...
WHERE id = ?
  AND status = queued
```

Only one process can win the `queued` compare-and-swap.

### PostgreSQL

The PostgreSQL path selects queue rows using:

```text
FOR UPDATE SKIP LOCKED
```

This is the preferred mode for multiple independent workers.

## Evidence integrity

Two hashes are stored:

```text
content_sha256
→ SHA256(Evidence.content)

integrity_sha256
→ SHA256(
    kind
    content_sha256
    project_id
    finding_id
    task_id
    job_id
    parent_evidence_id
    source_type
    source_id
    redaction_state
  )
```

`EvidenceProvenance` records deterministic relations rather than relying only on free text.

## Evidence secret policy

The normal Evidence table is not a credential vault.

Common credential material is redacted before persistence for Finding/Task Evidence.

If a future workflow genuinely requires exact secret-bearing raw evidence, it should use a separate encrypted, explicitly permissioned secret-evidence store rather than weakening the normal Evidence policy.

## Finding lifecycle

The three state axes are intentionally independent:

```text
Finding State
Remediation State
Verification State
```

A retest can update Verification without conflating the analyst's Finding confirmation state.

## Passive imports

Imports are data adapters, not scanner launchers.

```text
Burp XML
Nmap XML
Nuclei JSONL
```

Every imported target is filtered through Project Scope before it becomes Workspace data.

## Word report

The txb02 Word export is a structured delivery layer over current project data.

It does not treat AI output as confirmed evidence and it does not embed normal secret values.
