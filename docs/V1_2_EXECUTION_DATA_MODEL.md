# V1.2 Execution Engine, Data Model and Chinese Productization

<p align="center"><img src="../app/static/brand/snowedge-app.png" width="96" alt="SnowEdge"></p>

## 1. Persistent Job Engine

`PersistentJob` is the durable source of truth for long-running work.

Supported handlers:

```text
project_scan
browser_observe
copilot_query
agent_team
proof_retest
authorization_matrix
endpoint_sync
knowledge_refresh
```

Each job stores:

```text
project_id
kind
target
reference-only payload
scope snapshot JSON
scope snapshot SHA-256
status
priority
attempts / max_attempts
timeout
next retry time
started / finished timestamps
result / error
```

`PersistentJobEvent` is append-only execution history.

### Recovery

Application startup calls `recover_orphaned_jobs()`.

```text
running          → queued
cancel_requested → cancelled
```

This avoids silently losing work across process restarts.

### Immediate accelerator

HTTP actions enqueue the job first, then may call `run_job_now(job_id)` through FastAPI background execution for responsiveness.

The job row is still created before execution and remains the source of truth.

### Secret boundary

Persistent job payloads are reference-only.

The enqueue layer rejects obvious secret-bearing keys such as:

```text
Authorization
Cookie
Token
Password
Secret
API Key
Headers
Body
```

Identity/session material remains in the encrypted Identity / StoredRequest stores.

## 2. Scope semantics

Every job records the project Scope as it existed when the job was queued.

This snapshot is audit context only.

Before a network-backed handler runs, the handler still checks the **current** project Scope.

Therefore:

```text
historic snapshot cannot expand current authorization
```

## 3. Database migrations

Alembic is introduced in V1.2.

Migration chain:

```text
v1_1_legacy
    ↓
v1_2_core
```

Startup behavior:

```text
empty database
→ create current ORM schema
→ stamp head

legacy V1.1 database
→ legacy evidence patch if needed
→ stamp v1_1_legacy
→ upgrade head

current structure without valid alembic metadata
→ inspect real columns/tables
→ stamp head
```

This structural adoption exists to prevent duplicate-column failures on databases that were already created from the V1.2 ORM metadata.

## 4. Endpoint inventory

Endpoint fingerprint:

```text
SHA256(
  method
  hostname
  normalized path
)
```

Dynamic-looking path segments are normalized to `{id}`.

Example:

```text
/api/order/10001
/api/order/20002

→ /api/order/{id}
```

Endpoint parameters are stored separately.

Sensitive parameter paths use segment-aware detection.

Examples:

```text
token
ticket
Authorization
profile.password
credentials[].secret
```

Their examples are stored as:

```text
••••
```

## 5. Finding dedupe

Finding fingerprint intentionally excludes discovery source.

```text
SHA256(
  canonical vulnerability type
  normalized target
  parameter
)
```

This allows the same issue discovered by multiple modules to converge.

`FindingOccurrence` retains every duplicate observation and linked evidence.

## 6. Authorization Matrix

Authorization Matrix is a coordinator over the existing AuthorizationCase engine.

It does not implement a second authorization classifier.

Matrix constraints:

```text
GET / HEAD only
READ_ONLY only
max 6 explicitly selected comparison identities
optional Anonymous
no object enumeration
no ID guessing
no automatic parameter mutation
current Scope recheck
```

## 7. Sanitized project portability

Project export is intentionally not a forensic evidence export.

It carries reusable project structure while omitting sensitive or high-risk material.

Excluded:

```text
Identity credentials
Authorization / Cookie
secret request headers
request bodies
raw Evidence content
browser screenshots
remediation-note bodies
sensitive query parameter values
```

Imported identities and requests cannot immediately replay authenticated traffic until an authorized tester explicitly configures new credentials.

## 8. Chinese product layer

User-facing product text is Chinese-first.

Security protocol identifiers remain unchanged where translation would reduce precision:

```text
CWE
OWASP
READ_ONLY
GET / HEAD
Fingerprint
Skill slug
XHR / Fetch
Cookie
SKILL.md
```
