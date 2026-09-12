# V1.5 Personal Pentest Workflow 2.0

## Workflow

```text
Burp / Browser / Passive Import
                ↓
       StoredRequest + Revision
                ↓
       Request Workspace 2.0
                ↓
     Identity / Authorization
                ↓
       Evidence / Screenshot
                ↓
        Finding Quality Gate
                ↓
      Retest / Proof Capsule
                ↓
         Report Preflight
                ↓
            txb02 Word
```

## Burp trust boundary

The Burp integration is a local data-ingestion bridge, not an execution bridge.

```text
Burp Request
→ Integration Token
→ JSON API
→ Parse HTTP
→ Scope Check
→ Secret Header Split
→ StoredRequest
```

No replay is triggered by the API.

## Request revisions

A revision captures the exact request workspace state at that moment.

Restoring a revision creates a new revision instead of deleting later history.

## Screenshot annotation

Original files are immutable from the annotation workflow.

Annotation JSON uses normalized coordinates, so delivery rendering is independent of the browser viewport size.

## Quality Gate

Quality score measures report support, not vulnerability severity.

A high-risk Finding can still have low evidence quality, and an informational Finding can have excellent evidence quality.

## Browser metadata privacy

Browser 2.0 captures metadata necessary for security reasoning while excluding content that behaves like secrets.

Persist:

```text
Storage key names
Cookie attributes
WebSocket counts / byte lengths
CSP
route URLs with secret query redaction
DOM hash
```

Do not persist:

```text
Storage values
Cookie values
WebSocket message payload
```

## Environment QA limitation

The hosted Chromium used during release validation blocks local `page.goto()` with an administrator policy. This prevents a genuine Browser 2.0 navigation E2E in the release environment.

The release therefore uses:

```text
Python regression tests
runtime metadata model tests
sanitized Browser 2.0 UI rendering
source/syntax validation
```

and does not label the blocked navigation attempt as PASS.
