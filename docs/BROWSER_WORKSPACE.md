# Browser Workspace Architecture

## Purpose

Browser Workspace provides real-browser evidence collection for an explicitly authorized web target while preserving the Workspace's deterministic Scope and Policy boundaries.

## Security contract

The browser is not an autonomous interaction agent.

V0.9 permits:

```text
top-level GET navigation
page-load observation
in-scope resource loading
DOM metadata collection
Network/XHR/Fetch observation
console observation
screenshot capture
```

V0.9 does not implement automatic form submission or button clicking.

## Scope enforcement

A Playwright `route("**/*")` handler runs before browser HTTP(S) requests.

Every URL is checked using the same project Scope Engine used by scanners and request replay.

Out-of-scope requests are aborted and recorded as:

```text
BrowserEvent.event_type = blocked_out_of_scope
in_scope = false
```

## Secret handling

Identity secrets remain encrypted in the Identity model.

Browser request/response event headers are redacted before persistence.

Protected values are not available to Browser Event → StoredRequest promotion.

This intentionally means a request promoted from Browser Event history may need an authorized Identity selected later in Request Workspace to reproduce an authenticated request.

## Browser Event → StoredRequest

The handoff is import-only.

It does not replay the observed request.

Policy:

```text
GET/HEAD: READ_ONLY
other methods: STATE_CHANGE
```

POST bodies are not persisted from Browser Event observation in V0.9.

## Browser Event → Authorization Lab

Only GET/HEAD in-scope request events can be promoted.

Authorization Lab remains responsible for identity selection and differential validation.

## Artifacts

V0.9 stores:

- screenshot PNG,
- bounded DOM snapshot,
- DOM form/script/link metadata.

Artifact files are served only through a database-owned artifact ID and are required to remain beneath the configured browser artifact directory.

## Runtime fallback

Browser launch order:

1. Playwright bundled Chromium;
2. system Chromium;
3. system Chrome;
4. system Edge.

If no usable runtime exists, Browser Session ends as `unavailable` or `error` with actionable runtime detail.
