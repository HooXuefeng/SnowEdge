# V1.6.2 Asset Intelligence & UX

## Design goal

V1.6.2 improves the path between observations:

```text
Asset
→ Fingerprint
→ Endpoint
→ Context Action
→ Request / Browser
→ Evidence / Finding
```

A product fingerprint never grants exploitation permission.

## Fingerprint Engine

Inputs are existing Workspace observations: bounded HTTP Evidence, Technology Snapshot, Service Banner, headers, cookies, title and stored body snippets. Output is normalized `TechnologyFingerprint`.

Custom rules are constrained to `contains` matching; no arbitrary script or command execution is accepted.

## Network Routes

Project route selection is explicit: Direct, HTTP, SOCKS5 or Burp. HTTP-oriented modules consume the selected route.

Port scanning has no transparent HTTP proxy equivalent and therefore safely skips when the project route is non-Direct.

## Batch Assessment

A Batch is one user-intent unit containing multiple individually scoped targets. Each item still passes the existing Scope/Policy path.

Batch execution is serialized. The Job Engine additionally uses resource classes to reduce contention on a personal workstation; this is not advertised as a distributed multi-node semaphore.

## Context Actions

Context actions pass stored entity IDs instead of serializing hidden raw secrets into HTML. Browser Observe loads the Endpoint server-side, obtains the original URL, rechecks Scope and only then queues the browser job.

## TscanPlus boundary

Borrowed ideas:

```text
asset-pipeline UX
fingerprints
result context actions
batch targets
saved profiles
network routes
data-grid ergonomics
```

Not borrowed into automated execution:

```text
weak-password cracking
JWT secret cracking
WAF bypass
reverse shell
CS payload workflows
post-exploitation
```


## Release hardening

Final release regression additionally validates:

```text
real Request Replay through a local HTTP proxy
fingerprint evidence-summary URL query redaction
execution-time reapplication of a Batch-bound Scan Profile
```

This prevents three common productization failures: a route that only exists in settings, a fingerprint metadata leak, and a queued Batch silently changing behavior after ProjectSkill edits.
