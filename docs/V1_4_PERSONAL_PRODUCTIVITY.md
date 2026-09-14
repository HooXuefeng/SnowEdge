# V1.4 Personal Pentest Productivity

<p align="center"><img src="../app/static/brand/snowedge-app.png" width="96" alt="SnowEdge"></p>

## Default personal workflow

```text
Authorized target
→ Quick Scan / Passive Import
→ Endpoint + Stored Request
→ Explicit Identity / Authorization Matrix
→ Evidence + Screenshot
→ Finding / Retest
→ txb02 Word
```

V1.4 does not add automatic brute force, object-ID enumeration, arbitrary commands, destructive actions, persistence/evasion or Scope bypass.

## Personal settings

`/setup` stores ordinary preferences in `AppPreference.value_json`. AI API Key is stored separately in `secret_encrypted` using the existing APP_SECRET_KEY/Fernet layer and is never sent back to the browser in plaintext.

## Passive API import

Supported data adapters:

```text
HAR
Postman Collection v2.x
OpenAPI 3.x JSON/YAML
Swagger 2.x JSON/YAML
```

The adapters are parsers only. They do not launch scanners or make target requests. Project Scope is checked before imported targets become Workspace data.

## Screenshot Evidence

Binary screenshot bytes live under `EVIDENCE_ARTIFACT_DIR`; normal Evidence stores metadata and SHA256 only. Allowed formats are PNG/JPEG/WebP, maximum 8 MB, with magic-signature validation.

## Backups

V1.4 automatic backup is intentionally a sanitized portable project ZIP, not a secret-bearing full workstation image. This makes routine retention safer, but credentials and screenshot binaries must be reconfigured/restored separately.

## Diagnostics

The diagnostics page performs local environment/configuration checks only and does not probe the current pentest target or call the configured AI service.
