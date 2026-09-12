# V1.6 Personal Reliability & Recovery

## Design rule

V1.6 adds reliability and local data protection. It does not grant new pentest execution capabilities.

## Full Backup trust model

```text
SQLite backup API
→ temporary ZIP
→ scrypt(password, random salt)
→ AES-256-GCM streaming encryption
→ .aipwbak
```

The encrypted archive contains APP_SECRET_KEY because encrypted Identity/Vault rows are unusable after a disaster restore without the original application key.

The user password and APP_SECRET_KEY serve different purposes:

```text
Backup password  protects the .aipwbak file
APP_SECRET_KEY    protects application secrets inside the restored DB
```

## Restore atomicity

Restore is staged while the Web application is running, but applied only by the startup Supervisor before Web/Worker processes are created.

Current DB is copied to `<database>.pre_restore` before replacement.

## Vault

Vault payloads use the existing APP_SECRET_KEY/Fernet encryption layer.

HTTP Identity payload format:

```json
{"headers": {"Authorization": "..."}, "cookies": {"sid": "..."}}
```

The UI shows key names, not values.

## Drafts

WorkspaceDraft.content_json stores a Fernet token rather than plaintext JSON. This matters because a user may type Authorization/Cookie/request-body secrets into an unsaved request.

## Recovery

Recovery never invents a new action. Only existing PersistentJob kinds already accepted by the Job Engine can be returned to the queue.

## Search

Global search is metadata-oriented. Evidence body and Vault secret values are intentionally not search surfaces.

## Windows Launcher

The release contains both source and the built Windows x64 executable. The native launcher delegates Python process lifecycle to a hidden Supervisor so recovery logic remains testable independently of the Windows UI shell.
