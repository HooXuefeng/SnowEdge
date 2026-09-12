# SnowEdge · Burp Extension

## Prebuilt JAR

V1.5 release includes:

```text
dist/SnowEdge-Burp-1.0.0.jar
```

You can load this JAR directly in Burp. Source and Gradle project are also retained for rebuilding.


Purpose:

```text
Burp selected request
→ localhost Workspace API
→ Scope check
→ StoredRequest
→ Request Workspace 2.0
```

The extension does **not** replay the request and does not trigger scanning.

## Build

Requires JDK 8+ and Gradle:

```bash
gradle clean jar
```

Result:

```text
build/libs/SnowEdge-Burp-1.0.0.jar
```

Load the JAR in Burp:

```text
Extensions
→ Installed
→ Add
→ Java
```

## Configure

In Burp right-click menu:

```text
Configure SnowEdge...
```

Set:

```text
Base URL   http://127.0.0.1:8000
Project ID numeric project ID
Token      same Burp Integration Token configured in Workspace /setup
```

Then select one or more HTTP history / Repeater messages and choose:

```text
Send to SnowEdge
```

## Security behavior

- The API requires `X-SnowEdge-Token`.
- Workspace checks the parsed target against the selected project's current Scope.
- Sensitive request headers are encrypted by Workspace.
- GET/HEAD become READ_ONLY by default.
- Other HTTP methods become STATE_CHANGE and are not automatically replayed.
- The extension talks only to the user-configured Workspace URL.
