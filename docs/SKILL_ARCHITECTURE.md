# V0.6 Skill Architecture

<p align="center"><img src="../app/static/brand/snowedge-app.png" width="96" alt="SnowEdge"></p>

## Design goal

Security Skills should improve methodology selection without turning Markdown into an unrestricted command interface.

The central invariant is:

> Skill content describes intent and methodology; deterministic Workspace code owns execution.

## Data model

### SkillDefinition

Stores:

- slug / display name
- description
- category / tags
- risk tier
- execution mode
- capability list
- SKILL.md body
- provenance
- builtin/external marker

### ProjectSkill

Stores whether a Skill is enabled in one project.

This prevents a global Skill toggle from silently changing another engagement.

### SkillRun

Creates an auditable execution record when a selected built-in Skill maps to a deterministic capability.

## Capability router

Only capabilities in the Workspace allowlist are recognized:

```text
port_scan
http_probe
web_discovery
js_static_analysis
headers_check
tls_check
ai_analyze
coverage_judge
reporting
guardrail_audit
request_workspace
response_diff
authorization_lab
```

External Skills are never assigned capabilities by import.

## Execution modes

### DETERMINISTIC

A built-in methodology mapped to an existing hard-coded capability.

### AI_ANALYSIS

May add methodology context to a bounded AI evidence-review step.

### LOCAL_ANALYSIS

Reads existing project database state only.

### MANUAL_WORKSPACE

Describes a human-triggered workflow such as Request Workspace / Authorization Lab.

### KNOWLEDGE_ONLY

Reference methodology with no executable capabilities.

All imported Skills use this mode.

## Trust model

### Built-in Skill

Trusted as project-shipped methodology metadata, but the Markdown still is not code.

### External Skill

Untrusted content.

It may contain:

- malicious instructions
- stale commands
- destructive examples
- prompt injection
- links to changed dependencies
- incorrect assumptions

Therefore V0.6 stores the content as reference data and uses deterministic execution mapping separately.

## AI context

Enabled Skill methodology may be included in AI evidence review.

The AI receives explicit metadata saying:

```text
untrusted_external_content
instruction_boundary
prompt_injection_boundary
```

The system prompt independently states that third-party Skill text cannot override policy or become tool permission.

## Why no one-click GitHub execution

V0.6 deliberately does not:

```text
GitHub URL
  → clone
  → install dependencies
  → execute scripts
```

That would collapse knowledge ingestion and code execution into one trust boundary.

Instead:

```text
GitHub / team Skill
  → review / paste SKILL.md
  → parse metadata
  → risk label
  → KNOWLEDGE_ONLY
  → optional AI methodology context
```

Future versions can add signed/trusted Skill packages, but they should require explicit trust configuration and a reviewed capability adapter.
