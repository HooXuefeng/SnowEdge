# Execution Graph and Finding Proof Capsule

<p align="center"><img src="../app/static/brand/snowedge-app.png" width="96" alt="SnowEdge"></p>

## 1. Execution Graph

The Execution Graph is a persistent projection of a Skill Plan.

It records intended workflow structure separately from runtime traces.

### Planning state

`ExecutionGraphNode` stores:

- project and Skill Plan ownership,
- Skill slug,
- stage,
- execution mode,
- capabilities,
- dependencies,
- rationale,
- current status,
- linked SkillRun ID.

### Runtime truth

After an approved Skill Plan executes, graph status is derived from actual `SkillRun` rows.

The AI does not report a graph node as completed.

A node becomes `done` only when the corresponding Workspace SkillRun is `done`.

### Manual nodes

`MANUAL_WORKSPACE` nodes remain `manual_ready`.

Examples include request-diff and authorization workflows that require analyst-provided request/identity context.

## 2. Proof Capsule

A Proof Capsule is a verification contract linked to one Finding.

It separates:

```text
original observation
expected verification signal
latest observed verification signal
retest history
```

### Registered verifier classes

#### `http_header_absence`

Read-only HTTP probe.

Reproduced when the named header remains absent.

#### `http_header_presence`

Read-only HTTP probe.

Reproduced when the named header remains present.

#### `authorization_case_replay`

Replays an already configured Authorization Case using the existing safe GET/HEAD differential-testing workflow.

#### `evidence_snapshot`

No network action.

Used when the Workspace does not have a deterministic verifier for the Finding source.

### Security properties

- No Proof Capsule permits arbitrary commands.
- No Proof Capsule accepts shell snippets.
- No Proof Capsule creates payloads from AI text.
- Network verification checks current project scope.
- Authorization verification remains GET/HEAD only.
- Unsupported verification is surfaced as `needs_review`, not guessed.
- Each automated retest creates auditable Evidence.
