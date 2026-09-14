# V1.0 Intelligence Architecture

<p align="center"><img src="../app/static/brand/snowedge-app.png" width="96" alt="SnowEdge"></p>

## Core invariant

The intelligence layer never grants execution permission.

```text
Knowledge Graph
Assessment Memory
Specialist Agents
Handoffs
```

are analysis and coordination structures.

Network permission still comes exclusively from deterministic Scope / Policy / Skill capability mappings.

## Knowledge Graph trust model

Graph edges are materialized from database foreign-key/domain relationships.

No AI-generated relation is written into the canonical graph.

Graph summaries deliberately omit raw secret-bearing content.

## Assessment Memory trust model

Assessment Memory is derived from existing Workspace records.

A memory is a prior conclusion or coverage signal, not proof by itself.

High-confidence `avoid_repeat` guidance lowers Planner priority but never disables an explicit analyst retest.

## Specialist Agent model

Each specialist is a bounded role over a filtered graph/memory slice.

Specialists cannot call tools.

They return structured JSON:

```text
summary
observations
handoffs
next_checks
```

Server-side validation limits:

- observation count,
- confidence range,
- handoff destinations,
- output field lengths.

Unexpected execution-like fields are discarded and increment drift.

## Specialist roles

### Planner
Coordinates coverage and duplicate-work review.

### Recon Analyst
Reviews asset/service/transport evidence.

### Web Analyst
Reviews endpoints, JS/API mapping, Browser observations and Stored Requests.

### Authorization Analyst
Reviews read-only identity/object differential evidence.

### Evidence Reviewer
Checks Findings against Evidence and Proof Capsule state.

### Reporter
Prepares verification-aware reporting from existing facts.

## Intent Contract

Every SpecialistAgentRun persists:

```text
analysis_only = true
tool_invocation = false
scope_rules
allowed_skills
allowed_capabilities
visible_node_types
visible_memory_types
handoff_targets
risk_ceiling
unknown_action_policy = DENY
```

## Drift behavior

If a provider emits:

```text
tool_requests
commands
shell
payloads
invalid handoff
```

the Workspace:

1. does not execute it;
2. discards it;
3. increments `drift_count`;
4. continues the analysis run when possible.

## Data minimization

The canonical intelligence layer excludes:

- encrypted Identity values,
- Cookie values,
- Authorization values,
- API-key values,
- StoredRequest bodies,
- raw Evidence bodies,
- full Browser event header/detail blobs.

Sensitive URL query parameters are redacted using the Browser Workspace redaction rules before entering Knowledge or Memory.

## Reporting

The report pipeline consumes summary-level intelligence state only.

It does not include hidden model chain-of-thought or raw secrets.
