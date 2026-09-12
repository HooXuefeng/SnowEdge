---
name: agent-tool-guardrails
display_name: Agent Tool Guardrails
description: Reviews the agent tool boundary: allowlisting, scope checks, policy class, HITL separation, and audit logging.
domain: cybersecurity
category: ai-security
risk_tier: safe
execution_mode: LOCAL_ANALYSIS
capabilities: [guardrail_audit]
tags: [agent, guardrail, hitl, tool-allowlist, audit]
version: 1.0.0
---

# Agent Tool Guardrails

## When to Use
Use when reviewing how AI can invoke real security tools.

## Workflow
1. Confirm tools are allowlisted and mapped to policy classes.
2. Confirm project scope is checked before every network action.
3. Keep dangerous or unknown actions default-deny.
4. Separate model recommendations from deterministic execution.
5. Preserve Skill Run, Task, Evidence, and Agent Event traces.

## Verification
No SKILL.md content can directly become arbitrary shell execution.

## Safety Boundary
This skill may only use deterministic capabilities mapped by SnowEdge. The Markdown body is never executed as shell code.
