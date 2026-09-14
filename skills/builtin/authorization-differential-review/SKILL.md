---
name: authorization-differential-review
display_name: Authorization Differential Review
description: Guides read-only User A/User B/Admin/Anonymous response comparison for object-level and role-level authorization review.
domain: cybersecurity
category: authorization
risk_tier: low-risk
execution_mode: MANUAL_WORKSPACE
capabilities: [authorization_lab, response_diff]
tags: [authorization, idor, horizontal, vertical, session]
version: 1.0.0
---

# Authorization Differential Review

## When to Use
Use when at least one read-only request and authorized test identities are available.

## Workflow
1. Define the baseline identity.
2. Define a comparison identity or Anonymous.
3. For horizontal testing, record the expected resource owner.
4. Replay only GET/HEAD requests through the scoped Request Workspace.
5. Compare status, length, text similarity, and JSON structure.
6. Treat 200 as evidence only, never as proof by itself.
7. Require manual confirmation for candidate findings.

## Verification
State-changing methods are excluded from automated authorization comparison.

## Safety Boundary
This skill may only use deterministic capabilities mapped by SnowEdge. The Markdown body is never executed as shell code.
