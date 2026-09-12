---
name: request-response-diff
display_name: Request / Response Diff Review
description: Uses the scoped Request Workspace to compare read-only responses while masking identity secrets.
domain: cybersecurity
category: validation
risk_tier: low-risk
execution_mode: MANUAL_WORKSPACE
capabilities: [request_workspace, response_diff]
tags: [request, replay, diff, burp]
version: 1.0.0
---

# Request / Response Diff Review

## When to Use
Use for evidence-backed manual validation of a captured or imported request.

## Workflow
1. Store or import the request without sending it.
2. Confirm scope and policy class.
3. Select an authorized identity.
4. Replay only an allowed request.
5. Compare responses and preserve a redacted audit history.

## Verification
Secrets remain encrypted at rest and masked in UI/history.

## Safety Boundary
This skill may only use deterministic capabilities mapped by SnowEdge. The Markdown body is never executed as shell code.
