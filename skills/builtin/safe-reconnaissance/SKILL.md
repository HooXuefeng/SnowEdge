---
name: safe-reconnaissance
display_name: Safe Reconnaissance
description: Maps authorized hosts and common TCP services using constrained reconnaissance and stores evidence.
domain: cybersecurity
category: recon
risk_tier: low-risk
execution_mode: DETERMINISTIC
capabilities: [port_scan]
tags: [recon, ports, services, scope]
version: 1.0.0
---

# Safe Reconnaissance

## When to Use
Use at the beginning of an authorized assessment to identify reachable services.

## Workflow
1. Validate target against project Scope Engine.
2. Run the constrained built-in TCP reconnaissance capability.
3. Normalize discovered services into the Asset model.
4. Store raw output as Evidence.
5. Hand off observations to later selected skills.

## Verification
Confirm every network action is linked to a Task, Evidence record, and project scope.

## Safety Boundary
This skill may only use deterministic capabilities mapped by SnowEdge. The Markdown body is never executed as shell code.
