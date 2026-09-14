---
name: javascript-api-mapper
display_name: JavaScript & API Mapper
description: Statically reviews discovered JavaScript for API-style routes, fetch/axios calls, and source-map references.
domain: cybersecurity
category: web-discovery
risk_tier: safe
execution_mode: DETERMINISTIC
capabilities: [js_static_analysis]
tags: [javascript, api, source-map, routes]
version: 1.0.0
---

# JavaScript & API Mapper

## When to Use
Use after HTML discovery has identified JavaScript assets.

## Workflow
1. Analyze already in-scope JavaScript assets.
2. Extract API-looking paths and fetch/axios route references.
3. Record sourceMappingURL references without fetching out-of-scope content.
4. Store route candidates separately from observed endpoints.
5. Mark confidence based on extraction context.

## Verification
Static analysis must not execute JavaScript or invoke routes.

## Safety Boundary
This skill may only use deterministic capabilities mapped by SnowEdge. The Markdown body is never executed as shell code.
