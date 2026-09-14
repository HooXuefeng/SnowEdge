---
name: web-attack-surface-mapping
display_name: Web Attack Surface Mapping
description: Collects an HTTP baseline, crawls in-scope HTML with GET only, and builds the web resource graph.
domain: cybersecurity
category: web-discovery
risk_tier: safe
execution_mode: DETERMINISTIC
capabilities: [http_probe, web_discovery]
tags: [web, crawl, surface, endpoint]
version: 1.0.0
---

# Web Attack Surface Mapping

## When to Use
Use for in-scope web applications where the assessment needs an inventory before validation.

## Workflow
1. Collect a single read-only HTTP baseline.
2. Follow only in-scope HTTP/HTTPS links.
3. Use GET only and never submit discovered forms.
4. Record pages, redirects, status codes, JavaScript assets, and forms.
5. Persist the resulting attack surface.

## Verification
No out-of-scope redirect or discovered link may be followed.

## Safety Boundary
This skill may only use deterministic capabilities mapped by SnowEdge. The Markdown body is never executed as shell code.
