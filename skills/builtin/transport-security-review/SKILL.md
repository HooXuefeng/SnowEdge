---
name: transport-security-review
display_name: Transport & Header Security Review
description: Reviews HTTPS/TLS posture and evidence-backed security-header hardening observations.
domain: cybersecurity
category: configuration
risk_tier: safe
execution_mode: DETERMINISTIC
capabilities: [headers_check, tls_check]
tags: [tls, headers, hsts, csp]
version: 1.0.0
---

# Transport & Header Security Review

## When to Use
Use for web endpoints after a successful HTTP baseline.

## Workflow
1. Analyze captured response headers.
2. Review common hardening headers based on HTTP/HTTPS context.
3. For HTTPS, capture certificate and negotiated TLS information.
4. Create evidence-backed configuration findings only where observations support them.

## Verification
Do not infer protocol weaknesses that were not actually observed.

## Safety Boundary
This skill may only use deterministic capabilities mapped by SnowEdge. The Markdown body is never executed as shell code.
