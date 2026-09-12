---
name: reporting-evidence-pack
display_name: Reporting & Evidence Pack
description: Structures findings, authorization cases, and evidence into reproducible Markdown/HTML deliverables.
domain: cybersecurity
category: reporting
risk_tier: safe
execution_mode: LOCAL_ANALYSIS
capabilities: [reporting]
tags: [report, evidence, markdown, html]
version: 1.0.0
---

# Reporting & Evidence Pack

## When to Use
Use after findings and evidence have been collected.

## Workflow
1. Summarize assets and attack surface.
2. Include authorization case status separately from confirmed findings.
3. Link each finding to captured evidence.
4. Export a human-readable Markdown or standalone HTML report.

## Verification
Do not silently upgrade candidate or review findings to confirmed vulnerabilities.

## Safety Boundary
This skill may only use deterministic capabilities mapped by SnowEdge. The Markdown body is never executed as shell code.
