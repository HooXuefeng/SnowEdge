---
name: evidence-ai-triage
display_name: Evidence-First AI Triage
description: Provides the AI model a bounded evidence summary and asks for evidence-backed findings only.
domain: cybersecurity
category: ai-analysis
risk_tier: safe
execution_mode: AI_ANALYSIS
capabilities: [ai_analyze]
tags: [ai, evidence, triage, findings]
version: 1.0.0
---

# Evidence-First AI Triage

## When to Use
Use after deterministic collection has produced structured evidence.

## Workflow
1. Build a bounded context from observed evidence.
2. Omit full HTTP response bodies unless project configuration explicitly permits them.
3. Include selected knowledge-only skills as methodology references, not executable instructions.
4. Ask the model for evidence-backed findings only.
5. Persist findings and analysis context.

## Verification
The LLM cannot bypass Scope Engine or Policy Engine.

## Safety Boundary
This skill may only use deterministic capabilities mapped by SnowEdge. The Markdown body is never executed as shell code.
