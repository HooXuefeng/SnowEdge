---
name: browser-observation-workspace
display_name: Browser Observation Workspace
description: Uses a scope-constrained observe-only Chromium session to collect DOM, form, script, Network/XHR/Fetch, console and screenshot evidence without automatic interaction.
domain: cybersecurity
category: browser
risk_tier: low-risk
execution_mode: MANUAL_WORKSPACE
capabilities: [browser_workspace]
tags: [browser, playwright, xhr, fetch, dom, screenshot, evidence]
version: 1.0.0
---

# Browser Observation Workspace

## When to Use
Use when a web application needs real-browser observation beyond static HTTP crawling.

## Workflow
1. Select an explicitly authorized HTTP(S) URL.
2. Optionally select an already configured authorized Identity.
3. Perform top-level browser navigation only.
4. Block every HTTP(S) resource that is outside project Scope.
5. Observe DOM forms, scripts, links, Network/XHR/Fetch, console and a screenshot.
6. Mask Authorization, Cookie and API-key-style values in Browser Event history.
7. Promote selected request observations to Request Workspace without replaying them.
8. Send read-only GET/HEAD observations to Authorization Lab when appropriate.
9. Promote useful Browser Events into Evidence.

## Verification
Browser observation must never silently submit forms or click state-changing UI controls.

## Safety Boundary
This is a MANUAL_WORKSPACE Skill. Plan approval may enable it, but no browser navigation occurs until the analyst explicitly starts a Browser Session with an in-scope target.
