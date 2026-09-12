# AI Skill Planner Architecture

## Security property

The Planner is advisory until a human approves an exact built-in Skill selection.

```text
AI recommendation ≠ permission
```

Permissions continue to originate from hard-coded Skill capability mappings plus Scope and Policy.

## Input boundary

The AI provider receives:

- structural evidence profile,
- target characteristics,
- deterministic candidate list,
- built-in Skill catalog metadata.

It does not receive authentication secrets through the Planner.

## Output boundary

Only catalog slugs survive server-side validation.

Unknown model output is discarded.

## Execution boundary

Draft plans cannot execute.

Approved plans:

- must have an in-scope target,
- restore the exact approved built-in Skill selection,
- queue the normal project assessment workflow,
- preserve Task, SkillRun, AgentRun and Evidence traces.

`MANUAL_WORKSPACE` Skills may be enabled by a plan but remain explicitly user-triggered.
