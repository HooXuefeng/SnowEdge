# Skill System

Built-in skills are stored as `skills/builtin/<slug>/SKILL.md`.

A skill contains methodology plus metadata. Execution is separated from content:

- `DETERMINISTIC`: may invoke only hard-coded Workspace capabilities.
- `AI_ANALYSIS`: may influence bounded AI analysis, but not tool permissions.
- `LOCAL_ANALYSIS`: reads local project data only.
- `MANUAL_WORKSPACE`: describes an interactive workflow requiring a human trigger.
- `KNOWLEDGE_ONLY`: imported external skills; never gain tool execution automatically.

External SKILL.md content can be pasted into Skill Hub. Imports are always `KNOWLEDGE_ONLY`.
