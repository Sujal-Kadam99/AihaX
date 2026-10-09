---
name: gsd-stats
description: "Display project statistics — phases, plans, requirements, git metrics, and timeline"
allowed-tools:
  - Read
  - Bash
  - Grep
---

<objective>
Display comprehensive project statistics including phase progress, plan execution metrics, requirements completion, git history stats, and project timeline.
</objective>

<execution_context>
To load this command's workflow spec: check for `.claude/gsd-core/workflows/stats.md` relative to the current working directory first (project-local); if it is not there, fall back to `~/.claude/gsd-core/workflows/stats.md` (the global install). If neither file exists, stop — a workflow spec is required and none was found.
</execution_context>

<process>
Execute end-to-end.
</process>
