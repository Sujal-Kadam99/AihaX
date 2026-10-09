---
name: gsd-ship
description: "Create PR, run review, and prepare for merge after verification passes"
argument-hint: "[phase number or milestone, e.g., '4' or 'v1.0']"
allowed-tools:
  - Read
  - Bash
  - Grep
  - Glob
  - Write
  - AskUserQuestion
---

<objective>
Bridge local completion → merged PR. After /gsd-verify-work passes, ship the work: push branch, create PR with auto-generated body, optionally trigger review, and track the merge.

Closes the plan → execute → verify → ship loop.
</objective>

<execution_context>
To load this command's workflow spec: check for `.claude/gsd-core/workflows/ship.md` relative to the current working directory first (project-local); if it is not there, fall back to `~/.claude/gsd-core/workflows/ship.md` (the global install). If neither file exists, stop — a workflow spec is required and none was found.
</execution_context>

Execute the ship workflow from @~/.claude/gsd-core/workflows/ship.md end-to-end.
