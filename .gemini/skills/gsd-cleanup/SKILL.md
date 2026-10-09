---
name: gsd-cleanup
description: "Archive accumulated phase directories from completed milestones"
allowed-tools:
  - Read
  - Write
  - Bash
  - Grep
  - AskUserQuestion
---

<objective>
Archive phase directories from completed milestones into `.planning/milestones/v{X.Y}-phases/`.

Use when `.planning/phases/` has accumulated directories from past milestones.
</objective>

<execution_context>
To load this command's workflow spec: check for `.claude/gsd-core/workflows/cleanup.md` relative to the current working directory first (project-local); if it is not there, fall back to `~/.claude/gsd-core/workflows/cleanup.md` (the global install). If neither file exists, stop — a workflow spec is required and none was found.
</execution_context>

<process>
Execute end-to-end.
Identify completed milestones, show a dry-run summary, and archive on confirmation.
</process>
