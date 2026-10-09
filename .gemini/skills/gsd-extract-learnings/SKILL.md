---
name: gsd-extract-learnings
description: "Extract decisions, lessons, patterns, and surprises from completed phase artifacts"
argument-hint: "<phase-number>"
allowed-tools:
  - Read
  - Write
  - Bash
  - Grep
  - Glob
  - Agent
---

<objective>
Extract structured learnings from completed phase artifacts (PLAN.md, SUMMARY.md, VERIFICATION.md, UAT.md, STATE.md) into a LEARNINGS.md file that captures decisions, lessons learned, patterns discovered, and surprises encountered.
</objective>

<execution_context>
To load this command's workflow spec: check for `.claude/gsd-core/workflows/extract-learnings.md` relative to the current working directory first (project-local); if it is not there, fall back to `~/.claude/gsd-core/workflows/extract-learnings.md` (the global install). If neither file exists, stop — a workflow spec is required and none was found.
</execution_context>

Execute the extract-learnings workflow from @~/.claude/gsd-core/workflows/extract-learnings.md end-to-end.
