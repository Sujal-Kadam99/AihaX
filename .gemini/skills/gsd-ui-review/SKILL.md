---
name: gsd-ui-review
description: "Retroactive 6-pillar visual audit of implemented frontend code"
argument-hint: "[phase]"
allowed-tools:
  - Read
  - Write
  - Bash
  - Glob
  - Grep
  - Agent
  - AskUserQuestion
---

<objective>
Conduct a retroactive 6-pillar visual audit. Produces UI-REVIEW.md with
graded assessment (1-4 per pillar). Works on any project.
Output: {phase_num}-UI-REVIEW.md
</objective>

<execution_context>
To load this command's workflow spec: check for `.claude/gsd-core/workflows/ui-review.md` relative to the current working directory first (project-local); if it is not there, fall back to `~/.claude/gsd-core/workflows/ui-review.md` (the global install). If neither file exists, stop — a workflow spec is required and none was found.
@~/.claude/gsd-core/references/ui-brand.md
</execution_context>

<context>
Phase: $ARGUMENTS — optional, defaults to last completed phase.
</context>

<process>
Execute end-to-end.
Preserve all workflow gates.
</process>
