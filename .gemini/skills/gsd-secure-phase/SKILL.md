---
name: gsd-secure-phase
description: "Retroactively verify threat mitigations for a completed phase"
argument-hint: "[phase number]"
allowed-tools:
  - Read
  - Write
  - Edit
  - Bash
  - Glob
  - Grep
  - Agent
  - AskUserQuestion
---

<objective>
Verify threat mitigations for a completed phase. Three states:
- (A) SECURITY.md exists — audit and verify mitigations
- (B) No SECURITY.md, PLAN.md with threat model exists — run from artifacts
- (C) Phase not executed — exit with guidance

Output: updated SECURITY.md.
</objective>

<execution_context>
To load this command's workflow spec: check for `.claude/gsd-core/workflows/secure-phase.md` relative to the current working directory first (project-local); if it is not there, fall back to `~/.claude/gsd-core/workflows/secure-phase.md` (the global install). If neither file exists, stop — a workflow spec is required and none was found.
</execution_context>

<context>
Phase: $ARGUMENTS — optional, defaults to last completed phase.
</context>

<process>
Execute end-to-end.
Preserve all workflow gates.
</process>
