---
name: gsd-audit-uat
description: "Cross-phase audit of all outstanding UAT and verification items"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Bash
---

<objective>
Scan all phases for pending, skipped, blocked, and human_needed UAT items. Cross-reference against codebase to detect stale documentation. Produce prioritized human test plan.
</objective>

<execution_context>
To load this command's workflow spec: check for `.claude/gsd-core/workflows/audit-uat.md` relative to the current working directory first (project-local); if it is not there, fall back to `~/.claude/gsd-core/workflows/audit-uat.md` (the global install). If neither file exists, stop — a workflow spec is required and none was found.
</execution_context>

<context>
Core planning files are loaded in-workflow via CLI.

**Scope:**
Glob: .planning/phases/*/*-UAT.md
Glob: .planning/phases/*/*-VERIFICATION.md
</context>
