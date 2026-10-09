---
name: gsd-onboard
description: "Guide existing codebase onboarding through mapping, doc ingest, and planning setup"
argument-hint: "[--fast] [--text]"
allowed-tools:
  - Read
  - Bash
  - Write
  - Glob
  - Grep
  - Agent
  - AskUserQuestion
---



<objective>
Guide brownfield onboarding for an existing codebase by routing through the existing GSD primitives in the safe order: codebase map → docs ingest → project initialization → onboarding summary.

**Creates or confirms:**
- `.planning/codebase/` — evidence-backed codebase map from `/gsd-map-codebase`
- `.planning/PROJECT.md`, `REQUIREMENTS.md`, `ROADMAP.md`, `STATE.md` — project setup from `/gsd-new-project` or `/gsd-ingest-docs`
- `.planning/onboarding/SUMMARY.md` — lightweight index of what was learned and the next command

**Non-goals:** This command does not execute phases, ship work, or overwrite existing planning artifacts without an explicit gate.
</objective>

<execution_context>
To load this command's workflow spec: check for `.claude/gsd-core/workflows/onboard.md` relative to the current working directory first (project-local); if it is not there, fall back to `~/.claude/gsd-core/workflows/onboard.md` (the global install). If neither file exists, stop — a workflow spec is required and none was found.
@~/.claude/gsd-core/references/ui-brand.md
@~/.claude/gsd-core/references/gate-prompts.md
</execution_context>

<context>
Arguments: $ARGUMENTS

Flags:
- `--fast` — prefer `/gsd-map-codebase --fast` for the mapping handoff; the complete map is still required before `/gsd-new-project`.
- `--text` — use plain-text numbered lists instead of TUI menus.
</context>

<process>
Execute the onboard workflow end-to-end. Preserve all safety gates, text-mode fallbacks, idempotency checks, and top-level handoff rules for nested interactive commands.
</process>
