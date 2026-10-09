---
name: gsd-help
description: "Show available GSD commands and usage guide"
argument-hint: "[--brief | --full | <topic> | --brief <topic>]"
allowed-tools:
  - Read
---

<objective>
Display GSD help at the tier the user asked for: brief (one-line refresher), default (one-page tour), full (complete reference), a single topic section, or a compact scoped lookup of one topic (`--brief <topic>`: signature + one-line summary).

Output ONLY the reference content of the chosen tier. Do NOT add:
- Project-specific analysis
- Git status or file context
- Next-step suggestions
- Any commentary beyond the reference
</objective>

<execution_context>
To load this command's workflow spec: check for `.claude/gsd-core/workflows/help.md` relative to the current working directory first (project-local); if it is not there, fall back to `~/.claude/gsd-core/workflows/help.md` (the global install). If neither file exists, stop — a workflow spec is required and none was found.
</execution_context>

<context>
Arguments: $ARGUMENTS
</context>

<process>
Follow $HOME/.claude/gsd-core/workflows/help.md with $ARGUMENTS.
</process>
