---
name: gsd-next
description: "Smart entry — detect project state and route to the right next GSD action."
allowed-tools:
  - Read
  - Bash
  - Glob
  - Grep
  - SlashCommand
  - AskUserQuestion
---

<objective>
GSD smart entry — the state-aware front door. Detect what's going on in this project, then present a short menu of the right next actions and dispatch to one.

This is a launcher/router only. It never does the work itself. It reads project + workflow state via `gsd-tools smart-entry --json`, shows a situation-appropriate menu, and hands off to an existing GSD command.
</objective>

<execution_context>
To load this command's workflow spec: check for `.claude/gsd-core/workflows/smart-entry.md` relative to the current working directory first (project-local); if it is not there, fall back to `~/.claude/gsd-core/workflows/smart-entry.md` (the global install). If neither file exists, stop — a workflow spec is required and none was found.
@~/.claude/gsd-core/references/ui-brand.md
</execution_context>

<context>
Arguments: $ARGUMENTS
</context>

<process>
Follow $HOME/.claude/gsd-core/workflows/smart-entry.md. Detect the situation, present the menu, and dispatch exactly one command. Then stop.
</process>
