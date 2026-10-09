---
name: gsd-resume-work
description: "Resume work from previous session with full context restoration"
allowed-tools:
  - Read
  - Bash
  - Grep
  - Write
  - AskUserQuestion
  - SlashCommand
---


<objective>
Restore complete project context and resume work seamlessly from previous session.

Routes to the resume-project workflow which handles:

- STATE.md loading (or reconstruction if missing)
- Checkpoint detection (.continue-here files)
- Incomplete work detection (PLAN without SUMMARY)
- Status presentation
- Context-aware next action routing
  </objective>

<execution_context>
To load this command's workflow spec: check for `.claude/gsd-core/workflows/resume-project.md` relative to the current working directory first (project-local); if it is not there, fall back to `~/.claude/gsd-core/workflows/resume-project.md` (the global install). If neither file exists, stop — a workflow spec is required and none was found.
</execution_context>

<process>
Execute end-to-end.
</process>
