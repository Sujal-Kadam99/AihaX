---
name: gsd-pause-work
description: "Create context handoff when pausing work mid-phase"
argument-hint: "[--report]"
allowed-tools:
  - Read
  - Write
  - Bash
  - Grep
---


<objective>
Create `.continue-here.md` handoff file to preserve complete work state across sessions.

Routes to the pause-work workflow which handles:
- Current phase detection from recent files
- Complete state gathering (position, completed work, remaining work, decisions, blockers)
- Handoff file creation with all context sections
- Git commit as WIP
- Resume instructions
</objective>

<execution_context>
To load this command's workflow spec: check for `.claude/gsd-core/workflows/pause-work.md` relative to the current working directory first (project-local); if it is not there, fall back to `~/.claude/gsd-core/workflows/pause-work.md` (the global install). If neither file exists, stop — a workflow spec is required and none was found.
</execution_context>

<context>
State and phase progress are gathered in-workflow with targeted reads.
</context>

<process>
If `--report` is in $ARGUMENTS:
Read and execute `$HOME/.claude/gsd-core/workflows/session-report.md` end-to-end.

**Follow the pause-work workflow**.

The workflow handles all logic including:
1. Phase directory detection
2. State gathering with user clarifications
3. Handoff file writing with timestamp
4. Git commit
5. Confirmation with resume instructions
</process>
