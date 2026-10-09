---
name: gsd-sketch
description: "Sketch UI/design ideas with throwaway HTML mockups, or propose what to sketch next (frontier mode)"
argument-hint: "[design idea to explore] [--quick] [--text] [--wrap-up] or [frontier]"
allowed-tools:
  - Read
  - Write
  - Edit
  - Bash
  - Grep
  - Glob
  - AskUserQuestion
  - WebSearch
  - WebFetch
  - mcp__context7__resolve-library-id
  - mcp__context7__query-docs
---

<objective>
Explore design directions through throwaway HTML mockups before committing to implementation.
Each sketch produces 2-3 variants for comparison. Sketches live in `.planning/sketches/` and
integrate with GSD commit patterns, state tracking, and handoff workflows. Loads spike
findings to ground mockups in real data shapes and validated interaction patterns.

Two modes:
- **Idea mode** (default) — describe a design idea to sketch
- **Frontier mode** (no argument or "frontier") — analyzes existing sketch landscape and proposes consistency and frontier sketches

Does not require prior new-project setup — auto-creates `.planning/sketches/` if needed.
</objective>

<execution_context>
To load this command's workflow spec: check for `.claude/gsd-core/workflows/sketch.md` relative to the current working directory first (project-local); if it is not there, fall back to `~/.claude/gsd-core/workflows/sketch.md` (the global install). If neither file exists, stop — a workflow spec is required and none was found.
To load this command's workflow spec: check for `.claude/gsd-core/workflows/sketch-wrap-up.md` relative to the current working directory first (project-local); if it is not there, fall back to `~/.claude/gsd-core/workflows/sketch-wrap-up.md` (the global install). If neither file exists, stop — a workflow spec is required and none was found.
@~/.claude/gsd-core/references/ui-brand.md
@~/.claude/gsd-core/references/sketch-theme-system.md
@~/.claude/gsd-core/references/sketch-interactivity.md
@~/.claude/gsd-core/references/sketch-tooling.md
@~/.claude/gsd-core/references/sketch-variant-patterns.md
</execution_context>



<context>
Design idea: $ARGUMENTS

**Available flags:**
- `--quick` — Skip mood/direction intake, jump straight to decomposition and building. Use when the design direction is already clear.
- `--wrap-up` — Package sketch design findings into a persistent project skill for future build conversations. Runs the sketch-wrap-up workflow.
</context>

<process>
Parse the first token of $ARGUMENTS:
- If it is `--wrap-up`: strip the flag, execute the sketch-wrap-up workflow end-to-end.
- Otherwise: execute the sketch workflow end-to-end.

Preserve all workflow gates (intake, decomposition, target stack research, variant evaluation, MANIFEST updates, commit patterns).
</process>
