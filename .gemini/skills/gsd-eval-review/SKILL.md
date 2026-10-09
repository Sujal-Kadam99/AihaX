---
name: gsd-eval-review
description: "Audit an executed AI phase's evaluation coverage and produce an EVAL-REVIEW.md remediation plan."
argument-hint: "[phase number]"
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
Conduct a retroactive evaluation coverage audit of a completed AI phase.
Checks whether the evaluation strategy from AI-SPEC.md was implemented.
Produces EVAL-REVIEW.md with score, verdict, gaps, and remediation plan.
</objective>

<execution_context>
To load this command's workflow spec: check for `.claude/gsd-core/workflows/eval-review.md` relative to the current working directory first (project-local); if it is not there, fall back to `~/.claude/gsd-core/workflows/eval-review.md` (the global install). If neither file exists, stop — a workflow spec is required and none was found.
@~/.claude/gsd-core/references/ai-evals.md
</execution_context>

<context>
Phase: $ARGUMENTS — optional, defaults to last completed phase.
</context>

<process>
Execute end-to-end.
Preserve all workflow gates.
</process>
