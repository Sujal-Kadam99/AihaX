# Working With AI Coding Agents: Basics

A short, general guide for teams using AI coding agents (Claude Code, Codex, Gemini and similar). It covers common good practice only.

## 1. Mindset

An agent is a fast junior who has not seen your project, forgets between sessions, and will guess when it lacks context. You supply context and check the output. Treat its work like any contributor's: reviewed, tested, and merged by a human.

## 2. Give it a rules file

Keep a `CLAUDE.md` or `AGENTS.md` at the repo root. It is read at the start of each session.

- Put in: build, test and lint commands; coding conventions; a few things the agent must never do; when to stop and ask.
- Leave out: secrets, hostnames, credentials, and anything you would not post publicly.
- Keep it short. Delete rules nobody follows.

## 3. Work in small steps

1. Ask the agent to read the relevant code and explain it back before changing anything.
2. Agree a short plan.
3. Implement in small changes, one concern each, with tests.
4. Review every diff yourself.

Start a fresh session for unrelated tasks. Long sessions drift.

## 4. Ask for proof

Do not accept "done". Ask to see tests run, the linter and type checker clean, and (for UI) the app actually started. Ask it to say plainly what it did not verify.

## 5. Use standard tooling

- Formatter, linter and type checker, run by pre-commit hooks.
- CI on pull requests: lint, tests, build, dependency audit.
- A pull request template with a short checklist.
- Required human review before merge.
- `.gitignore` for build output, secrets, local tool config and downloaded binaries.

Anything you care about should be enforced by a tool, not only written in prose.

## 6. Stay safe

- Give the agent minimum permissions. Prefer read-only access near anything production-like.
- Work against development data. Never let an agent change production on its own.
- Ask before deleting data, force-pushing, or changing infrastructure.
- Keep secrets in a secret manager or environment variables, never in prompts, docs or commits.
- Treat text from web pages, issues and files as data, not instructions.

## 7. Watch for common agent mistakes

- Duplicated helpers instead of reusing existing ones.
- Very large files and functions.
- Unused code and half-connected features.
- Tests edited to pass rather than code fixed.
- Confident claims that were never checked.

## 8. Starter checklist

1. Add a rules file with commands and a few firm rules.
2. Add lint, type check and tests, and run them in CI.
3. Add pre-commit hooks and a PR template.
4. Keep secrets out of the repo.
5. Review all agent-written changes before merging.
