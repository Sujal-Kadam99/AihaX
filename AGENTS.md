# Repository guidance

- Read the relevant code and tests before editing; keep changes focused and reuse existing helpers.
- Run security checks only against explicitly authorized targets. Do not run live-target or production workflows without explicit authorization.
- Never commit `.env`, credentials, generated scan data, installers, or downloaded tool binaries.
- Backend: `uv sync --locked --project backend --group dev`, then `uv run --locked --project backend pytest backend/tests`; lint with `uv run --locked --project backend ruff check backend`.
- Frontend: from `frontend/`, run `npm test`, `npm run lint`, and `npm run build`.
- Electron: from `electron/`, run `npm test`.
- Report checks that were skipped and preserve failing tests as evidence; do not weaken tests to make a change pass.
