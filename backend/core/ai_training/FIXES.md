# AihaX FIXES

Ordered fix list for `C:\D_Drive\Code\AihaX`, from the review in `AihaX_JUDGEMENT_REPORT.md`. Nothing here has been applied. Paths and line numbers come from reading the code; no tests, lint or builds were run.

Effort: S = under 1 hour, M = under 1 day, L = several days.

## P0: the product does not work

- [ ] **Blank packaged app (S).** `frontend/src/App.jsx:1,27`: replace `BrowserRouter` with `HashRouter`. Electron loads `file://` (`electron/main.js:146`).
- [ ] **Real login (M).** `frontend/src/components/auth/LoginModal.jsx:18` only calls `loginWithMock`. Call `window.aihax.startOAuth` when it exists; keep the mock behind `import.meta.env.DEV`.
- [ ] **Protect routes (S).** Wrap routes in `ProtectedRoute` in `App.jsx:36-62`. It is currently used only in tests.
- [ ] **Token plumbing (M).** `frontend/src/context/AuthContext.jsx:70,108`: use `lib/api.js` instead of relative `fetch`. Add an axios request interceptor that sets `Authorization`, and a 401 handler that refreshes the token. `lib/api.js:26-39` sends only `X-AihaX-Token`.
- [ ] **Hardcoded URLs (S).** `localhost:8000` appears in `lib/api.js:4,14` and `lib/socket.js:1,11`. Move to `import.meta.env.VITE_API_URL` with one shared constant.

## P0: Electron security (`electron/main.js`)

- [ ] `webPreferences.sandbox: true` (S).
- [ ] Add `setWindowOpenHandler(() => ({ action: 'deny' }))` and a `will-navigate` guard that blocks anything off the app origin (S).
- [ ] CSP: remove `unsafe-eval`; register the header hook once, not inside `createWindow`; also set a CSP `<meta>` in `frontend/index.html` (M).
- [ ] `open-folder` (`main.js:267-270`): only allow paths under the app's own data directory (S).
- [ ] `googleClientId` (`main.js:333`, `oauth.js:153`): read from main-process config, not from the renderer, and build the URL with `URLSearchParams` (S).
- [ ] `spawn`/`exec` with `shell: true` (`main.js:70,256`): use `execFile` with an argument array (S).
- [ ] `before-quit`: `event.preventDefault()`, await `docker compose down`, then quit (S).
- [ ] Deep links (`main.js:236-246`, `preload.js:15`): validate scheme and path allowlist in main; return an unsubscribe function from `onDeepLink` (S).
- [ ] Check `senderFrame.url` in each IPC handler (M).
- [ ] `electron/package.json:21`: `files: ["**/*"]` ships `test/` and `scripts/`. Narrow it. Upgrade Electron (^28 is end of life) (M).
- [ ] `electron-builder.config.js:7`: make unsigned builds fail loudly or label them dev (S).

## P0: repo cleanup

Run from `C:\D_Drive\Code\AihaX`. Review `git status` before committing.

```bash
git rm -r --cached bin/tools .agents .gemini .kilo downloads
printf '%s\n' 'bin/tools/' '.agents/' '.gemini/' '.kilo/' 'downloads/' >> .gitignore
git rm --cached frontend_*.png scan_results.json dvwa_scan_results.json dist-list.txt dist-installers.txt
```

- [ ] Add a `scripts/fetch-tools` step (pinned versions plus SHA-256) so the tools in `bin/tools` can be downloaded instead of committed (M).
- [ ] Move or delete root one-offs: `check_logs.py`, `fetch_vulns.py`, `run_dvwa_scan*.py`, `run_juice_shop_scan*.py`, `test_post.py`, `test_report.py`, `test_sqli_dvwa.py`. Put keepers under `scripts/dev/` (S).
- [ ] Delete the unrelated `downloads/sujal-portfolio/` and the tracked `AiHaX-Setup-1.0.0.exe` (S).
- [ ] Optional: drop the binaries from history with `git filter-repo` (about 100 MB). Rewriting history needs a team decision and a force-push, so do it only with agreement (M).

## P1: process gates

- [ ] `.github/workflows/ci.yml`: `ruff check`, `mypy`, `pytest`, frontend `npm test` and `npm run lint`, `electron` update-policy test, `npm audit` (M).
- [ ] `.pre-commit-config.yaml`: ruff, ruff-format, detect-secrets, check-added-large-files (S).
- [ ] `.github/pull_request_template.md` with checklist: tests, docs, security, no secrets (S).
- [ ] Pin `backend/requirements.txt` (24 entries are `>=`). Generate a lockfile with `uv lock` or `pip-compile`. `uv.lock` is currently 55 bytes (S).
- [ ] Drive `ruff_baseline.txt` (1556 findings, mostly F401) to zero with `ruff check --fix backend`, then delete the baseline and make ruff required (M).
- [ ] Enable ruff `S` (bandit) rules in `pyproject.toml`, then retire `backend/recon/phase27_certification.py`, which greps for `shell=True` by hand (M).
- [ ] `docker/Dockerfile`: pin the base image digest and add a non-root `USER` (S).
- [ ] `frontend/vite.config.js:13`: bind the dev server to `localhost` (S).

## P1: backend structure

- [ ] Split `backend/routers/campaigns.py` (2197 lines, 60 routes) into a package by resource. Target under 400 lines per file (L).
- [ ] Split `services/verification_engine.py` (2206), `recon/live_recon_validator.py` (2131), `services/campaign_operations.py` (1890), `services/exploit_validator.py` (1472) (L).
- [ ] Replace hand-rolled `models/migrations.py` (1513 lines) with Alembic (L).
- [ ] Add per-router `Depends` for authorization (organization and tenant scope) in addition to the global middleware in `main.py:75-95` (M).
- [ ] Add a test that fails if any route is neither on the public allowlist nor returns 401 without a token (M).
- [ ] Move the inline imports out of `auth_middleware` in `main.py` (S).
- [ ] Check `backend/agents/checks/c017_session_fixation.py` and `backend/tests/test_billing_checkout.py`, which match a secret regex. Likely fixtures, but confirm (S).

## P2: frontend quality

- [ ] Replace 73 empty `.catch(() => {})` blocks with a shared error handler that shows a Toast (M).
- [ ] Replace `alert()` in `ValidationQueue.jsx:69,89` and `RealWorldValidationQueue.jsx:64,80,113` with `Toast` (S).
- [ ] Add TanStack Query for the 31 files that fetch in `useEffect`, and the 3 that poll with `setInterval` (L).
- [ ] Split pages: `Campaigns.jsx` (1008), `NewAssessment.jsx` (825), `FindingDetail.jsx` (536), `Evidence.jsx` (532) (L).
- [ ] Type safety: add `tsconfig.json` and move to TypeScript, or start with `// @ts-check` plus JSDoc (L).
- [ ] `frontend/.eslintrc.json`: re-enable the `react-hooks` rules and remove the reference to the uninstalled `react-compiler` rule (S).
- [ ] Dead code: `electron/tray.js:70` (`tray.ContextMenu` does not exist), the unused `express`, `nedb` and `body-parser` in the root `package.json`, and the stale `download.html` links (S).
- [ ] Tests for `electron/main.js`, `oauth.js`, `preload.js`, `updater.js`, and wire `test:update` into CI (M).

## P2: design system

Current state: tokens exist in `frontend/tailwind.config.js` but pages bypass them (365 `slate-*`, 178 `zinc-*`, 204 `emerald-*`, 120 `amber-*`, 95 `cyan-*`, 48 `indigo-*`, 78 arbitrary hex classes, 28 distinct hex literals, 20 files with inline `style`).

- [ ] Choose one neutral scale (slate or zinc) and define it, a type scale, a 4px spacing scale, radii and elevations as CSS variables (M).
- [ ] Switch `theme.extend.colors` to `theme.colors` so raw palette classes stop compiling. Remove the duplicate `surface-1` token (S).
- [ ] Add ESLint rules `tailwindcss/no-arbitrary-value` and `react/forbid-elements` (for `button`, `input`, `select`) (S).
- [ ] Codemod by mapping: `slate`/`zinc` to `surface`, `border`, `text-*`; `emerald` to `success`; `amber` to `warning` or `medium`; `cyan` and `indigo` to `info` or `accent`. Do one page per PR and compare screenshots (L).
- [ ] `ui/Modal.jsx`: focus trap and focus restore; `useId()` for `aria-labelledby`; accept `size` or fix the `LoginModal` prop (`maxWidth`) (M).
- [ ] Add missing primitives (`Stat`, `PageHeader`, `DataTable`, `FormField`) and use them in the big pages (L).
- [ ] Use `@axe-core/react` (already a devDependency) in component tests (S).
- [ ] Self-host fonts with `@fontsource/inter` and `@fontsource/jetbrains-mono`. Remove the Google Fonts links in `frontend/index.html:20-22`. Use mono for code and ids only (S).
- [ ] Decide on light mode: support it through the tokens, or delete `darkMode: 'class'` (S).
- [ ] Write `docs/DESIGN_SYSTEM.md` with token table and component list (S).

## P2: docs

- [ ] `docs/` has 141 files. Move `*_phase*_audit.md` and `*_walkthrough.md` to `docs/archive/` or delete them (S).
- [ ] Add `docs/README.md` as an index; keep architecture, security, runbook and `DECISIONS.md` (M).
- [ ] Remove `AihaX_Description_Oct_7_2026.md` from the root or merge it into `README.md` (S).

## Suggested order

1. Repo cleanup and `.gitignore` (an hour).
2. `HashRouter`, real login, `ProtectedRoute`, token plumbing.
3. Electron hardening list.
4. CI, pre-commit, pinned dependencies.
5. Ruff to zero and the `S` rules.
6. Backend splits and Alembic.
7. Design-system lock-in and codemod.
8. Frontend data layer and TypeScript.
