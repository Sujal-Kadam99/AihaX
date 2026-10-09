# AihaX Codebase Judgement Report

Reviewed against the bar of a mature, well-gated production monorepo.

## Scope and limits

- Reviewed: repo layout and hygiene, `backend/` (structure, security grep checks, size), `frontend/` and `electron/` (full read-through by a reviewer agent), design tokens and styling usage.
- Not done: no tests, ruff, mypy or lint were run. `node_modules` is absent, so the frontend was never built. Nothing was executed, so "likely broken" below means "broken by reading the code", not "observed failing".
- The backend was reviewed by targeted greps and file-size checks only, not line by line.
- "AI-generated" is an inference from evidence listed in section 3, not a fact.

## 1. Verdict

A serious but unfinished prototype. The backend security design is better than average. The product around it does not work end to end, the repo has no engineering process, and the codebase carries the marks of unsupervised AI generation: huge files, phase-audit document dumps, vendored agent plugins and dead code.

It is not ready to ship, and it is not something a team could safely extend as it stands.

| Area | Grade | One-line reason |
|---|---|---|
| Backend security design | B | Global auth, no-shell execution, scope validator, prod guard on mock auth |
| Backend maintainability | D | 2000+ line modules, hand-rolled migrations, unpinned deps, 1556 lint violations |
| Frontend correctness | F | Packaged app likely renders blank, login is mock only, routes unprotected |
| Electron security | C | Good updater and OAuth design, but missing sandbox, navigation guards and IPC validation |
| Design system | D | Tokens exist but are bypassed almost everywhere |
| Repo hygiene | F | 1949 vendored files, binaries, root clutter, no CI, no hooks |
| Process | F | A mature project gates changes with CI, hooks, a PR template and security docs. AihaX has none |

## 2. What is actually good

- `backend/main.py:75-95`: one middleware enforces auth and rate limiting on every request, so no router is accidentally open.
- `backend/execution/tool_execution_boundary.py`: tools run through `create_subprocess_exec` with no shell.
- `backend/core/scope_validator.py`: blocks private, reserved and multicast ranges before scanning.
- `backend/core/auth.py:204` and `core/config.py:82`: `DEV_MOCK_AUTH` is refused in production.
- `electron/update-policy.js` and `electron-builder.config.js`: HTTPS-only feed, publisher allowlist, no downgrade, release builds refuse to run without signing.
- `electron/oauth.js`: correct PKCE flow with S256, state check, loopback on a random port, timeout, refresh token encrypted with `safeStorage`.
- 121 backend test files for 282 source files.

These show the author knew what good looks like. The failure is in finishing and in process, not in knowledge.

## 3. Why it reads as unsupervised AI output

- `.agents/plugins/superpowers/` (a whole third-party plugin with its own `.github/`), `.gemini/` and `.kilo/` are committed. Agent tooling leaked into the product repo.
- `docs/` has 141 files, mostly `*_phase*_audit.md` and `*_walkthrough.md`. These are session transcripts turned into files, with no index and no owner.
- Root contains `AihaX_Description_Oct_7_2026.md`, `dist-list.txt` (56 KB), `dist-installers.txt`, `ruff_baseline.txt` (63 KB), scan result JSONs, screenshots and seven one-off scripts.
- Modules grew by accretion: `verification_engine.py` 2206 lines, `routers/campaigns.py` 2197 lines with 60 routes, `live_recon_validator.py` 2131, `Campaigns.jsx` 1008.
- Features were written but never connected: real OAuth is never called, `ProtectedRoute` is used by no route, `onDeepLink` has no consumer, `tray.js:70` references a property that does not exist.
- 73 empty `.catch(() => {})` blocks in the frontend.
- Comments and docstrings that assert rules (for example "Zero Shell/Subprocess") with a certification script (`recon/phase27_certification.py`) that greps for them. This is process theatre: a rule checked by a custom script instead of by ruff's `S` rules and a CI job.

## 4. Critical defects (fix first)

1. **Blank app when packaged.** `frontend/src/App.jsx:1,27` uses `BrowserRouter`, but Electron loads `file://.../index.html` (`electron/main.js:146`). No route matches. Fix: `HashRouter`.
2. **Login is fake.** `components/auth/LoginModal.jsx:18` only calls `loginWithMock`. The real `window.aihax.startOAuth` is never called. The only protection is the backend `DEV_MOCK_AUTH` gate. Fix: branch on `window.aihax?.startOAuth`, and compile the mock out of non-dev builds.
3. **Routes unprotected.** `ProtectedRoute` is used only by tests. Every page is reachable without login.
4. **Token plumbing broken.** `context/AuthContext.jsx:70,108` uses a relative `fetch('/api/...')`, which is `file:///api/...` when packaged. It bypasses `lib/api.js`. The access token is never attached to requests. The refresh token is never used.
5. **Electron hardening gaps.** `main.js` has no `sandbox: true`, no `setWindowOpenHandler`, no `will-navigate` guard, and a CSP with `unsafe-eval`. `open-folder` (`main.js:267-270`) passes an unchecked renderer string to `shell.openPath`. `googleClientId` comes from the renderer (`main.js:333`, `oauth.js:153`). `spawn`/`exec` use `shell: true` (`main.js:70,256`).
6. **Repo carries 1949 vendored files.** `bin/tools` holds `subfinder.exe`, `naabu.exe` (about 29 MB each), `dalfox.exe` (25 MB), `gau.exe`, `gobuster.exe` and a full WhatWeb checkout. Also tracked: `downloads/AiHaX-Setup-1.0.0.exe` and an unrelated `downloads/sujal-portfolio/`.

## 5. Design system

### What exists

`tailwind.config.js` defines a decent semantic token layer: `background`, `surface`, `surface-2`, `border`, `accent`, `text-primary/secondary/muted`, plus severity pairs (`critical`, `high`, `medium`, `low`, `info`, `warning`, `success` each with a `-bg`). They map to CSS variables. `src/components/ui/` has 15 primitives (Alert, Badge, Button, Card, Drawer, EmptyState, ErrorBoundary, Input, Modal, Progress, Select, Skeleton, Table, Tabs, Toast).



The tokens exist and are ignored. Counting utility classes in `frontend/src`:

| Pattern | Count |
|---|---|
| raw `slate-*` classes | 365 |
| raw `emerald-*` | 204 |
| raw `zinc-*` | 178 |
| raw `amber-*` | 120 |
| raw `cyan-*` | 95 |
| raw `indigo-*` | 48 |
| arbitrary `bg/text/border-[#hex]` | 78 |
| distinct hardcoded hex values in JSX | 28 |
| files with inline `style={{}}` | 20 |

Consequences:

- **Two grey scales in one UI.** `slate` (365) and `zinc` (178) are both used for neutrals. They differ in hue, so panels never quite match.
- **Severity colours are not centralised.** Components use `emerald`, `amber`, `cyan`, `indigo` directly instead of `success`, `warning`, `info`. A theme change or a light mode means editing hundreds of call sites.
- **Hex literals** like `#22d3ee`, `#f87171`, `#7d8590`, `#30363d` and `#0d1117` are scattered through components. These are the GitHub-dark palette pasted in by hand next to a different token set.
- `darkMode: 'class'` is configured but there is only one theme. The tokens could support light mode, but raw palette classes would break it.
- **Primitives are not enforced.** The big pages (`Campaigns.jsx` 1008 lines, `NewAssessment.jsx` 825) build their own markup. `alert()` is used for errors in `ValidationQueue.jsx` even though `Toast.jsx` exists.
- **Primitive bugs.** `Modal.jsx` has no focus trap or focus restore. Its `aria-labelledby` uses the fixed id `modal-title`, so two modals collide. `LoginModal` passes `size="sm"` but `Modal` expects `maxWidth`. `@axe-core/react` is installed but unused in tests.
- **Fonts.** Display font is JetBrains Mono for everything labelled `display`, loaded from Google Fonts (`index.html:20-22`) in a desktop app. That fails offline and conflicts with the CSP.
- **Loose scale.** Radii are 2/6/6/10 px with no spacing, type-size or elevation scale defined. `surface-1` duplicates `surface`.

### How to fix it

1. **Freeze the palette.** Pick one neutral (slate or zinc, not both). Define in CSS variables: neutrals 0-950, one accent, the seven status colours, a type scale (12/14/16/20/24/32), a spacing scale (4px base), radii (4/8/12) and three elevations.
2. **Lock the tokens in.** Add a Tailwind config that removes the default colour palette (`theme.colors` instead of `theme.extend.colors`), so `slate-400` and `bg-[#...]` fail to compile or lint. Add the ESLint rule `tailwindcss/no-arbitrary-value` and `tailwindcss/no-custom-classname`, or a stylelint equivalent.
3. **Codemod the 1100 call sites.** Script the mapping `slate-*/zinc-*` to `surface/border/text-*`, `emerald` to `success`, `amber` to `warning`/`medium`, `cyan` to `info`/`accent`, `indigo` to `accent`. Run per page and review visually.
4. **Make primitives the only way.** Add `Stat`, `PageHeader`, `DataTable`, `FormField` and `Severity` components. Ban raw `<button>`, `<input>` and `<select>` in pages with the `react/forbid-elements` rule. Replace every `alert()` with `Toast`.
5. **Fix the primitives properly.** Focus trap and restore, unique ids from `useId`, consistent prop names, keyboard support in `Tabs` and `Select`, and automated axe checks in the test suite.
6. **Self-host fonts** with `@fontsource/inter` and `@fontsource/jetbrains-mono`, and reserve mono for code, ids and terminals, not headings.
7. **Document it.** A single `docs/DESIGN_SYSTEM.md` with the token table, component list and a "do not" section. Optionally add Storybook so each primitive is visible in every state (default, hover, disabled, error, loading).
8. **Decide on light mode.** Either support it through the tokens or delete `darkMode: 'class'`.

## 6. Improvement plan

### Week 1: stop the bleeding
- `git rm -r --cached bin/tools .agents .gemini .kilo downloads` and add them to `.gitignore`. Put tools in a `scripts/fetch-tools` step with pinned versions and SHA-256 checks. Consider rewriting history (for example with `git filter-repo`) to drop about 100 MB of binaries.
- Move or delete the seven root scripts, screenshots, JSON results and `dist-*.txt`. Move one-off scan runners into `scripts/dev/` or delete them.
- Switch to `HashRouter`, wire real OAuth, apply `ProtectedRoute`, route all calls through `lib/api.js` with token and refresh handling.
- Electron: `sandbox: true`, navigation and window-open guards, path allowlist for `open-folder`, `execFile` instead of `shell: true`, read client id from main-process config, remove `unsafe-eval`.
- Add `USER` and a pinned base image to `docker/Dockerfile`.

### Weeks 2-3: gates
- Add `.github/workflows/ci.yml`: ruff, mypy, pytest, `npm test`, `npm run lint`, Electron update-policy test, `npm audit`.
- Add pre-commit (ruff, secret scan, large-file check) and a PR template.
- Pin backend dependencies and generate a lockfile (`uv lock` or `pip-compile`). Fix `uv.lock`, which is 55 bytes.
- Drive `ruff_baseline.txt` (1556 findings) to zero, then delete the file and make ruff a required check. Turn on the `S` (bandit) rules to replace `phase27_certification.py`.
- Replace `models/migrations.py` with Alembic.

### Month 2: structure
- Split `routers/campaigns.py` into a package by resource (campaigns, workspaces, recon, evidence). Each router file stays under about 400 lines. Do the same for `verification_engine.py`, `live_recon_validator.py` and `campaign_operations.py`.
- Move authorization (org and tenant scope) into per-router dependencies, and keep the global middleware only as a backstop. Add tests that every route either appears on the public allowlist or returns 401.
- Frontend: add TypeScript (or `// @ts-check` plus JSDoc as a stepping stone), TanStack Query for fetching, one error and loading pattern, and split pages over about 400 lines into feature folders.
- Consolidate `docs/`: keep an architecture doc, a security doc, a runbook and ADRs (`docs/DECISIONS.md` is a good start). Move `*_phaseN_audit.md` files into `docs/archive/` or delete them. Add a `docs/README.md` index.

### Ongoing
- One owner per area (`CODEOWNERS`).
- No agent tooling in the product repo. Keep it in a user-level config.
- Review every AI-generated change as if it came from a junior who never runs the code: tests required, file-size limit enforced in CI, no unused code merged.

## 7. Bottom line

The author can build thoughtful security-conscious backend code, but the project has been grown by generation rather than engineered. The fastest path to a credible product is not new features. It is: clean the repo, make the shipped app actually start and log in, put CI in front of everything, and enforce the design tokens and file-size limits by tooling rather than by hope.
