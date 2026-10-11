# AihaX Security Bugs

Source: read-only code review of AihaX `master` `dfb5dd6`, 2026-10-11, measured against the NCS ERP security bar (`SECURITY.md`, `CLAUDE.md`, `docs/BACKEND_SECURITY.md`). Companion to [SCOPE_AND_OPEN_QUESTIONS.md](SCOPE_AND_OPEN_QUESTIONS.md), which holds the product scope, the reliability findings and the questions for the author.

**Status key.** Verified: the code path was read end to end. Suspected: inferred from the code, not traced or exploited. Nothing here was exploited and no live endpoint was called.

Scan counts: Bandit (non-test code) reports 2 High and 14 Medium. Of about 113 HTTP/WebSocket routes, 30 rely only on the global auth middleware, and 22 of those return or change tenant data with no ownership check.

## Findings against the NCS bar

The NCS ERP rules applied: (1) identity and scope come from the session and are re-read from the database, never from the request; (2) the backend owns business decisions; (3) responses carry only fields the caller may see; (4) every body is schema-validated; (5) authorization is never cached; (6) per-route permission, not only global middleware; (7) tenant isolation; (8) audit log of sensitive actions; (9) secrets never in logs; (10) webhook verification unconditional and fail-closed; (11) signed, ownership-checked file access; (12) money and entitlement integrity.

### 5.1 Critical and high

| ID | Sev | Finding | NCS rule | Status |
|---|---|---|---|---|
| S1 | Critical | "Local caller" is not loopback. `core/auth.py:131-145` treats any `10.*`, `172.*` or `192.168.*` client as local, and `172.*` covers public ranges. `GET /api/auth/token` hands the permanent IPC token to such a caller, and `POST /api/auth/admin/verify` returns it for any username and password. Behind a load balancer every request is "local". The token never rotates, is stored in plaintext at `config/.api_token`, and is accepted on every non-user route. A scanned lab container that can reach the host is a suspected path to it | 1, 7 | Verified |
| S2 | Critical | No tenant isolation on the legacy API. Any JWT or the IPC token reaches `GET /api/findings/all` (all users' findings), `/api/findings/{scan_id}`, `/api/report/{scan_id}`, `/api/scan/history/list`, `DELETE /api/scan/{id}`, `POST /api/findings/{id}/review` (the `actor` is client-supplied), `PUT /api/programs/{id}/scope`, and `/api/settings` (process-global vault of Claude, Twilio and Shodan keys). 22 of 30 middleware-only routes expose or mutate tenant data without an ownership check | 1, 6, 7 | Verified |
| S3 | Critical | `/ws/scan/{scan_id}` (`routers/ws.py:11-31`) accepts any connection with no token, no ownership check and no Origin check. The HTTP auth middleware does not run for WebSocket scopes. Any web page can connect to `ws://localhost:8000/...`, and each connection costs a Redis subscription | 6, 7 | Verified |
| S4 | Critical | The watch scheduler bypasses every scan guard. `POST /api/watch` stores an unvalidated `scan_config` dict, and the scheduler passes it to the pipeline. Keys such as `allow_loopback`, `execution_mode`, `authorization_confirmed` and `in_scope_assets` are read from that dict, so a free-tier user can scan RFC1918 targets with deep mode and WAF bypass, skipping quota and tier gates. `alert_webhook` is posted with `requests` to an unvalidated URL (blind SSRF, follows redirects). Credentials in `scan_config` are stored unencrypted | 1, 2, 4 | Verified |
| S5 | High | Validation-plan execution has no real approval gate. `execute_plan` hardcodes `operator_approval={"status": "APPROVED"}` and never loads the campaign (`services/exploit_validator.py:1196`). `/approve` sets APPROVED unconditionally. `reproduce` and `stop` do not check that `plan_id` belongs to the campaign in the path, so one user can run or stop another user's plan | 1, 2, 7 | Verified |
| S6 | High | Real verification can run against unauthorized campaigns: status DRAFT is allowed and `_verify_authorization_or_raise` is never called (`exploit_validator.py:759, 806`). Authorization itself is self-attested everywhere (`authorized_by` is free text, no DNS TXT or file challenge proving target ownership). Any user can create a campaign for any internet host and mark it authorized | 2 | Verified |
| S7 | High | Scope validator gaps: no DNS resolution, so a name resolving to 127.0.0.1, 10.x or 169.254.169.254 passes. No pinned-IP connect, so DNS rebinding and check-to-use races are open. Decimal and hex IP forms and `::ffff:` mapped addresses are Suspected bypasses of the metadata block. An in-scope URL rule beats an explicit out-of-scope host, against the file's stated precedence. `excluded_paths` matching does no normalization (`/%61dmin`, `//admin` slip past `/admin`). Headless Chromium runs `--no-sandbox` as root with no request-routing guard | 1 | Verified (code), Suspected (exploit) |
| S8 | High | Subprocess boundary: `allowed_flags` is defined for every tool but never read. Only shell metacharacters are blacklisted, so `--script`, `-oN <path>` and `-t <path>` pass. Every request hardcodes `authorization_confirmed=True`, so the boundary's authorization check is a tautology. The host is passed positionally with no `--` and no reject of a leading `-`. The child inherits the full environment (`JWT_SECRET_KEY`, `AIHAX_MASTER_KEY`, Stripe and Anthropic keys). Bearer tokens passed to katana as `-H` land in plaintext in `sanitized_args_json` | 1, 9 | Verified; Windows `.bat` metacharacter issue is Suspected |
| S9 | High | Credentials in logs. `agents/auth_agent.py:876` logs the whole credential dict at INFO. `xss_strategy.py:303-306` logs session cookies. The redaction filter handles only dict messages | 9 | Verified |
| S10 | High | Google sign-in checks `aud` only if `GOOGLE_CLIENT_ID` is set, and it defaults to empty. Only `environment == "cloud"` requires it, so an ID token minted for another OAuth app is accepted. The 401 response echoes the exception text, which includes the token | 1 | Verified |
| S11 | High | Master key. `core/encryption.py` reads `os.environ["AIHAX_MASTER_KEY"]`, not `Settings`. A key set only in `.env` and a non-Docker run falls back to a hard-coded `sha256(b"aihax-dev-fallback-key-only")`. The refusal triggers only for the exact strings `production` or `cloud`, and the default environment is `local`. Static salt, no key versioning or rotation, PBKDF2 on every read. `save_scan_config` encrypts twice | 9 | Verified |

### 5.2 Medium

| ID | Finding | Status |
|---|---|---|
| S12 | Authorization is cached: the middleware accepts any JWT for 15 minutes with no account-status check and no revocation list. JWT is HS256 with no minimum secret length, no `iss` or `aud`, and `exp` is not required | Verified |
| S13 | Entitlements are forgeable locally. The verification public key comes from env or `.env`, so a user can set their own keypair. The cache is an editable SQLite row. No clock-rollback guard. Revocation takes up to 7 days | Verified |
| S14 | Quota gaps: cancelling a scan removes it from the free-tier quota (cancel works on completed scans too). Campaigns have no tier or quota gating. Programs are looked up by id with no owner check | Verified |
| S15 | Rate limiting is process-local, keyed on the raw bearer token (so token rotation bypasses it and grows memory), and auth failures are never recorded for failed Google or refresh calls | Verified |
| S16 | Tool provisioning computes a SHA-256 but never compares it (`recon/recon_tool_provisioner.py:319`). `docker/install-tools.sh` installs "latest" releases as root without a checksum | Verified |
| S17 | Electron: `open-folder` and renderer-supplied paths, `unsafe-eval` CSP, `shell: true`. PR #2 addresses most of this. The dev-CSP and focus regressions in that PR are listed in the PR review | Verified |
| S18 | Errors return `str(e)` in many 500 responses. Evidence detail returns 400 vs 404, which leaks id existence | Verified |
| S19 | Billing: no handling of `charge.refunded` or dispute events, and a one-time Pro purchase gets a 100-year end date, so a refund leaves lifetime Pro. `subscription.updated` has no event-time ordering. Webhook signature check and idempotency are correct | Verified |
| S20 | Request bodies for finding review, program import and `ScanConfig` extras are raw dicts. Status and decision strings are free-form | Verified |
| S21 | Audit trail identity: `actor`, `authorized_by` and `operator_id` are client-supplied or default to `"operator"`. The hash chain proves order, not who | Verified |

### 5.3 What is good (credit where due)

- Refresh tokens are stored hashed, rotated, with family reuse detection.
- The Stripe webhook check is unconditional, fails closed, and is idempotent.
- Report download resists path traversal, and Jinja autoescape is on.
- Subprocesses use an argv list, not a shell.
- `RequestEngine` fails closed on a default scope of `*`, re-validates each redirect hop, and real verification is restricted to GET, HEAD and OPTIONS with a request budget.
- `DEV_MOCK_AUTH` is refused in production. Docker ports are bound to loopback, and there is no docker.sock mount.
