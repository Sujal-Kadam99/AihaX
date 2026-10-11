# AihaX: Scope Document, Reliability Findings and Open Questions

Prepared for: Abhi (reviewer) and Sujal (author)
Basis: AihaX repo at `master` `dfb5dd6` plus open PR #2, read on 2026-10-11
Standard applied: NCS ERP `SECURITY.md`, `CLAUDE.md` and `docs/BACKEND_SECURITY.md` (there is no separate NCS "security skill"; these three documents are the bar)

## 0. How this document was produced, and its limits

- Three read-only reviewers read the code: one for persistence and task recovery, one for security and scope safety, one for product intent and tech stack. A fourth pass ran ruff and bandit.
- Every finding was found by reading the code. Nothing was exploited and no live endpoint was called. Findings are marked **Verified** (code path read end to end) or **Suspected** (inferred, not traced).
- Where a document claims something the code does not do, that is called out as a **doc/code gap**. Those matter most, because they show what the platform says about itself versus what it does.
- Sujal's answers are the missing half. Sections 6 to 12 are questions only he can answer. Section 13 is the command to give his agent.

## 1. What AihaX says it is

- README: "a desktop-first application security assessment platform for authorized testing of web applications", made of an Electron shell, a React/Vite UI and a FastAPI backend with SQLite, Redis and optional ChromaDB.
- `AihaX_Description_Oct_7_2026.md` (repo root): "a fully autonomous, AI-powered penetration testing platform. Enter URL. Click Start. Get a Professional Pentest Report", with "zero manual intervention".
- `docs/MASTER_IMPLEMENTATION_PLAN.md`: targets freelancers and small security consultancies, later Team, Agency and Enterprise tiers and bug-bounty hunters.
- The engineering documents describe something different from the marketing: a **human-supervised, evidence-gated** assessment workbench. Authorization records, scope hashes and operator confirmation are required before live work. The hunting engine "never auto-dispatches".

Reviewer's reading, to be confirmed by Sujal: the code supports "human-supervised, evidence-gated", not "autonomous". The scope document should state which one the product is.

## 2. What the platform actually does (end to end, as read from the code)

1. The operator creates a Program or Campaign, enters a concrete target and defines scope (`core/scope_validator.py`).
2. An authorization record is created and bound to a scope hash. A campaign should not reach RUNNING without it.
3. Recon runs in one of three modes (`recon/recon_modes.py`): `AUDIT` (mock fixtures, no network), `DRY_RUN`, or `AUTHORIZED_LIVE_RECON` (real subprocesses and network, behind a 9-point preflight). Tools: subfinder, amass, httpx, katana, gau, nmap, whatweb, gobuster, nuclei, dalfox, sqlmap, crt.sh and DNS. The output is a hashed `CanonicalReconSnapshot`.
4. A selector and hypothesis engine decide which checks apply to what recon found.
5. Checks (C001 to C086) run as persistent `ExecutionTask` rows claimed by an in-process worker.
6. Evidence is captured with secret redaction, content hashing and a hash chain.
7. A `VerificationEngine` with per-check strategies assigns a disposition (VULNERABILITY, HARDENING_ONLY, INCONCLUSIVE, FALSE_POSITIVE, NOT_BOUNTY_ELIGIBLE) and a confidence band.
8. Reports are produced as PDF (WeasyPrint and Jinja2), plus a bug-bounty export. Claude is used only to write remediation and business-impact prose, and only if a key is configured.
9. Commercial layer: Google sign-in, JWT sessions with rotated refresh tokens, Stripe billing, Ed25519-signed entitlements, team workspaces.

## 3. Proposed scope statement (for Sujal to confirm or correct)

**In scope (claimed or built):**
- Authorized, human-supervised assessment of web applications and APIs.
- Scope and authorization management, recon, a check catalog, verification and false-positive controls, evidence, PDF and bug-bounty reports.
- Desktop delivery (Electron plus Docker Compose on localhost).
- Per-user tiers, team workspaces and signed entitlements.

**Out of scope (not found in the code, or explicitly deferred):**
- Fully autonomous "enter URL, click start" operation (marketing only).
- AI-driven testing of targets. `MASTER_IMPLEMENTATION_PLAN.md` section 9 describes an AI/LLM security testing subsystem. Nothing in `backend/` implements it.
- Multi-tenant cloud SaaS. The `TrustedHost` list is localhost only, the "local caller" logic breaks behind a proxy (see S1), and the SQLite persistence is single-node.
- ZAP, Nikto, Nessus and similar scanners. There is no ZAP anywhere in the repo, though a recent branch commit mentions a ZAP API key setting.
- Mobile apps, network and infrastructure scanning, cloud posture, source-code review.

**Contradictions inside the repo that the scope statement must resolve:**

| Topic | Source A | Source B | Source C |
|---|---|---|---|
| Autonomy | Marketing doc: zero manual intervention | Ops docs: authorization and confirmation at every step | Hunting engine: never auto-dispatches |
| Number of checks | `docs/checks/README.md`: 77, all production | Marketing: 86, all implemented | Code: C001 to C086 exist, registry certifies C001 to C077 |
| Tiers | Plan: 3 (Community, Pro, Team) | `entitlements.py`: free, pro, team, founder | `billing.py`: Pro, Pro one-time, Team, Agency, Enterprise |
| "execution_mode" | Recon: AUDIT, DRY_RUN, AUTHORIZED_LIVE_RECON | Campaign: PRODUCTION, TEST | same field name, two unrelated enums |
| Test count | 530 (phase 8 doc) | 246 (testing matrix) | 95 / 121 (other docs); 116 `test_*.py` files on disk |

## 4. Reliability findings

### 4.1 Measured

| Check | Result |
|---|---|
| Size | 403 `.py` files and about 65,000 lines under `backend/`; 116 `test_*.py` files |
| Ruff (v0.17, repo config) | 7,875 findings on master; `ruff_baseline.txt` records 1,556. Counts differ by ruff version and rule set. Either way, lint is not clean |
| Bandit (non-test code) | 2 High and 14 Medium findings |
| Backend test suite | 47 failed, 1,934 passed (Appendix A). Failures concentrate in worker, budget and authorization-expiry tests |
| Tests run by CI | None. There was no CI on master. PR #2 adds one, but its main backend gate is `continue-on-error` |

### 4.2 Persistence and migrations

| ID | Severity | Finding | Status |
|---|---|---|---|
| R1 | High | Migrations are not transactional. `engine.begin()` wraps them, but Python's `sqlite3` does not open a transaction for DDL (confirmed with a stdlib check: two `CREATE TABLE` statements survived `rollback()`). A migration that fails halfway leaves earlier statements committed with no `schema_migrations` row (`models/migrations.py:1436-1494`) | Verified |
| R2 | Medium | The only rollback is a file copy of the main `.db`. It ignores the `-wal` file, is overwritten on every startup even when nothing is pending, is not integrity-checked, is not rotated and has no retention (`migrations.py:1427-1433`) | Verified |
| R3 | Medium | Restore on any exception, including a checksum mismatch or a lost startup race, overwrites the live DB without a lock. A restart loop can copy a half-migrated DB over the good backup | Verified |
| R4 | Medium | Checksum is over raw statement text, so a whitespace edit blocks startup. Versions skip from 16 to 19. There is no downgrade guard. `create_all` runs before migrations, so the migration SQL is untested on a clean install | Verified |
| R5 | High | The campaign worker flushes task status to RUNNING and then awaits network checks before its first commit (`services/campaign_worker.py:162-165, 316, 404, 511`). pysqlite holds the write lock across that time. The heartbeat then fails with `database is locked` after 5 s, and the error is swallowed at debug level. Pause and cancel calls can return 500 | Suspected (inferred from transaction behavior; reproduce with a check that sleeps over 10 s plus a pause call) |
| R6 | Low | `synchronous=NORMAL` can lose the last commits on power loss, while `persistence.md` calls it "optimal durability". Compose bind-mounts the SQLite directory from the host, and WAL on Docker Desktop bind mounts is unreliable | Verified (config), Suspected (impact) |

### 4.3 Task execution and recovery

| ID | Severity | Finding | Status |
|---|---|---|---|
| R7 | High | No timeout around `check.execute`, `verify_finding` or recon. `dispatch_once` runs tasks one after another across all campaigns. One hung check blocks every campaign, and stale-lease recovery cannot run because it sits in the same loop (`campaign_worker.py:316, 404, 680-762`) | Verified |
| R8 | High | Recon calls synchronous `dns.resolver.resolve` inside async code (`recon/live_recon_validator.py:640-646, 1549`). A slow DNS server can freeze the whole API for up to about 70 s. The `except Exception: continue` blocks turn timeouts into "no result" | Verified |
| R9 | High | Campaign rate limits and budgets are not enforced on the worker path. The worker hardcodes `rate_limit_rps=10`, ignores `campaign.rate_limit_rps`, `max_concurrency` and `target_budget`, and counts budget as one per task rather than per request, non-atomically (`campaign_worker.py:121, 233`). `docs/operations/campaign-lifecycle.md` says "bounds strictly enforced" | Verified |
| R10 | Medium | `claim_tasks` is select-then-update with no `WHERE status` guard (`persistence/repository.py:543-562`). Safe with one process. With two workers, two can run the same task. The recon claim, by contrast, is atomic | Verified |
| R11 | Medium | Pause, cancel and kill do not stop in-flight work. State is checked only before and after a check. On the abort path the task is not committed or released, so it burns a retry attempt. `KILLED` is missing from the abort list, so the kill switch does not stop the task already running (`campaign_worker.py:142, 489-498`) | Verified |
| R12 | Medium | Any recon exception marks the campaign FAILED, which is terminal. There is no recon retry. A crash during recon leaves the run RUNNING with a 600 s lease and no heartbeat. Task retries have no backoff | Verified |
| R13 | Medium | `CancelledError` is not caught by `except Exception`, so a cancelled task stays RUNNING until its lease expires. `scheduler.shutdown()` is never called. Legacy scans started through `BackgroundTasks` stay `pending` or `running` forever after a restart | Verified |
| R14 | Medium | Legacy scan cancel depends on Redis only. The pipeline overwrites `cancelled` with `complete`. One Redis failure disables Redis for the life of the process (`core/redis_client.py:15-34`). Redis keys have no TTL | Verified |
| R15 | Medium | Subprocess handling: timeout kills only the child, not its process group, so grandchildren are orphaned. Cancellation never kills the child. After the output cap, the child blocks on a full pipe and the result is mislabelled TIMEOUT. There are no CPU or memory limits (`execution/tool_execution_boundary.py:599-720`) | Verified |
| R16 | Low | `/api/health` hardcodes `db_status="ok"` (`main.py:193`). Rate-limit dicts grow without bound. The worker creates a `Scan` row with status `running` and never updates it | Verified |

### 4.4 Evidence integrity and observability

| ID | Severity | Finding | Status |
|---|---|---|---|
| R17 | High | The evidence "hash chain" is not verified. `verify_vault_integrity` recomputes only content hashes, ignores `prev_chain_hash`, and silently truncates at 1000 records. The chain is built from the oldest row because of `limit=1` with ascending order, and the chain timestamp is not stored. Deleting a row would not be flagged (`evidence/evidence_store.py:105-209`, `evidence_manifest.py:218-241`). Docs: "tamper-evident", "row deletion immediately flagged" | Verified, doc/code gap |
| R18 | High | Live-recon audit events insert `previous_event_hash="0"*64` and a random UUID as the event hash (`services/operator_live_recon_service.py:347-348`). Any campaign that ran live recon will fail the audit-trail integrity check. Concurrent writers can also fork the chain | Verified, doc/code gap |
| R19 | Medium | `save_snapshot` updates the row in place, while `persistence.md` says "immutable snapshot" | Verified, doc/code gap |
| R20 | High | Most application logs never reach a handler. `setup_logger` configures only `"aihax.main"`, and no root `basicConfig` exists. Info-level messages from the worker and migrations are dropped, and warnings go to unformatted stderr with no redaction | Verified |
| R21 | Medium | Metrics: most counters in `observability.md` are never incremented in the runtime path. The metrics endpoint returns mostly zeros. 33 `print()` calls, no correlation ID | Verified |
| R22 | Low | Swallowed exceptions (regex counts, lower bounds): 112 `except Exception` in `services`, 38 in `recon`, 4 in `execution`. A bare `except:` remains in `vulnerability_execution_engine.py:305`. A failed bug-bounty DTO build is silently dropped from the report | Verified |

### 4.5 Doc/code gaps in `docs/operations/` (the platform describes behavior it does not have)

1. `task-recovery.md` claims atomic `claim_tasks`, a "background coordinator" for recovery, and heartbeat renewal for long tasks. None of the three holds as described (R10, R7, R5).
2. `campaign-lifecycle.md` says PAUSED lets running tasks "finish safely", workers "immediately cease" on cancel, and bounds are "strictly enforced". The code does none of these (R9, R11). The state diagram also omits `KILLED` and two valid transitions.
3. `evidence-vault.md` and `integrity-verification.md` claim tamper-evident chains. See R17 and R18.
4. `observability.md` lists about 20 counters. See R21.

### 4.6 Test run

Result of `pytest backend/tests` in a clean Python 3.11 environment: **47 failed, 1,934 passed**. Details and caveats in Appendix A.

## 5. Security findings

Moved to [security-bugs.md](security-bugs.md) (IDs S1 to S21). The questions in section 9 refer to those IDs.

## 6. Open questions: product and scope

Answer each as **FACT** (cite file and line), **DECISION** (state who decided and when), **OPINION** (yours) or **UNKNOWN**. Do not guess.

- **Q1.** In one paragraph: what is AihaX, who pays for it, and why would they pick it over Burp Suite Pro, Nuclei, ZAP or a pentest firm?
- **Q2.** The marketing document says "fully autonomous, zero manual intervention". The code requires authorization and confirmation. Which is the product? Should the marketing document be deleted?
- **Q3.** Who is the first real customer, and has anyone outside the team run a full scan with it? What happened?
- **Q4.** Is this a desktop tool, a hosted SaaS, or both? The code assumes localhost, but billing and teams assume cloud.
- **Q5.** Is the authoritative number of checks 77 or 86? Why are C078 to C086 outside the registry?
- **Q6.** The three tier models (3, 4 and 5 tiers). Which is real? What does a customer get for each, and where is it enforced server-side?
- **Q7.** What is the "founder" tier? Who can grant it, and how?
- **Q8.** What is the difference between the Campaign flow and the legacy Scan flow (`/api/scan/*`)? Which is the future? Can the legacy flow be deleted?
- **Q9.** What are the two "execution modes" (recon vs campaign) for? Can they be merged or renamed?
- **Q10.** The AI/LLM testing subsystem in `MASTER_IMPLEMENTATION_PLAN.md` section 9: is it in scope for the next release? If yes, what is the safety model for letting an LLM choose actions against a target?
- **Q11.** What is ChromaDB's "learning" supposed to achieve, and what evidence shows it improves detection or reduces false positives? What stops one user's learned patterns from leaking into another user's results?
- **Q12.** What should the product refuse to do? List the hard "never" rules (for example, never scan without proof of ownership).
- **Q13.** What is the definition of "done" for version 1.0? Name the measurable exit criteria.
- **Q14.** Bug-bounty features: is the goal to help hunters or to generate submissions automatically? How do you prevent spamming programs with unverified reports?
- **Q15.** Why is ZAP mentioned in a recent branch commit but absent from the repo on master?

## 7. Open questions: architecture and tech stack

- **Q16.** Why SQLite for a product with teams, billing and background workers? What is the plan when two instances run, or when the data outgrows a file? Why not Postgres?
- **Q17.** Redis is used for pub/sub and cancel flags but not as the task queue. Why? What happens to cancel and status when Redis is down (R14)?
- **Q18.** Why an in-process asyncio worker instead of a real queue (Celery, RQ, Arq, Temporal)? What is the maximum number of concurrent campaigns it can handle correctly?
- **Q19.** The worker runs tasks serially and hardcodes 10 rps (R7, R9). Was that deliberate? How is the per-campaign rate limit supposed to be enforced?
- **Q20.** Why hand-rolled migrations (1,513 lines) instead of Alembic? What is the tested upgrade path from an old install?
- **Q21.** Why is `backend/pyproject.toml` empty on master while `requirements.txt` has 24 unpinned `>=` entries? What is the lockfile story? Was `uv.lock` (55 bytes) ever valid?
- **Q22.** Two PDF libraries (WeasyPrint and fpdf2) are listed. Which is canonical? Is `PyJWT` an undeclared dependency? What other imports are missing from `requirements.txt`?
- **Q23.** The stack mixes versions that normally do not pair (vitest 4 with vite 5, typescript-eslint 8 with eslint 8, Electron 28 EOL). Who owns dependency upgrades, and how often?
- **Q24.** Why Electron plus Docker plus Compose for a desktop product? Does the end user need Docker Desktop? What happens to the Docker daemon, ports 3000 and 8000, and database files when the app is uninstalled or upgraded?
- **Q25.** How do the vendored Windows binaries in `bin/tools` and the Linux tools in the Docker image relate? Which is the supported runtime? Who verifies tool versions and hashes?
- **Q26.** `routers/campaigns.py` is 2,197 lines with 60 routes. What is the plan to split it, and what tests protect that refactor?
- **Q27.** Why are `execution_mode`, `allow_loopback` and `authorization_confirmed` plain keys in a free-form dict instead of typed, validated fields?
- **Q28.** What is the data model for multi-tenancy? Is there an `organization_id` or `user_id` on every table? Which tables have none?
- **Q29.** How does the frontend work when the backend is down, slow or on another port? What is the failure UX?
- **Q30.** What is the logging and observability plan? Why does no root logger exist (R20)? Who reads the metrics endpoint?
- **Q31.** What was the process used to write this code (which agents, what prompts, what review)? How much of the 65,000 lines has a human actually read and run?

## 8. Open questions: reliability and operations

- **Q32.** Has any campaign run for more than one hour, or against more than 100 endpoints, on real infrastructure? What broke?
- **Q33.** What happens if the laptop sleeps or the app crashes mid-campaign? Walk through the recovery path with file names. Was it tested by killing the process?
- **Q34.** Show the test that proves pause, cancel and kill stop in-flight traffic (R11). If none exists, will you write it first?
- **Q35.** Show the test that proves the evidence hash chain detects a deleted row (R17). If it does not, which claim in the docs is wrong?
- **Q36.** Why does the live-recon audit event use a zero hash and a random event hash (R18)? Is campaign integrity verification expected to pass after live recon?
- **Q37.** What is the backup and restore story for the user's database and evidence (R2, R3)? Has restore ever been tested?
- **Q38.** What are the resource limits (CPU, memory, disk, open files) for tools and for headless Chromium? What stops a malicious target from filling the disk or memory?
- **Q39.** How are false-positive and false-negative rates measured? On what benchmark (DVWA, Juice Shop, WebGoat, a labeled corpus)? What are the numbers?
- **Q40.** Which of the 86 checks have been validated against a real vulnerable target and which only against mocks? Give the list.
- **Q41.** Most recon adapters are marked `LIVE_ADAPTER_PRESENT_NOT_LIVE_VALIDATED`. What is the plan and date to validate them?
- **Q42.** The backend suite, ruff and mypy have known legacy failures. List exactly which tests fail on master today, why, and who owns each.
- **Q43.** What is the upgrade story for installed copies (database schema, config, tool versions)?
- **Q44.** What is the SLO you would put your name on (scan completion rate, report accuracy, crash rate)?

## 9. Open questions: cyber security and safety

These follow the NCS ERP bar. Answer with the code that enforces each rule, not with intent.

**Authorization and legality**
- **Q45.** How does the platform know the operator owns or is permitted to test the target? Today `authorized_by` is free text. Will you require proof (DNS TXT, file challenge, signed letter) before live work? If not, what stops misuse against third parties, and what is the legal position of the company if it happens?
- **Q46.** Who is liable if a user scans an out-of-scope host because of a scope-validator bypass? What does the terms of service say? Has a lawyer read it?
- **Q47.** Is there an abuse-reporting or kill path for the vendor (for example, revoking a user's entitlement if they scan targets they do not own)?
- **Q48.** Validation plans send real exploit traffic. What is the list of payloads that must never be sent (destructive SQL, file writes, DoS)? Where is it enforced?

**Identity and tenancy**
- **Q49.** Why does "local" include `10.*`, `172.*` and `192.168.*` (S1)? Why does `/api/auth/admin/verify` return the token for any username and password? What is the admin login supposed to be?
- **Q50.** What is the IPC token for, why is it permanent, and can a scanned target's content, a browser page, or a container reach it?
- **Q51.** Which routes enforce ownership today, and which do not (S2)? Can you produce the test that fails if a route is neither on the public allowlist nor returns 401 without a token, and another that proves user B cannot read user A's data?
- **Q52.** Why is the WebSocket `/ws/scan/{scan_id}` unauthenticated (S3)? Was it meant to be behind auth?
- **Q53.** Which user is allowed to change `/api/settings`, and why is the vault process-global rather than per user or per organization?
- **Q54.** Why does the watch API accept a free-form `scan_config` (S4)? What validates it before the pipeline runs it?
- **Q55.** Why is Google `aud` verification optional (S10)? What stops a token from another app logging in?
- **Q56.** How is an account suspended or a session revoked, and how long until that takes effect (S12)?

**Scope enforcement and SSRF**
- **Q57.** Why does the scope validator not resolve DNS (S7)? What is the plan for resolving once, pinning the IP and re-checking on connect?
- **Q58.** Campaign targets allow loopback and private ranges. Why, and what stops a target page from making AihaX talk to `localhost:8000` (its own backend) or to cloud metadata at 169.254.169.254?
- **Q59.** Why does an in-scope URL rule override an explicit out-of-scope host? Is that intended?
- **Q60.** How are `excluded_paths` matched, and have you tested encoded or doubled-slash paths?
- **Q61.** Headless Chromium runs `--no-sandbox` as root and renders hostile content. What is the isolation boundary? Can a malicious page reach the host or Docker network?

**Subprocess and supply chain**
- **Q62.** Why is `allowed_flags` defined but not enforced (S8)? What stops `nmap --script`, `-oN <path>` or nuclei `-t <path>` from being injected through target or parameter fields?
- **Q63.** Why is `authorization_confirmed=True` hardcoded in every tool request?
- **Q64.** Why does the child process inherit all environment secrets? Will you pass an allowlisted environment instead?
- **Q65.** How are tool binaries verified (S16)? Why is the computed SHA-256 never compared? Who updates the pins?
- **Q66.** Third-party code runs against your users' targets: what is the threat model if a tool release or plugin is compromised?

**Secrets, crypto and data handling**
- **Q67.** What happens when `AIHAX_MASTER_KEY` is missing on a non-Docker run, or `ENVIRONMENT` is not set (S11)? Will you fail closed? Is the fallback key ever acceptable?
- **Q68.** Which data does the platform store about the user's targets (credentials, cookies, tokens, session captures, response bodies)? Which are encrypted, how long are they kept, and how are they deleted?
- **Q69.** Why do logs contain credentials and cookies (S9)? Who audited the log output?
- **Q70.** Reports and evidence may contain secrets and personal data from the target. What is the retention, redaction and export policy?
- **Q71.** How does the platform handle a target's PII found during testing, under GDPR, India's DPDP Act and the client's contract?
- **Q72.** What is the process if AihaX itself is breached, given it stores other companies' vulnerabilities? What would an attacker gain by compromising a user's database file?

**Billing and entitlements**
- **Q73.** The entitlement public key is configurable by the user (S13). What stops a user from signing their own tier? Is the app expected to be tamper-resistant, or is it honor-system?
- **Q74.** What happens on refunds, disputes and cancellations (S19)? Why does a one-time purchase get a 100-year expiry?
- **Q75.** Can a free user bypass the scan quota by cancelling scans, or use campaigns, which have no tier gate (S14)?

**Electron and frontend**
- **Q76.** After PR #2: who reviewed the CSP change, the `before-quit` change, and the move to Electron 44? Were they tested in a packaged build, not only in tests?
- **Q77.** Findings include attacker-controlled strings from the scanned site. Which components render them, and how is XSS prevented?

**Process**
- **Q78.** Is there a threat model document? If not, will you write one before adding features? (STRIDE per component is enough.)
- **Q79.** Has anyone outside the team done a security review or pentest of AihaX itself? A security tool that is easy to attack is a liability.
- **Q80.** What is the vulnerability disclosure channel for AihaX? There is no `SECURITY.md` (NCS ERP has one with severity SLAs).
- **Q81.** What is the minimum gate for merging: tests, lint, security scan, human review? Who is the second reviewer, given the author is an AI agent plus one developer?

## 10. Questions that ask for an opinion

- **Q82.** Rank these by what you would fix first and say why: S1, S2, S3, S4, S5, S6, S7, R5, R7, R9, R11, R17. What would you remove from the product instead of fixing?
- **Q83.** If you had two weeks and no new features, what would you do?
- **Q84.** What part of this codebase are you least sure works? Where do you expect the next bug?
- **Q85.** What claims in the README or docs do you know are not true yet?
- **Q86.** What would make you comfortable letting a paying customer run this against their production system?
- **Q87.** What would you cut to ship a smaller, correct version 1.0?
- **Q88.** What do you want from Abhi: decisions, budget, time, a second developer?

## 11. Suggested decisions to ask Abhi to make after the answers

1. Delete or rewrite the "autonomous" marketing document, and fix the claim list in the README.
2. Freeze features until the Critical items in security-bugs.md (S1 to S4) are closed and have tests.
3. Pick one tier model, one check count, and one mode vocabulary.
4. Require proof of target ownership before any live run.
5. Add a CI gate that actually blocks: lint on touched files, the full test suite on touched modules, a route-auth inventory test, and a tenant-isolation test.
6. Add `SECURITY.md`, a threat model, and an incident and disclosure process modelled on NCS ERP.
7. Decide: one process with SQLite (desktop only, remove SaaS claims) or Postgres plus a real queue (hosted).

## 12. How to answer

Create `backend/core/ai_training/ANSWERS.md` with one heading per question ID. For each, give:
- **Type**: FACT, DECISION, OPINION or UNKNOWN
- **Answer**: short and specific
- **Evidence**: file:line, command output, or commit hash. For FACT, evidence is required
- **Action** (optional): what you would change

If the answer needs a command run, run it and paste the output. Do not invent. "UNKNOWN" is an acceptable answer and is more useful than a guess.

## 13. Command to run on Sujal's agent

Paste this into Sujal's coding agent, run from the root of the AihaX repo on `master`, after pulling the branch that contains `backend/core/ai_training/`. The agent should work through all questions in section 6 to 10 of this document and write `ANSWERS.md` next to it.

```text
You are helping answer a technical due-diligence questionnaire about this repository (AihaX).

1. Read backend/core/ai_training/SCOPE_AND_OPEN_QUESTIONS.md and backend/core/ai_training/security-bugs.md in full.
2. Answer EVERY question Q1 to Q88 by reading the actual code, running read-only commands (grep, git log, pytest, ruff, bandit) and checking git history. Do not rely on the docs alone: docs are known to disagree with the code.
3. For each question write a section in backend/core/ai_training/ANSWERS.md with: Type (FACT / DECISION / OPINION / UNKNOWN), a short Answer, and Evidence (file:line, command output, or commit hash). A FACT without evidence is not acceptable.
4. For each finding R1 to R22 in SCOPE_AND_OPEN_QUESTIONS.md and S1 to S21 in security-bugs.md, say CONFIRMED, PARTLY TRUE or WRONG, with evidence. If you think a finding is wrong, show the code that proves it.
5. Where a question asks for an opinion, give your honest engineering opinion, including when it is unflattering to the code you wrote.
6. Where you do not know, write UNKNOWN. Never invent a number, a test result or a decision. Do not claim a test passes unless you ran it in this session and include the output.
7. Do not change any code in this task. Do not push or open PRs. Only create backend/core/ai_training/ANSWERS.md.
8. When finished, print a summary: how many questions are FACT, DECISION, OPINION, UNKNOWN; the 5 findings you are most worried about; and the 5 claims in the README or docs that you know are not true.
```

## Appendix A: backend test run

Run on 2026-10-11: master `dfb5dd6`, Windows 11, Python 3.11.16 in a clean virtual environment, dependencies installed from `backend/requirements.txt` at the latest allowed versions (it has no pins), plus pytest 60 s per-test timeout. Tool binaries (amass, subfinder and others) were not installed.

**Result: 47 failed, 1,934 passed, 3,097 warnings, 7 min 26 s.**

The failures are not random. They group as follows:

| Group | Failing tests | What I confirmed |
|---|---|---|
| Worker, budget and authorization expiry | about 30 tests in `test_phase14_production_safety`, `test_phase15_*`, `test_phase17_*`, `operations/test_worker_dispatch_runtime`, `operations/test_live_local_runtime_execution` | Sampled two budget tests: the worker returns status `blocked` while the test expects `failed`. The code and its tests have drifted apart on the very behavior (budget and authorization fail-closed) that the docs describe as certified. Related to R9 and R11 |
| Migrations | `test_billing_checkout::test_stripe_subscription_migration_upgrades_existing_database` | `ALTER TABLE watch_schedules ADD COLUMN user_id` fails with `no such table: watch_schedules`. A migration assumes a table that an older database does not have. This is a real defect in the upgrade path, consistent with R4 (migrations are untested outside the `create_all` path) |
| Verification strategies | `test_77_checks_real_http` (C019), `test_batch_e_strategies` (C019, C056 x2) | Not investigated. Could be logic drift or dependency drift |
| Recon and tool provenance | `test_phase25_*`, `test_phase26_*`, `test_phase27_*` | At least some are environment: `binary_sha256 == "BINARY_NOT_FOUND"` because the tools are not installed here. They still show the suite depends on local binaries without skipping cleanly |

Caveats: I did not run the suite on Sujal's machine or inside the Docker image. Some failures may be Windows-, dependency-version- or tool-related. Sujal must say which of the 47 he already knew about (Q42). I did not run the frontend or Electron tests here.

Suggested follow-up: run the same command inside the Docker image, where the tools exist, and compare.
