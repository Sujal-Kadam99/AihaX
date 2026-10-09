# Unified Campaign Reconnaissance Pipeline

**Date:** 2026-10-08  
**Status:** Draft for operator review

## Goal

Whenever AihaX performs reconnaissance in Safe Scan, Recon Only, Plan Only, or Fully Authorized mode, it must use the same campaign reconnaissance pipeline. Passive discovery, low-impact web inventory, provenance, and result semantics stay consistent across modes. Mode and authorization change which additional actions may run; they do not select a different recon method.

## Mode behavior

- `RECON_ONLY`: run the shared recon pipeline, create a recon report, and run no vulnerability checks. The report must say vulnerability testing was not performed. Nmap and Gobuster still require explicit per-run selection and saved scope/port authorization; the scan profile does not implicitly enable them.
- `PLAN_ONLY`: run the shared recon pipeline, then build a check plan; execute no vulnerability checks. Report the discovered surface and proposed checks, clearly marked as not executed. Nmap and Gobuster still require explicit per-run selection and saved scope/port authorization.
- `SAFE_SCAN`: run the shared recon pipeline before configured safe checks. Nmap and Gobuster remain off unless separately selected and authorized.
- `FULL_AUTHORIZED_SCAN`: run the same recon pipeline before the selected authorized checks. Nmap and Gobuster still require explicit per-run selection and saved scope/port authorization; the scan profile does not implicitly enable them.
- `assessment_mode` (`CONTROLLED` or `PRODUCTION_AUTHORIZED`) is independent of the scan profile and continues to set its own authorization, rate, concurrency, and budget limits.
- Any recon dispatch whose authorization, scope snapshot, or required-provider preflight fails stops before target traffic and prevents dependent check work from starting.

## Required behavior

The campaign recon pipeline includes:

- Subfinder and passive Amass for subdomain discovery.
- crt.sh certificate transparency and Wayback/GAU URL history.
- The built-in scoped subdomain wordlist (including names such as `api`, `app`, `auth`, and `admin`).
- DNS resolution/enrichment and HTTP/HTTPS probing.
- Technology and login-surface fingerprinting.
- Endpoint discovery from robots.txt, sitemaps, OpenAPI/Swagger, GraphQL paths, and in-scope links, forms, and scripts.
- Nmap and Gobuster as separate, default-off active recon capabilities. Nmap receives only the selected TCP ports intersected with explicit authorization, minus exclusions. Gobuster uses the bundled small wordlist and bounded concurrency.

Nuclei and Dalfox are vulnerability-testing tools, not recon providers; they may only run in an authorized downstream testing phase when that profile permits them. They never count as recon coverage. Sublist3r remains identified as a stub and is never counted as executed discovery.

## Architecture and data flow

1. `NewAssessment` creates, explicitly authorizes, and starts the campaign. Every profile creates one durable recon run before dependent work. `CampaignOperationsService.start_campaign` creates zero vulnerability-check tasks for `RECON_ONLY` and `PLAN_ONLY`; `SAFE_SCAN` and `FULL_AUTHORIZED_SCAN` queue only the checks allowed by their profile and assessment policy, held behind successful recon. The initial campaign snapshot remains immutable and is not overwritten with results.
2. `CampaignWorkerRuntime` claims recon records before ordinary `ExecutionTask` work, recovers stale recon leases, and does not dispatch dependent checks until the shared recon run succeeds. `RECON_ONLY` and `PLAN_ONLY` never reach the vulnerability check execution branch.
3. The worker builds one `ReconContext` from the campaign's concrete target, active authorization record, program scope (including exclusions), request budget, recorded operator confirmation, and mode policy. The same saved authorization/scope checks must pass immediately before dispatch in every mode.
4. One canonical recon result contract is used by user-facing scan and campaign entry points. The campaign-facing service runs the same configured passive providers and built-in wordlist in every profile, normalizes and deduplicates results, and preserves provider provenance/status. It combines provider discovery with HTTP, technology/login-surface, and endpoint-discovery inventory without duplicating requests. The result is persisted and made available to Plan Only and downstream authorized checks; the standard scan orchestrator adapts to the same contract rather than maintaining a separate recon data shape.
5. Every discovered hostname is rechecked against in-scope and out-of-scope rules before DNS enrichment or any HTTP request. Out-of-scope rules win. Discovery alone never grants authorization. Requests continue through the existing request engine and its destination-safety and request-budget controls.
6. Nmap and Gobuster run only when individually selected in campaign preflight and authorized for the campaign, regardless of campaign mode. Nmap's effective port set is the intersection of selected profile and explicit `allowed_ports`, minus `excluded_ports`. Empty or malformed authorization fails closed. Gobuster is similarly scope-gated and uses the bundled wordlist and fixed low concurrency.
7. A durable recon-run result stores mode, per-provider status, normalized assets, endpoint and technology observations, output summary, errors, counts, and evidence/provenance and is exposed in campaign details. Every provider/tool is recorded as executed, unavailable, blocked, failed, or stub-only; missing required providers block target traffic and dependent checks. No vulnerability check IDs execute or count as verified findings in Recon Only or Plan Only.
8. The recon result is the input to mode-specific downstream work: `PLAN_ONLY` produces a non-executed check plan; `SAFE_SCAN` and `FULL_AUTHORIZED_SCAN` select eligible checks using the recon result and available shared authentication context, then pass candidates and evidence through verification and finding analysis. Recon Only stops after recon.
9. Reporting consumes both the recon result and applicable downstream records. Recon Only gets a documented recon report; Plan Only gets recon plus a clearly non-executed plan; scanning modes get recon coverage alongside actual check, verification, impact, remediation, and reportable-finding outcomes. Reports distinguish not tested, tested with no finding, inconclusive, blocked, failed, and skipped; zero vulnerability checks must never be presented as a clean vulnerability assessment.

The current campaign start path auto-queues vulnerability checks regardless of campaign mode, and `CampaignWorker` executes those checks. `CampaignExecutor`'s `RECON_ONLY`/`PLAN_ONLY` branches are not the worker path used by the UI. The legacy `ReconAgent`, `ReconOrchestrator`, newer `UnifiedReconOrchestrator`, and operator live-recon validator also form separate paths. The implementation must establish one canonical recon result contract and shared provider flow for all four scan profiles, gate dependent checks on its result, and avoid duplicate HTTP probing or endpoint requests. The scan profile (`RECON_ONLY`, `PLAN_ONLY`, `SAFE_SCAN`, `FULL_AUTHORIZED_SCAN`) must remain distinct from `assessment_mode` (`CONTROLLED`, `PRODUCTION_AUTHORIZED`).

## User experience

The preflight names the providers and active capabilities that will be used. All four scan profiles show the same passive providers and low-impact inventory. Nmap and Gobuster stay off until selected. Campaign status and the Recon tab show run state/profile, per-provider status, discovered in-scope assets, endpoint counts, technology observations, Nmap effective ports, Gobuster scope, and explicit reasons for skipped or failed work. Recon Only and Plan Only reports visibly state that vulnerability tests did not run; reports for scanning profiles separate recon observations from executed checks and verified findings.

## Safety and error handling

- Authorization expiry, scope mismatch, unsafe destinations, excluded ports, and out-of-scope hosts block the relevant action before network traffic.
- Provider errors are isolated and shown; they do not erase successful results from other providers or masquerade as a clean scan.
- Request and host limits are surfaced with deferred counts; no silent truncation.
- Recon output is evidence of observations only. It does not claim a vulnerability is verified.

## Verification

Use mocked providers and local fixtures to prove all four modes invoke the same required provider sequence and produce the same discovery semantics, while mode-specific gates affect only allowed active work and dependent checks. Also prove the campaign path scope-gates every discovered host before follow-up, reports unavailable/stub providers truthfully, applies port exclusions to Nmap, requires explicit opt-in for Nmap/Gobuster, and executes zero vulnerability checks in `RECON_ONLY` and `PLAN_ONLY`. Do not validate against a third-party target as part of implementation.

## Self-review

- The capability list matches the requested recon workflow and separates active service/path discovery from passive providers.
- Campaign start and worker dispatch are included; merely changing `CampaignExecutor` would not affect the UI path.
- `RECON_ONLY`, `PLAN_ONLY`, `SAFE_SCAN`, and `FULL_AUTHORIZED_SCAN` share the same recon contract and provider flow; profile gates control downstream execution while `assessment_mode` separately controls operational limits.
- Recon Only and Plan Only have report semantics distinct from a completed vulnerability assessment; a zero-task run is never described as a clean scan.
- The mode matrix treats `FULL_AUTHORIZED_SCAN` as a scan profile and `assessment_mode == PRODUCTION_AUTHORIZED` as a separate operational-policy setting while using the same recon pipeline.
- Recon run state/results do not alter the immutable authorization snapshot.
- Existing scan and campaign orchestration paths are accounted for; duplicate requests are explicitly prohibited.
- Authorization remains the gate for use of discovered assets and active probes.
- Stub and vulnerability-testing tools have explicit non-execution behavior.
- Results distinguish discovery observations from verified vulnerabilities.
