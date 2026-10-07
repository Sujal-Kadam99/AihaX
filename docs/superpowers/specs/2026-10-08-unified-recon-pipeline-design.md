# Unified Campaign Reconnaissance Pipeline

**Date:** 2026-10-08  
**Status:** Draft for operator review

## Goal

Whenever AihaX performs reconnaissance in Safe Scan, Recon Only, Plan Only, or Fully Authorized mode, it must use the same campaign reconnaissance pipeline. Passive discovery, low-impact web inventory, provenance, and result semantics stay consistent across modes. Mode and authorization change which additional actions may run; they do not select a different recon method.

## Mode behavior

- `RECON_ONLY`: run the shared recon pipeline and no vulnerability checks.
- `PLAN_ONLY`: run the shared recon pipeline, then build the check plan; execute no vulnerability checks.
- `SAFE_SCAN`: run the shared recon pipeline before configured safe checks. Nmap and Gobuster remain off unless separately selected and authorized.
- Fully Authorized (`assessment_mode == PRODUCTION_AUTHORIZED`): run the same recon pipeline before authorized checks. Nmap and Gobuster still require explicit per-run selection and saved scope/port authorization; the broader campaign mode does not implicitly enable them.
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

Nuclei and Dalfox remain outside `RECON_ONLY`: they perform vulnerability testing, not asset and surface reconnaissance. Sublist3r remains identified as a stub and is never counted as executed discovery.

## Architecture and data flow

1. `NewAssessment` creates, explicitly authorizes, and starts the campaign. Every mode whose flow performs recon creates one durable recon run before dependent check work. `CampaignOperationsService.start_campaign` creates zero vulnerability-check tasks for `RECON_ONLY` and `PLAN_ONLY`; Safe Scan and Fully Authorized checks remain queued behind successful recon. The initial campaign snapshot remains immutable and is not overwritten with results.
2. `CampaignWorkerRuntime` claims recon records before ordinary `ExecutionTask` work, recovers stale recon leases, and does not dispatch dependent checks until the shared recon run succeeds. `RECON_ONLY` and `PLAN_ONLY` never reach the vulnerability check execution branch.
3. The worker builds one `ReconContext` from the campaign's concrete target, active authorization record, program scope (including exclusions), request budget, recorded operator confirmation, and mode policy. The same saved authorization/scope checks must pass immediately before dispatch in every mode.
4. One campaign-facing recon service runs the same configured passive providers and built-in wordlist in every mode, normalizes and deduplicates results, and preserves provider provenance/status. It combines provider discovery with HTTP, technology/login-surface, and endpoint-discovery inventory without duplicating requests. Recon results are available to Plan Only and downstream authorized checks.
5. Every discovered hostname is rechecked against in-scope and out-of-scope rules before DNS enrichment or any HTTP request. Out-of-scope rules win. Discovery alone never grants authorization. Requests continue through the existing request engine and its destination-safety and request-budget controls.
6. Nmap and Gobuster run only when individually selected in campaign preflight and authorized for the campaign, regardless of campaign mode. Nmap's effective port set is the intersection of selected profile and explicit `allowed_ports`, minus `excluded_ports`. Empty or malformed authorization fails closed. Gobuster is similarly scope-gated and uses the bundled wordlist and fixed low concurrency.
7. A durable recon-run result stores mode, per-provider status, output summary, errors, counts, and evidence/provenance and is exposed in campaign details. Every provider/tool is recorded as executed, unavailable, blocked, failed, or stub-only; missing required providers block target traffic and dependent checks. No vulnerability check IDs execute or count as verified findings in Recon Only or Plan Only.

The current campaign start path auto-queues vulnerability checks regardless of campaign mode, and `CampaignWorker` executes those checks. `CampaignExecutor`'s `RECON_ONLY`/`PLAN_ONLY` branches are not the worker path used by the UI. The legacy `ReconOrchestrator`, newer `UnifiedReconOrchestrator`, and operator live-recon validator also form separate paths. The implementation must establish one shared campaign pipeline for all four modes, gate dependent checks on its result, and avoid duplicate HTTP probing or endpoint requests.

## User experience

The preflight names the providers and active capabilities that will be used. All four modes show the same passive providers and low-impact inventory. Nmap and Gobuster stay off until selected. Campaign status and the Recon tab show run state/mode, per-provider status, discovered in-scope assets, endpoint counts, technology observations, Nmap effective ports, Gobuster scope, and explicit reasons for skipped or failed work.

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
- Safe, Recon Only, Plan Only, and Fully Authorized modes share the same recon service; mode gates only suppress disallowed actions and dependent work.
- The mode matrix distinguishes `SAFE_SCAN` from `assessment_mode == PRODUCTION_AUTHORIZED` while using the same recon pipeline.
- Recon run state/results do not alter the immutable authorization snapshot.
- Both existing orchestration paths are accounted for; duplicate requests are explicitly prohibited.
- Authorization remains the gate for use of discovered assets and active probes.
- Stub and vulnerability-testing tools have explicit non-execution behavior.
- Results distinguish discovery observations from verified vulnerabilities.
