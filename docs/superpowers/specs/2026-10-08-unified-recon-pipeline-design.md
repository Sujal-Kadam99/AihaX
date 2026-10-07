# Unified Campaign Reconnaissance Pipeline

**Date:** 2026-10-08  
**Status:** Draft for operator review

## Goal

Every `RECON_ONLY` campaign run should use AihaX's established reconnaissance capabilities through one campaign pipeline. Passive discovery and low-impact web inventory must be visible per provider, respect the campaign's saved authorization and scope, and never be reported as vulnerability verification.

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

1. `NewAssessment` creates, explicitly authorizes, and starts the campaign. `CampaignOperationsService.start_campaign` must detect `RECON_ONLY` and create no vulnerability-check tasks. It instead creates one durable recon run. The existing initial campaign snapshot remains the immutable authorization/scope snapshot and is not overwritten with results.
2. `CampaignWorkerRuntime` claims and executes the pending recon run separately from ordinary `ExecutionTask` check work. It recovers stale recon leases and marks the campaign complete only after the recon run reaches a terminal state. A `RECON_ONLY` campaign never reaches the check execution branch in `CampaignWorker.execute_task`.
3. The worker builds a live `ReconContext` from the campaign's concrete target, active authorization record, program scope (including exclusions), request budget, and a recorded operator confirmation. The same saved authorization/scope checks used by campaign execution must pass immediately before dispatch.
4. One campaign-facing recon service runs the configured passive providers and built-in wordlist, normalizes and deduplicates results, and preserves provider provenance and status. It combines provider discovery with the existing HTTP, technology/login-surface, and endpoint-discovery inventory without duplicating requests.
5. Every discovered hostname is rechecked against in-scope and out-of-scope rules before DNS enrichment or any HTTP request. Out-of-scope rules win. Discovery alone never grants authorization. Requests continue through the existing request engine and its destination-safety and request-budget controls.
6. Nmap and Gobuster run only when individually selected in campaign preflight and authorized for the campaign. Nmap's effective port set is the intersection of selected profile and explicit `allowed_ports`, minus `excluded_ports`. Empty or malformed authorization fails closed. Gobuster is similarly scope-gated and uses the bundled wordlist and fixed low concurrency.
7. A durable recon-run result stores per-provider status, output summary, errors, counts, and evidence/provenance and is exposed in campaign details. Every provider/tool is recorded as executed, unavailable, blocked, failed, or stub-only; missing required providers block launch before target traffic. No vulnerability check IDs are executed or counted as verified findings by `RECON_ONLY`.

The current campaign start path auto-queues vulnerability checks regardless of campaign mode, and `CampaignWorker` executes those checks. `CampaignExecutor`'s `RECON_ONLY` branch is not the worker path used by the UI. The legacy `ReconOrchestrator` and newer `UnifiedReconOrchestrator` also form separate paths. The implementation must correct campaign dispatch first, establish one campaign-facing pipeline, and avoid duplicate HTTP probing or endpoint requests when adapting provider output.

## User experience

The preflight names the providers and active capabilities that will be used. Passive providers and low-impact inventory run as part of recon. Nmap and Gobuster stay off until selected. Campaign status and the Recon tab show run state, per-provider status, discovered in-scope assets, endpoint counts, technology observations, Nmap effective ports, Gobuster scope, and explicit reasons for skipped or failed work.

## Safety and error handling

- Authorization expiry, scope mismatch, unsafe destinations, excluded ports, and out-of-scope hosts block the relevant action before network traffic.
- Provider errors are isolated and shown; they do not erase successful results from other providers or masquerade as a clean scan.
- Request and host limits are surfaced with deferred counts; no silent truncation.
- Recon output is evidence of observations only. It does not claim a vulnerability is verified.

## Verification

Use mocked providers and local fixtures to prove the campaign path invokes the configured recon suite once, scope-gates every discovered host before active follow-up, reports unavailable/stub providers truthfully, applies port exclusions to Nmap, requires explicit opt-in for Nmap/Gobuster, and executes zero vulnerability checks in `RECON_ONLY`. Do not validate against a third-party target as part of implementation.

## Self-review

- The capability list matches the requested recon workflow and separates active service/path discovery from passive providers.
- Campaign start and worker dispatch are included; merely changing `CampaignExecutor` would not affect the UI path.
- Recon run state/results do not alter the immutable authorization snapshot.
- Both existing orchestration paths are accounted for; duplicate requests are explicitly prohibited.
- Authorization remains the gate for use of discovered assets and active probes.
- Stub and vulnerability-testing tools have explicit non-execution behavior.
- Results distinguish discovery observations from verified vulnerabilities.
