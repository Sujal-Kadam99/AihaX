# AihaX Full-Port Recon Background Job Design

**Date:** 2026-10-07  
**Status:** Draft for operator review  
**Approved direction:** Durable background job with per-host progress, cancellation, and saved results.

## Problem

AihaX currently performs live recon synchronously through `OperatorLiveReconService.execute_validation_run`. The Nmap tool definition has a 60-second default and a 120-second maximum, and discovered-host follow-up is capped at 100 hosts. A full TCP scan of ports 1–65535 on each discovered host therefore cannot be represented reliably by the existing request/response flow.

The requested behavior is a complete TCP port scan for every discovered host that remains in the campaign's authorized scope, with explicitly excluded ports omitted. A successful run must preserve per-host evidence and make incomplete, blocked, cancelled, and timed-out work visible.

## Goals

- Queue every discovered host that passes the campaign's in-scope and out-of-scope rules, without silently dropping hosts at the current fixed 100-host limit.
- Scan the full authorized TCP port range, 1–65535, minus excluded ports. The campaign's `allowed_ports` must explicitly cover the requested ports; this feature does not expand authorization.
- Run hosts sequentially with one Nmap process at a time and a conservative TCP connect profile.
- Return quickly from the launch request and expose durable run state, per-host progress, cancellation, and saved results.
- Resume queued work after an application restart without repeating completed hosts.
- Preserve the scope snapshot, exclusions, Nmap arguments, output hashes, statuses, and timestamps as audit evidence.
- Report partial completion truthfully when an individual host fails, times out, is blocked, or the operator cancels the run.

## Non-goals

- No vulnerability templates, NSE scripts, exploit attempts, credential testing, fuzzing, brute force, UDP scan, or service-version detection in this full-port workflow.
- No direct IP targets unless the IP itself is in scope. Hostnames are resolved only through the existing destination-safety controls.
- No promise that a complete scan is risk-free, fast, accepted by a bounty program, or guaranteed to find a vulnerability.
- Mobile and non-web reconnaissance remain outside this feature.

## Scope and port rules

1. The program's saved in-scope and out-of-scope asset rules remain authoritative for every discovered hostname. Out-of-scope rules override in-scope rules.
2. Before a full TCP scan can be launched, the program's `allowed_ports` must explicitly cover ports 1–65535. A narrower authorized range can be used only with a correspondingly narrower scan profile; it is not labeled a full-port scan.
3. `excluded_ports` are subtracted from the selected ports even if also present in `allowed_ports`.
4. Discovery and full-port scanning use two confirmation stages. First, AihaX discovers and scope-checks hosts without Nmap traffic. The operator reviews the in-scope host list/count, effective port range, exclusions, and planned host-by-port workload, then separately confirms the full scan.
5. Invalid or missing port authorization blocks service discovery; an empty allowlist never means “all ports.”

## Proposed architecture

### Durable records

Add a recon run record linked to the campaign, storing run state, authorization ID, scope hash, port profile, compressed allowed/excluded/selected port ranges, timestamps, cancellation request, current host, and aggregate counts. Add one child host record per authorized discovered host, storing provenance, scope decision, host state, start/end times, Nmap execution/evidence identifiers, output hashes, and failure detail.

The host queue is persisted after discovery and before port scans begin. A unique `(run_id, normalized_host)` constraint prevents duplicate work. Completed hosts are immutable for that run; retrying or resuming affects only unfinished eligible hosts.

### Worker lifecycle

Use a background worker integrated with AihaX startup/shutdown lifecycle. A new run starts in `DISCOVERING`; it performs passive/low-impact discovery and scope classification, then pauses in `AWAITING_SCAN_CONFIRMATION` with the exact host list and workload estimate. Only a separate operator confirmation transitions it to `QUEUED`. The worker claims queued runs with a renewable lease, revalidates active authorization and the scope snapshot before work, and processes one host at a time. On restart, it recovers expired leases and resumes pending hosts. A run with no remaining pending hosts becomes completed, partial, cancelled, or failed according to its host outcomes.

The existing generic campaign task worker is not reused as-is: it executes vulnerability check tasks and its completion semantics would conflate a long-running recon job with campaign assessment completion. The new worker should reuse existing authorization, audit, persistence, and cancellation primitives where compatible.

### Nmap execution and cancellation

For each host, invoke the Nmap adapter only through `ToolExecutionBoundary`, with the original scope rules, `allowed_ports`, and `excluded_ports` carried into the boundary request. Use TCP connect scan (`-sT`), conservative timing (`-T2`), and the compressed exact selected-port set. Do not use Nmap scripts, version detection, or additional probes.

The execution boundary must support a cancellation signal while a subprocess is active. On cancellation it terminates and reaps the current Nmap process, records the host as cancelled/interrupted, then stops before claiming another host. A bounded per-host process timeout remains configurable; timeout results are partial and are never reported as a completed full scan.

Progress is reported per host (index, hostname, queued/running/completed/blocked/failed/timed-out/cancelled). Port-level progress is not required in the first release unless the existing process adapter can expose it without buffering unbounded output.

### API and UI

- `POST /api/campaigns/{campaign_id}/recon-live-runs` validates authorization and scope, creates a discovery run, and returns `202` with `run_id` and `DISCOVERING` status. It performs no port scan.
- `POST /api/campaigns/{campaign_id}/recon-live-runs/{run_id}/confirm` revalidates authorization and scope, requires full `1-65535` port coverage and explicit workload confirmation, then queues the scan phase.
- `GET /api/campaigns/{campaign_id}/recon-live-runs/{run_id}` returns aggregate counts, current host, port plan, and per-host status/evidence summary.
- `POST /api/campaigns/{campaign_id}/recon-live-runs/{run_id}/cancel` records a cancellation request and wakes the local worker.
- The UI shows a workload confirmation before launch, then live/polling progress, completed/remaining host counts, cancellation, and downloadable or viewable per-host evidence.
- The existing inline recon flow remains available for passive discovery and the common-web profile. Full-range scans use the background run endpoints.

## State model

Run states: `DISCOVERING`, `AWAITING_SCAN_CONFIRMATION`, `QUEUED`, `RUNNING`, `CANCEL_REQUESTED`, `CANCELLED`, `COMPLETED`, `PARTIAL`, `FAILED`.  
Host states: `PENDING`, `RUNNING`, `COMPLETED`, `BLOCKED_SCOPE`, `BLOCKED_AUTHORIZATION`, `TIMED_OUT`, `FAILED`, `CANCELLED`.

`COMPLETED` means every queued in-scope host completed its selected scan. Any failed, blocked, timed-out, or cancelled host prevents a misleading all-complete result and is reflected in a `PARTIAL` or `CANCELLED` run summary.

## Verification plan

- Unit tests prove full port expansion/compression, exclusion precedence, allowlist enforcement, out-of-scope rejection, and fail-closed behavior for incomplete port coverage.
- Worker tests prove sequential execution, restart recovery, idempotent host completion, cancellation between hosts, and active-process termination.
- API tests prove start returns before scanning completes, progress is durable, only authorized campaign members can access the run, and cancel does not queue further hosts.
- UI tests prove discovery review before launch, workload/port confirmation, progress states, cancellation, and partial-result messaging.
- Use local mocked Nmap/boundary executions and authorized vulnerable labs only. Do not run the tests against the client's production target.

## Operator and safety notes

- Ports 1–65535 contain 65,535 TCP ports; after exclusions the exact selected count is shown before launch.
- Full scans over many subdomains may take hours or longer and generate substantial connection attempts even at conservative timing. The operator must review the host count and workload and confirm client authorization before launch.
- There is no silent fixed 100-host truncation in the proposed behavior. If a future explicit campaign budget limits hosts, the UI and result must show deferred hosts and require an operator choice to continue in another run.
- The initial implementation should not auto-launch full-port scans merely because the service-discovery checkbox is selected; full-range scanning requires a separate explicit profile selection and confirmation.

## Review checklist

- Full scan selection cannot exceed the program's authorized allowed-port range.
- Exclusions win over allowed ports and are visible in both preflight and saved run details.
- No host outside the exact scope rules reaches Nmap.
- Cancellation kills the active subprocess and prevents further hosts from starting.
- Restart recovery never repeats a host already durably marked completed.
- Timeouts and partial results are never labeled complete.
