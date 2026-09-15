# Human Operator Live Recon Validation Runbook

**STATUS: FINAL HANDOFF READY**

This runbook defines the exact sequence of actions for a Human Security Operator to execute the Live Recon Validation phase. The automated AihaX system has been frozen and will **NOT** initiate live reconnaissance without explicit human authorization via the GUI.

## Required Preparations

1. **Start Backend**: Launch the backend API services (e.g., `docker-compose up -d --build` or via `scripts/dev-start.bat`).
2. **Start Frontend**: Launch the Vite frontend dev server or serve the built production application.
3. **Open AihaX**: Navigate your web browser to the AihaX GUI (e.g., `http://localhost:3000`).

## Operator Execution Workflow

**IMPORTANT:** The automated AihaX engine relies strictly on human review and confirmation prior to initiating any live network traffic.

4. **Select Authorized Campaign**: From the main dashboard or campaigns list, select the campaign you are authorized to test (e.g., the specific campaign for `mitacsc.ac.in`).
5. **Open Live Recon Preflight**: Navigate to the Live Recon Validation or Preflight tab within the campaign view.
6. **Verify Authorization**: Confirm that the system displays an `ACTIVE` authorization record mapped to your Operator ID. If it is `MISSING` or `EXPIRED`, **STOP IMMEDIATELY**.
7. **Verify Target**: Ensure the target is exactly as authorized. The system strictly forbids automatic expansion to subdomains or third-party properties without separate authorization.
8. **Verify Scope**: Ensure the scope hash validates perfectly against the current execution boundaries.
9. **Verify Capabilities**: Check the capability permissions (Passive, Historical, Controlled Discovery, Service Discovery, Active Security). Only tools aligning with these exact permissions will be permitted to execute.
10. **Verify Safety Budget**: Confirm the request/time budget allocations are correctly bounded and meet policy constraints (e.g., Concurrency = 1).
11. **Complete Required Confirmations**: Acknowledge and sign off on the required operator confirmation checkboxes presented by the Preflight GUI. The backend will independently re-verify these signals upon launch.

### Execution

12. **Click Launch Live Validation**: Click the execution button. This sends an explicit `mode="live"` POST request to `/api/campaigns/{campaign_id}/recon-live-validation`.

### Monitoring & Validation

13. **Monitor Tool-by-Tool Results**: The execution runs synchronously (or asynchronously through websockets). Monitor the tool statuses as they evolve. The final status **MUST** reflect ground truth.
    - `LIVE_VALIDATED`: Actual live execution succeeded.
    - `AUTH_REQUIRED` / `BLOCKED_POLICY`: Execution stopped by security boundary.
    - `UNAVAILABLE` / `STUB_ONLY`: Tool not provisioned or implemented.
14. **Review Evidence**: Validate the captured command-line arguments, start/end timestamps, stdout/stderr hashes, and cryptographically bound execution traces.
15. **Review ReconSnapshot**: Confirm the snapshot safely integrated the results without unauthorized data creep.
16. **Review AttackSurfaceGraph**: Validate the newly mapped assets maintain accurate provenance.
17. **Review Traffic Accounting**: Verify the actual request counts do not exceed safety budgets.

## Expected Live Tool Behaviors

* **Subfinder**: PASSIVE ONLY.
* **Amass**: PASSIVE ONLY.
* **GAU**: HISTORICAL DISCOVERY ONLY.
* **Certificate Transparency (CT)**: PASSIVE ONLY.
* **Wayback**: HISTORICAL DISCOVERY ONLY.
* **DNS**: BOUNDED ONLY.
* **HTTP/HTTPS**: Requests constrained exclusively to the authorized target via `RequestEngine`.
* **WhatWeb**: LOW-IMPACT ONLY.
* **Naabu**: BOUNDED SERVICE DISCOVERY ONLY.
* **Nmap**: BOUNDED SERVICE DISCOVERY ONLY. No unrestricted scanning, exploit NSEs, or brute force.
* **Gobuster**: Executes ONLY if explicit `CONTENT_DISCOVERY` authorization is present. Otherwise, blocks with `AUTH_REQUIRED`.
* **Nuclei**: Executes ONLY if `VULNERABILITY_DETECTION` is authorized. Constrained to safe template sets. No destructive actions.
* **Dalfox**: Executes ONLY if `SPECIALIZED_ACTIVE_TESTING` is authorized.
* **Sublist3r**: `STUB_ONLY` if unimplemented.

## Hard Stop Conditions

**ABORT IMMEDIATELY IF YOU OBSERVE:**
* Authorization is invalid, expired, or missing.
* Target or Scope mismatches expectations.
* Unsafe redirects off the authorized target domain.
* Non-HTTPS requests (unless specifically authorized for plaintext discovery).
* Safety budget overrun (e.g., excessive request rate).
* Concurrency > 1 for live operational scanning.
* Raw network bypasses (tool bypassing `ToolExecutionBoundary`).
* Evidence persistence failure.
* Unauthorized destructive behavior or automatic target expansion.

## Export & Finalization

19. **Export Validation Report**: Generate the official report combining the evidence references, traffic accounting, and tool verdicts.
