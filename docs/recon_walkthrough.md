# AihaX Reconnaissance Walkthrough

## 1. Audit Mode Walkthrough

1. Operator initializes a scan with `execution_mode = "AUDIT"`.
2. `ReconPreflightGate` verifies target concreteness, scope, and safety. Emits warning that external providers are disabled.
3. `UnifiedReconOrchestrator` invokes mock adapters for Subfinder, Amass, CT, DNS, and HTTP probing.
4. Mocks return deterministic synthetic assets.
5. Assets are normalized and validated through `ScopeValidator`.
6. Observations are recorded with deterministic SHA-256 evidence hashes.
7. `CanonicalReconSnapshot` is created with unique snapshot hash.
8. External network traffic: **0**.

## 2. Dry Run Mode Walkthrough

1. Operator specifies `execution_mode = "DRY_RUN"`.
2. `ReconPreflightGate` confirms configuration.
3. Providers generate command and query plans without making network calls or spawning processes.
4. Returns planned providers, commands, and budget estimates.
5. External network traffic: **0**.

## 3. Authorized Live Recon Mode Walkthrough

1. Operator selects `AUTHORIZED_LIVE_RECON`.
2. Supplies `authorization_record_id`, concrete target, and confirms prompt:
   `LIVE RECON WILL CONTACT EXTERNAL INFRASTRUCTURE`.
3. Preflight succeeds: status `READY`.
4. Real adapters invoke approved CLI tools (`subfinder`, `amass`) via `ToolExecutionBoundary` (safe argv, `shell=False`, timeout bounded).
5. Real CT queries route through `RequestEngine`.
6. Discovered subdomains are evaluated against `ScopeValidator`. In-scope subdomains are recorded; out-of-scope subdomains are blocked.
7. Discovered assets remain tagged `NOT_EXECUTABLE` (not automatically attacked).
8. Results populate `CanonicalReconSnapshot` and update `AttackSurfaceGraph`.
