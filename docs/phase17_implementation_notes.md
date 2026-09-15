# Phase 17 — First Real Authorized Bug-Bounty Assessment: Implementation Notes

## Stage 0 Repository Audit Summary

### 1. Existing Architecture & Reusable Components
AihaX provides a certified, hardened baseline established through Phases 1–16:
- **Centralized Network Request Path**: `RequestEngine` in `backend/services/request_engine.py` with `ScopeValidator`, concurrency semaphore, token-bucket rate limiting, granular timeouts, secret redaction, and SHA-256 evidence capture.
- **Safety Boundary Gating**: `validate_concrete_target_url` (prohibiting wildcards, CIDR, bare domains, malformed URLs) and `validate_destination_safety` (prohibiting cloud metadata 169.254.169.254, link-local, loopback, private IPs, and non-HTTP schemes) in `backend/core/scope_validator.py`.
- **Preflight Checklist & Lifecycle Orchestration**: `CampaignOperationsService` in `backend/services/campaign_operations.py` enforcing immutable execution plans, scope snapshot integrity, active authorization, server-side request budgets, and kill switch checks.
- **Worker & Lease Mechanics**: `CampaignWorker` in `backend/services/campaign_worker.py` handling task claims, heartbeats, non-resurrection of cancelled/killed tasks, and bounded retries.
- **Cryptographic Evidence & Audit Trail**: `EvidenceVault` and `ManifestBuilder` in `backend/evidence/` with content-addressed hashing and hash-chained audit trails.
- **Check Registry**: 77 non-destructive security checks registered in `CheckRegistry`.
- **Finding Lifecycle & Deduplication**: Deterministic deduplication in `backend/services/finding_deduplicator.py` and `VerificationEngine`.
- **Bug-Bounty Data Models**: `Program` and `BugBountyScopeAsset` in `backend/models/database.py` with `POST /api/programs/import` and `POST /api/campaigns/import-program`.

### 2. Missing Functionality / Enhancements for Phase 17
1. **`WAITING_FOR_TARGET` Workflow**:
   - `create_production_campaign(..., target_url=None)` must support creating campaigns in `awaiting_target=True` state.
   - `supply_concrete_target(campaign_id, target_url, operator_confirmation, actor)` to safely bind an operator-supplied concrete target to an awaiting campaign, validate scope against the imported program, validate destination safety with `allow_loopback=False`, recompute scope snapshot and execution plan, and emit required audit events.
2. **Worker Gating on `awaiting_target`**:
   - Explicit check in `claim_tasks_for_worker` and `run_task` to prevent any task claiming or execution if `awaiting_target==True`.
3. **Complete Audit Event Sequence**:
   - Emit all required Phase 17 audit events: `PROGRAM_IMPORTED`, `AUTHORIZATION_CONFIRMED`, `PRODUCTION_CAMPAIGN_CREATED`, `TARGET_SUPPLIED`, `TARGET_SCOPE_VALIDATED`, `DESTINATION_SAFETY_PASSED`, `ASSESSMENT_PREFLIGHT`, `EXECUTION_STARTED`, `CHECK_STARTED`, `REQUEST_DISPATCHED`, `EVIDENCE_RECORDED`, `FINDING_CANDIDATE`, `FINDING_VERIFIED`, `FINDING_REJECTED`, `EXECUTION_COMPLETED`, `REPORT_GENERATED`, `CAMPAIGN_KILLED`.
4. **API Endpoints**:
   - `POST /api/campaigns/{campaign_id}/target` to supply concrete target URL.
5. **Test Suite**:
   - `backend/tests/test_phase17_first_real_assessment.py` covering all 36+ test scenarios with `MockTransport`.
6. **Certification Script**:
   - `scripts/verify_phase17_first_real_assessment.py` with 52 deterministic checkpoints.

### 3. Security Invariants & Non-Negotiable Boundaries
- **WILDCARD SCOPE IS NOT A TARGET**: Wildcards (`*.xiaomi.com`, `*.mi.com`) are authorization boundary rules only, NEVER executable targets.
- **PRODUCTION_AUTHORIZED MEANS ONE CONCRETE TARGET PER CAMPAIGN**: Only one concrete, non-wildcard target URL is allowed per campaign.
- **CONSERVATIVE PRODUCTION PROFILE**: Server-side enforced `budget=10`, `concurrency=1`, `rate_limit=2 RPS`, `methods=GET/HEAD/OPTIONS only`.
- **FAIL CLOSED**: Any missing authorization, expired token, out-of-scope target, unsafe destination, or tampering fails closed with 0 requests sent.
- **ZERO EXTERNAL NETWORK IN AUTOMATED TESTS**: All test and certification executions use `MockTransport` with 0 external network requests.
