# AihaX Phase 8 — Persistence Layer Architecture

## 1. Database Architecture
AihaX utilizes SQLite with enterprise-grade operational settings:
* **WAL Mode:** Write-Ahead Logging (`PRAGMA journal_mode=WAL;`) for concurrent read/write throughput.
* **Busy Timeout:** 5000ms (`PRAGMA busy_timeout=5000;`) to prevent transient lock failures under concurrency.
* **Foreign Keys:** Strictly enforced (`PRAGMA foreign_keys=ON;`).
* **Synchronous:** `NORMAL` for optimal durability and write performance.

## 2. ORM Models (`backend/persistence/models.py`)

1. **`Campaign` (`campaigns`)**:
   Stores campaign configuration, execution mode, status, budget limits, requests used, and cryptographic hashes (`scope_snapshot_hash`, `config_hash`, `registry_hash`, `manifest_hash`).

2. **`CampaignTarget` (`campaign_targets`)**:
   Tracks per-target normalization, scope status, authorization status, recon status, and per-target request consumption.

3. **`ExecutionTask` (`campaign_tasks`)**:
   Persistent task queue records with worker leases (`worker_id`, `lease_expires_at`), attempt counts, max retries, budget reservations, and unique idempotency keys.

4. **`AuthorizationRecord` (`authorization_records`)**:
   Verifiable authorization proof anchoring authorized party, consent type, expiration datetime, and scope SHA-256 hash.

5. **`EvidenceRecord` (`evidence_records`)**:
   Vault storage for secret-redacted request/response pairs, content hashes, and sequential chain hashes.

6. **`AuditTrailEvent` (`audit_trail_events`)**:
   Tamper-evident chained audit trail records linking previous event hashes to guarantee immutability.

7. **`CampaignSnapshot` (`campaign_snapshots`)**:
   Immutable snapshot of target scope, selected checks, and registry version at campaign initialization.

## 3. Migration 16
Migration 16 (`016_phase8_persistent_campaign_vault`) was added to `backend/models/migrations.py` with automatic pre-migration backup and SHA-256 checksum validation.
