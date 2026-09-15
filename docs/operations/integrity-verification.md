# AihaX Phase 8 — Cryptographic Integrity Verification & Manifest

## 1. Campaign Manifest Architecture
Every completed campaign is anchored by a cryptographic root manifest:
```text
Campaign Manifest (manifest_hash)
 ├── scope_hash
 ├── config_hash
 ├── execution_graph_hash
 ├── evidence_hashes[] (sorted SHA-256)
 ├── finding_hashes[] (sorted SHA-256)
 ├── coverage_report_hash
 └── report_hashes[]
```

## 2. Integrity Verification (`verify_campaign_integrity()`)
The verification engine performs 4 independent cryptographic audits:
1. **Authorization Validity:** Verifies active, non-expired authorization with matching scope hash.
2. **Snapshot Integrity:** Computes SHA-256 over stored configuration JSON and asserts exact match with `snapshot_hash`.
3. **Evidence Vault Integrity:** Recomputes SHA-256 content hashes for all evidence records and verifies sequential chain hashes.
4. **Audit Trail Integrity:** Walks the audit event log from genesis, recomputing SHA-256 chained hashes and asserting zero broken links or modifications.

Returns a structured `CampaignIntegrityReport` with detailed pass/fail checks and identified issues.
