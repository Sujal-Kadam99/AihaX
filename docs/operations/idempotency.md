# AihaX Phase 8 — Idempotency Protections

## 1. Idempotent Task Creation
Tasks carry a unique `idempotency_key` constructed from:
`campaign_id | check_id | endpoint_url | parameter_name`
Re-issuing or re-queueing the same check against the same endpoint returns the existing task record without creating duplicates.

## 2. Idempotent Target Ingestion
Targets are uniquely constrained by `(campaign_id, normalized_url)`. Adding the same asset multiple times resolves to the single existing canonical target record.

## 3. Idempotent Snapshots
Configuration and registry snapshots are keyed by `campaign_id` with deterministic SHA-256 content hashes.
