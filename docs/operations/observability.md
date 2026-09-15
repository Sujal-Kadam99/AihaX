# AihaX Phase 8 — Structured Observability & Operational Metrics

## 1. Low-Cardinality Metrics Model
To prevent metric cardinality explosions and memory leaks in production, all metrics adhere strictly to low-cardinality label designs:
* No URLs in labels
* No query parameters
* No tokens or secrets
* No user IDs or raw payloads

## 2. Collected Metric Counters
* **Campaigns:** `campaigns_total`, `campaigns_running`, `campaigns_completed`, `campaigns_failed`, `campaigns_paused`, `campaigns_cancelled`
* **Tasks:** `tasks_total`, `tasks_pending`, `tasks_claimed`, `tasks_running`, `tasks_completed`, `tasks_failed`, `tasks_retried`, `tasks_recovered_stale`
* **Requests:** `requests_total`, `requests_blocked_scope`, `requests_blocked_budget`, `requests_failed`
* **Findings:** `findings_candidates`, `findings_verified`, `findings_reportable`, `findings_blocked`
* **Evidence:** `evidence_created`, `evidence_integrity_failures`
* **Coverage:** `coverage_checks_executed`, `coverage_checks_skipped`

## 3. Query API
`GET /api/campaigns/metrics/operational` returns the current `OperationalMetricsSnapshot`.
