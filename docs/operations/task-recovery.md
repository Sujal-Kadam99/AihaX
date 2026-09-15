# AihaX Phase 8 — Task Queue, Atomic Leases & Crash Recovery

## 1. Concurrency & Worker Lease Model
To prevent race conditions, duplicate check execution, and split-brain states across workers:
1. **Atomic Claiming:** Tasks in `PENDING` or `RETRY_PENDING` are claimed via `claim_tasks()` using atomic database queries with an updated worker lease timestamp.
2. **Worker Leases:** When a worker claims a task, it receives a lease (e.g., 60 seconds) stored in `lease_expires_at`.
3. **Lease Renewal:** Long-running tasks must periodically invoke `renew_task_lease()` to prevent early recovery.
4. **Completion:** Upon successful check execution, `complete_task()` transitions the task to `COMPLETED` and clears the lease.

## 2. Crash Recovery & Stale Lease Reclamation
If a worker process crashes, terminates abruptly, or loses connectivity:
1. The lease timestamp `lease_expires_at` naturally elapses.
2. The `CampaignOperationsService.recover_stale_tasks()` background coordinator queries all tasks where `status IN ('CLAIMED', 'RUNNING')` and `lease_expires_at < utc_now()`.
3. If `attempt_count < max_retries`, the task is reset to `RETRY_PENDING` and unassigned (`worker_id = None`), allowing another healthy worker to claim it.
4. If `attempt_count >= max_retries`, the task is marked `FAILED` with failure reason `"Worker lease expired and maximum retries exceeded"`.
