# AihaX Phase 8 — Campaign Lifecycle & State Machine

## 1. Overview
AihaX implements a deterministic, fail-closed state machine for penetration testing and bug-bounty campaigns. State transitions are strictly enforced and audit-logged with cryptographic chaining.

## 2. State Machine Diagram

```text
       ┌──────────┐
       │  DRAFT   ├────────────────────────┐
       └────┬─────┘                        │
            │ (authorize)                  │
            ▼                              │
       ┌──────────┐                        │
       │AUTHORIZED├───────────┐            │
       └────┬─────┘           │            │
            │ (queue)         │ (start)    │ (cancel)
            ▼                 │            │
       ┌──────────┐           │            │
       │  QUEUED  │           │            │
       └────┬─────┘           │            │
            │ (start)         │            │
            ▼                 ▼            │
       ┌────────────────────────┐          │
       │        RUNNING         │          │
       └───┬─────────────┬──────┘          │
           │ (pause)     │ (complete)      │
           ▼             ▼                 │
     ┌──────────┐  ┌───────────┐           │
     │  PAUSED  │  │ COMPLETED │ (terminal)│
     └───┬──────┘  └───────────┘           │
         │ (resume)                        │
         └────────► [RUNNING]              │
                                           ▼
                                    ┌───────────┐
                                    │ CANCELLED │ (terminal)
                                    └───────────┘
```

## 3. Lifecycle States

| State | Description | Invariants |
|---|---|---|
| `DRAFT` | Initial state upon creation. Targets and snapshot defined. | No network traffic allowed. No worker tasks dispatched. |
| `AUTHORIZED` | Scope verified and signed by authorized party. | Cannot start without active, unexpired `AuthorizationRecord`. |
| `QUEUED` | Execution graph and tasks created in database. | Awaiting worker claim leases. |
| `RUNNING` | Active execution. Workers atomically claim tasks under time leases. | Budget and concurrency bounds strictly enforced. |
| `PAUSED` | Execution temporarily halted. | No new tasks claimed; running tasks allowed to finish safely. |
| `COMPLETED` | All tasks finished. Final manifest computed. | Terminal state. Cannot transition back to `RUNNING`. |
| `CANCELLED` | Operator aborted campaign. | Pending and claimed tasks marked `CANCELLED`. |
| `FAILED` | Unrecoverable error occurred. | Terminal state. |

## 4. Transition Rules & API

* `create_campaign()`: Creates in `DRAFT`.
* `authorize_campaign()`: `DRAFT -> AUTHORIZED`. Fails closed if expired or invalid.
* `queue_campaign()`: `AUTHORIZED -> QUEUED`.
* `start_campaign()`: `AUTHORIZED / QUEUED -> RUNNING`.
* `pause_campaign()`: `RUNNING -> PAUSED`.
* `resume_campaign()`: `PAUSED -> RUNNING`.
* `cancel_campaign()`: `DRAFT / AUTHORIZED / QUEUED / RUNNING / PAUSED -> CANCELLED`.
* `complete_campaign()`: `RUNNING -> COMPLETED`.
