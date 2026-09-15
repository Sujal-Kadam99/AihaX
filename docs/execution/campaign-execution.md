# AihaX — Bug Bounty Campaign Execution Pipeline

## Overview

The AihaX Bug Bounty Execution Engine provides a deterministic, scope-bounded, and evidence-driven pipeline for executing security assessments across authorized targets.

---

## 1. Architecture Flow

```text
Campaign
    ↓
Scope (Default-Deny)
    ↓
Asset Normalization & Deduplication
    ↓
Target Selection
    ↓
Check Planning (Capability & Auth Filtering)
    ↓
Request Budget (Campaign / Target / Check)
    ↓
RequestEngine (Rate Limits + Concurrency + Safe Mode)
    ↓
C001–C077 Checks
    ↓
Candidate Evidence (Strictly CANDIDATE Status)
    ↓
VerificationEngine (Deterministic Multi-Strategy)
    ↓
Finding Deduplicator (Stable Fingerprints & Merging)
    ↓
Severity + Confidence (Decoupled & Computed)
    ↓
Bug-Bounty Report Generator (Anti-Hallucination)
```

---

## 2. Core Pipeline Components

### A. Asset Normalization & Scope Pre-Flight (`AssetNormalizer` & `ScopeValidator`)
- Every discovered URL or hostname is normalized into a `CanonicalAsset`.
- Subdomain isolation is strictly preserved (e.g. `example.com` vs `api.example.com`).
- ScopeValidator operates on **Default-Deny**: Any out-of-scope asset produces **0 network bytes**.

### B. Deterministic Check Planning (`CheckPlanner`)
- Replaces ad-hoc check invocation with reproducible `CheckExecutionPlan`.
- Validates capability boundaries (`HTTP`, `BROWSER`, `WORKFLOW`).
- If prerequisites are missing (e.g. missing browser engine or missing authentication credentials), the check is planned as `PREREQUISITE_MISSING` / `NOT_APPLICABLE` without fabricating mock findings.

### C. Hierarchical Request Budget (`CampaignRequestBudget`)
- **Campaign Budget**: Global request ceiling for the assessment (e.g. 500 requests).
- **Target Budget**: Per-target request ceiling (e.g. 100 requests).
- **Check Budget**: Per-check execution budget (e.g. 20 requests).
- When a budget limit is reached, execution halts immediately and logs a `budget_exhausted` event.

### D. Campaign Execution Orchestrator (`CampaignExecutor`)
- Implemented in `backend/services/campaign_executor.py`.
- Coordinates check execution through centralized `RequestEngine` with bounded concurrency (`asyncio.Semaphore`).
- Manages candidate creation, deterministic verification, deduplication, and report DTO generation.
