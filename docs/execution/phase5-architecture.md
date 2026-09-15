# AihaX Phase 5 — Real-Target Vulnerability Execution & Attack-Surface Coverage Architecture

## 1. Executive Summary & Objective

Phase 5 transforms AihaX from an endpoint reconnaissance and static check suite into an active, **parameter-aware vulnerability execution system**. Operating under strict default-deny scope enforcement and non-destructive testing invariants, the Phase 5 engine discovers real parameters across diverse web formats (URL queries, path templates, HTML forms, JSON payloads, multipart uploads, OpenAPI schemas), captures pre-mutation baseline fingerprints, applies deterministic canary mutations through centralized `RequestEngine`, and performs differential analysis to isolate true vulnerability signals from application anomalies.

```
Reconnaissance & Asset Discovery
               ↓
    Discovered Endpoints
               ↓
 ┌───────────────────────────┐
 │ ParameterDiscoveryEngine  │ (URL Query, Path, Form, JSON, Multipart, OpenAPI)
 └─────────────┬─────────────┘
               ↓
 ┌───────────────────────────┐
 │   BaselineCaptureEngine   │ (Status, Headers, Content-Type, SHA-256, Fingerprint)
 └─────────────┬─────────────┘
               ↓
 ┌───────────────────────────┐
 │  ExecutionContext / Graph │ (Scope Gating, Prerequisite Verification, Budget)
 └─────────────┬─────────────┘
               ↓
 ┌───────────────────────────┐
 │   CanaryGenerator Engine  │ (Reflection, Math, SSTI, SQL Syntax, Boolean, LFI)
 └─────────────┬─────────────┘
               ↓
 ┌───────────────────────────┐
 │  ParameterMutationEngine  │ (Replace, Append, Prepend, Type Change, Encoding)
 └─────────────┬─────────────┘
               ↓
 ┌───────────────────────────┐
 │   Central RequestEngine   │ (Pre-probe ScopeValidator, Rate Limiter, Safe Mode)
 └─────────────┬─────────────┘
               ↓
 ┌───────────────────────────┐
 │ResponseDifferentialEngine │ (Signal Extraction, Context Classification, FP Defense)
 └─────────────┬─────────────┘
               ↓
 ┌───────────────────────────┐
 │    VerificationEngine     │ (Non-destructive Multi-strategy Verification)
 └─────────────┬─────────────┘
               ↓
 Verified Bug Bounty Findings & PoC
```

---

## 2. Core Architectural Components

### 2.1 Parameter Discovery (`backend/execution/parameter_model.py` & `parameter_discovery.py`)
- **Strict Evidence Provenance**: Parameters are discovered strictly from observed network fixtures, crawled HTML forms, JavaScript routes, and OpenAPI definitions. Zero synthetic or invented parameters are allowed.
- **Locations Covered**: `QUERY`, `PATH`, `FORM`, `JSON`, `MULTIPART`, `HEADER`, `COOKIE`, and `GRAPHQL_VARIABLE`.
- **Types Inferred**: `STRING`, `INTEGER`, `FLOAT`, `BOOLEAN`, `ARRAY`, `OBJECT`, `FILE`, and `UUID`.

### 2.2 Baseline Capture (`backend/execution/baseline.py`)
- Before sending any active mutation probe, `BaselineCaptureEngine` executes a clean, canonical baseline request against the endpoint.
- Captures: HTTP status code, canonical response headers, content-type, body SHA-256 hash, response latency ($T_{\text{baseline}}$), structural tag skeleton fingerprint, and redirect destination.

### 2.3 Canary Generation (`backend/execution/canary.py`)
- Generates unique, high-entropy, deterministic tokens with matched negative controls:
  - **Reflection**: `<aihax_refl_{check_id}_{token}>` vs `<aihax_ctrl_{token}>`
  - **Mathematical**: `$(( n1 * n2 ))` and `{{ n1 * n2 }}` expecting exact integer product.
  - **SQL Syntax**: Syntactic escape probes (`'token`, `"token`) triggering database dialect syntax errors.
  - **Boolean Differential**: Paired true/false expressions (`1=1` vs `1=2`).
  - **LFI / Path Traversal**: Safe root file markers (`/etc/passwd` root: regex, win.ini extensions).

### 2.4 Mutation Engine (`backend/execution/mutation_engine.py`)
- Constructs structured `RequestSpec` mutations without direct network socket calls.
- Supports `REPLACE`, `APPEND`, `PREPEND`, `TYPE_CHANGE`, `BOUNDARY`, `ENCODING`, and `MULTIPART` mutation strategies.

### 2.5 Response Differential (`backend/execution/differential.py`)
- Evaluates the variance between the baseline response and the mutated response:
  - Reflection context classification: `RAW_HTML`, `HTML_ENCODED`, `ATTRIBUTE`, `JAVASCRIPT`, `JSON`, `HEADER`.
  - Database syntax error extraction vs generic 500 error rejection.
  - Arithmetic evaluation matching and negative-control cancellation.

### 2.6 Execution Context & Graph (`backend/execution/execution_context.py` & `execution_graph.py`)
- Enforces strict prerequisite gating before any check executes:
  - `MISSING_SCOPE`: Out-of-scope targets produce 0 network bytes.
  - `MISSING_PARAMETER`: Parameter-dependent checks are skipped when no valid parameters exist.
  - `MISSING_AUTH`: Authenticated checks require a valid `AuthenticationContext`.
  - `MISSING_BROWSER`: DOM/browser checks require browser automation capabilities.
  - `BUDGET_EXHAUSTED`: Per-campaign, per-target, and per-check request caps prevent target disruption.

---

## 3. Strict Safety & Determinism Guarantees

1. **Zero Direct Network Calls**: All active probes flow exclusively through `ScopeValidator` $\rightarrow$ `RequestEngine` $\rightarrow$ `AiohttpTransport`.
2. **Default-Deny Scope Enforcement**: Scope is verified on every request specification and before any redirect chain is followed.
3. **Non-Destructive Testing Invariants**: No `DROP`, `DELETE`, `UPDATE`, web shell deployment, command execution, or destructive file modifications.
4. **Deterministic Reproducibility**: All findings contain cryptographically hashed evidence, request IDs, and deterministic reproduction payloads.
