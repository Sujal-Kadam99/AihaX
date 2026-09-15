# Bug Bounty Phase 5.1-C: Passive Discovery Providers & Asset Ingestion Audit

## Executive Summary
This document provides the architectural audit and technical specification for **Phase 5.1-C: Passive Discovery Providers + Asset Ingestion** in AihaX.

The objective of Phase 5.1-C is to implement native, passive third-party reconnaissance providers (`CRTShProvider`, `WaybackProvider`, `AlienVaultProvider`, `DNSProvider`) and an asset ingestion service that persists canonical, normalized discoveries into the database with cryptographic provenance and strict scope gating.

```
+-----------------------------------------------------------------------------------+
|                            Bug Bounty ProgramScope                                |
|        (in_scope_assets, out_of_scope_assets, authorization_confirmed)            |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                           Passive Discovery Providers                             |
|       (CRTShProvider, WaybackProvider, AlienVaultProvider, DNSProvider)           |
+-----------------------------------------------------------------------------------+
                                         |
                  Queries via RequestEngine (Token-Bucket Limits)
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                         Public Passive Aggregators                                |
|          (crt.sh CT Logs, Archive.org CDX, AlienVault OTX, DNS Records)           |
+-----------------------------------------------------------------------------------+
                                         |
                         RequestEvidence (REQ-..., EVD-...)
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                       Deterministic Asset Normalizer                              |
|          (Domain, IPv4, IPv6, URL, Query Parameter Canonicalization)               |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                                 AssetService                                      |
|                 (Deduplication + Ingestion + Scope Classification)                |
+-----------------------------------------------------------------------------------+
                                         |
                         Evaluated against ScopeValidator
                                         |
                 +-----------------------+-----------------------+
                 |                       |                       |
                 v                       v                       v
            [ IN_SCOPE ]          [ OUT_OF_SCOPE ]          [ UNKNOWN ]
                 |                       |                       |
        authorization_confirmed?         |                       |
          ├── True  -> ACTIVE_TESTING    |                       |
          └── False -> GATED (False)     v                       v
                                  ACTIVE_TESTING_ALLOWED = FALSE
```

> [!IMPORTANT]
> **Core Non-Negotiable Invariant: Discovered ≠ Authorized**
> Passive discovery discovers *existence*, NOT *authorization*.
> Every newly discovered asset MUST default to:
> - `scope_status = "UNKNOWN"`
> - `active_testing_allowed = False`
> - `authorization_confirmed = False`
>
> `active_testing_allowed` may ONLY become `True` when **BOTH** conditions are met:
> 1. `scope_status == "IN_SCOPE"`
> 2. `authorization_confirmed == True`

---

## 1. Current Architecture Review

### Existing Completed Foundations:
1. **Phase 1 (Scope Definition & Target Foundation)**:
   - `ScopeValidator` (`backend/core/scope_validator.py`): Pure deterministic evaluator with precedence: `EXPLICIT EXCLUSION > EXPLICIT INCLUSION > WILDCARD INCLUSION > DEFAULT DENY`.
   - `Program` and `ProgramScope` models in `backend/models/database.py`.
2. **Phase 2 (Central Request Engine & Evidence Engine)**:
   - `RequestEngine` (`backend/services/request_engine.py`): Central network boundary enforcing token-bucket rate limits, timeouts, scope verification prior to packet transmission, secret redaction, SHA-256 evidence hashing, and unique request IDs (`REQ-xxxxxxxx`).
3. **Phase 3 & 4 (Verification Engine & Modernized Check Registry)**:
   - Zero raw sockets or unmanaged requests in active vulnerability checks.
4. **Phase 5.1-A (Passive Recon Database Foundation)**:
   - Migration `015_passive_asset_discovery` and ORM models (`discovery_sources`, `assets`, `asset_observations`, `endpoints`, `technology_fingerprints`).
5. **Phase 5.1-B (Deterministic Asset Normalization)**:
   - `backend/services/discovery/normalizer.py`: Zero-network normalizers for domains, subdomains, IPv4, IPv6 (RFC 5952), URLs (dot segments, duplicate slashes, credential stripping), and query parameters.

### Current Gaps in `ReconAgent` (`backend/agents/recon_agent.py`):
- `ReconAgent` still relies on unmanaged external binaries (`subfinder`, `gau`, `whatweb`, `nmap`).
- Subprocesses bypass `RequestEngine`, lack provenance tracking, lack rate limiting, and fail in environments without CLI tools.
- Conflates active port probing (`nmap`) with passive discovery.

---

## 2. Existing Reusable Components

| Component | File Path | Role in Phase 5.1-C |
| :--- | :--- | :--- |
| **`RequestEngine`** | [backend/services/request_engine.py](file:///c:/Users/sujal/OneDrive/Documents/Desktop/Aihax/backend/services/request_engine.py) | Executes all HTTP queries to third-party passive APIs with rate limiting, timeouts, and `RequestEvidence` generation. |
| **`MockTransport`** | [backend/services/request_engine.py](file:///c:/Users/sujal/OneDrive/Documents/Desktop/Aihax/backend/services/request_engine.py#L220-L310) | Enables 100% deterministic, offline testing of passive provider API responses and error states. |
| **`ScopeValidator`** | [backend/core/scope_validator.py](file:///c:/Users/sujal/OneDrive/Documents/Desktop/Aihax/backend/core/scope_validator.py) | Evaluates discovered hostnames and endpoints against program scope rules during asset ingestion. |
| **`AssetNormalizer`** | [backend/services/discovery/normalizer.py](file:///c:/Users/sujal/OneDrive/Documents/Desktop/Aihax/backend/services/discovery/normalizer.py) | Normalizes domains, IPs, URLs, and query parameters before database deduplication. |
| **Database Models** | [backend/models/database.py](file:///c:/Users/sujal/OneDrive/Documents/Desktop/Aihax/backend/models/database.py) | `DiscoverySource`, `Asset`, `AssetObservation`, `Endpoint`, `TechnologyFingerprint` models ready for transactional persistence. |

---

## 3. Passive Provider Architecture & Design

All providers inherit from `BasePassiveProvider` (`backend/services/discovery/base_provider.py`).

### 1. `CRTShProvider` (`SRC_CRTSH`)
- **Data Source**: Certificate Transparency logs via `https://crt.sh/?q=%.{domain}&output=json`.
- **Methodology**: Passive HTTP GET via `RequestEngine`.
- **Parsing**: Extracts `name_value` (splitting multiple SANs on `\n` and `,`) and `common_name`.
- **Normalization**: Every raw name is cleaned via `normalize_domain()`. Wildcards (`*.`) and trailing dots are stripped.
- **Safety**: Malformed names or invalid TLDs are skipped safely without throwing.
- **Target Probing**: **ZERO**. The provider communicates only with `crt.sh`.

### 2. `WaybackProvider` (`SRC_WAYBACK`)
- **Data Source**: Archive.org Wayback Machine CDX API via `https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey`.
- **Methodology**: Passive HTTP GET via `RequestEngine`.
- **Parsing**: Parses CDX JSON rows containing historical URLs.
- **Normalization**: Full URL canonicalization via `normalize_url()` (scheme lowercasing, dot-segment resolution, trailing slash consistency, credential stripping, parameter sorting via `normalize_query()`).
- **Safety**: Historical URLs are never requested. Zero traffic sent to discovered endpoints.

### 3. `AlienVaultProvider` (`SRC_ALIENVAULT_OTX`)
- **Data Source**: AlienVault Open Threat Exchange Passive DNS via `https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns`.
- **Methodology**: Passive HTTP GET via `RequestEngine`.
- **Parsing**: Extracts `passive_dns` array records:
  - `hostname` $\rightarrow$ `normalize_domain()`
  - `record_type` (`A`, `AAAA`, `CNAME`)
  - `address` $\rightarrow$ `normalize_ip()` for A/AAAA, `normalize_domain()` for CNAME.
- **Safety**: Zero active DNS queries or reverse lookups against target hosts.

### 4. `DNSProvider` (`SRC_DNS_RECORD`)
- **Data Source**: Structured passive DNS datasets and pre-resolved record dumps (A, AAAA, CNAME, MX, TXT).
- **Methodology**: Pure data processor.
- **Safety**: Performs **ZERO** active dictionary brute-forcing, zero recursive zone crawling, zero zone transfer attempts.

---

## 4. RequestEngine Integration Design

### Clear Target Separation:
- **Provider API URLs**: E.g., `https://crt.sh/?q=%.example.com&output=json`, `https://web.archive.org/cdx/...`, `https://otx.alienvault.com/...`.
  - These are third-party infrastructure queries.
  - Routed through `RequestEngine` to enforce timeout budgets, header redaction, token-bucket limits, and evidence capture.
- **Discovered Asset URLs**: E.g., `https://api.example.com/v1/users`, `https://admin.example.com/login`.
  - These are target assets discovered passively.
  - Providers **NEVER** instantiate or execute `RequestSpec` against discovered asset URLs.

### Rate Limiting & Concurrency:
| Provider | Target Endpoint | Rate Limit | Max Concurrency | Timeout (Connect / Read / Total) |
| :--- | :--- | :--- | :--- | :--- |
| **CRT.sh** | `https://crt.sh/` | 1.0 RPS | 1 | 5.0s / 15.0s / 20.0s |
| **Wayback CDX** | `https://web.archive.org/cdx/` | 2.0 RPS | 2 | 5.0s / 20.0s / 25.0s |
| **AlienVault OTX** | `https://otx.alienvault.com/` | 3.0 RPS | 3 | 5.0s / 15.0s / 20.0s |
| **DNS Processor** | In-memory | 10.0 RPS | 5 | 5.0s / 5.0s / 10.0s |

---

## 5. Scope Validation and Ingestion Workflow

When `AssetService` processes discoveries emitted by providers:

```python
# 1. Normalize discovered value
asset_type, normalized_value = normalize_asset(item.raw_value, item.asset_type)

# 2. Scope Evaluation via ScopeValidator
scope_decision = scope_validator.validate_target(normalized_value)

if scope_decision.allowed:
    scope_status = "IN_SCOPE"
elif scope_decision.status == ScopeStatus.OUT_OF_SCOPE:
    scope_status = "OUT_OF_SCOPE"
else:
    scope_status = "UNKNOWN"

# 3. Strict Authorization Gate
active_testing_allowed = (scope_status == "IN_SCOPE" and authorization_confirmed is True)

# 4. Upsert canonical Asset record
# 5. Insert immutable AssetObservation record with request_id and evidence_id
# 6. Upsert Endpoints (if URL) with normalized path and query parameters
```

---

## 6. Evidence & Provenance Design

Every discovery item produces an immutable trace:
- **`source_id`**: Foreign key to `discovery_sources.id` (`SRC_CRTSH`, `SRC_WAYBACK`, `SRC_ALIENVAULT_OTX`, `SRC_DNS_RECORD`).
- **`request_id`**: The `RequestEngine` request identifier (`REQ-xxxxxxxx`) generated during the public API query.
- **`evidence_id`**: Deterministic SHA-256 hash (`EVD-PASSIVE-xxxxxxxx`).
- **`raw_data`**: The exact raw JSON dictionary or CDX row returned by the provider.
- **`confidence`**: Integer score (0–100) reflecting provider reliability.
- **`observed_at`**: UTC timestamp of observation.

---

## 7. Deduplication Strategy

1. **In-Memory Pipeline Deduplication**:
   - Providers maintain a `seen_values: set[str]` hash set during result iteration to eliminate duplicate SANs or URL rows within a single run.
2. **Database Level Deduplication (UPSERT)**:
   - `assets` table has a composite unique constraint: `uq_assets_program_type_value (program_id, asset_type, normalized_value)`.
   - `endpoints` table has a composite unique constraint: `uq_endpoints_asset_url (asset_id, normalized_url)`.
   - If an asset already exists in the program inventory:
     - The existing `Asset` record is retrieved.
     - `last_seen_at` / `updated_at` timestamps are updated.
     - A new `AssetObservation` is appended to record the recurring observation.
     - Duplicate asset rows are never created.

---

## 8. Failure Handling & Resilience

- **External Provider Outages / 5xx Errors**:
  - If `crt.sh`, `web.archive.org`, or `AlienVault` returns HTTP 500, 502, 503, 504, or network timeout:
  - The provider logs a debug message and returns `[]`.
  - **No exceptions are raised to the orchestrator.**
  - **No vulnerability findings or false positives are created.**
- **Malformed JSON / HTML Error Pages**:
  - `json.loads` failures are caught with `try/except Exception`, logged, and return `[]`.
- **Malformed Discovery Strings**:
  - Invalid domain labels or broken URLs are skipped safely during iteration.

---

## 9. Security Risks & Mitigations

| Security Risk | Impact | Architectural Mitigation |
| :--- | :--- | :--- |
| **Accidental Active Probing** | Scanner sends requests to discovered subdomains/endpoints | Providers only communicate with public provider APIs. Zero HTTP/TCP calls to discovered hosts. |
| **Credential Leakage in Historical URLs** | Archive.org URLs containing embedded API tokens or passwords | `normalize_url()` automatically strips `userinfo` (`user:pass@`). Parameter redaction handles sensitive query tokens. |
| **Scope Drift / Wildcard Cloud Overreach** | Discovered subdomain points to shared cloud service (e.g. `s3.amazonaws.com`) | `ScopeValidator` enforces explicit exclusions. Out-of-scope assets receive `active_testing_allowed = False`. |
| **Third-Party API Flooding / IP Bans** | Scanner overwhelms public services like `crt.sh` | Central token-bucket rate limiters in `RequestEngine` + per-provider throttling. |
| **Subprocess / Shell Injection** | Malicious characters in provider responses executed in shell | **Zero subprocesses**. All providers implemented in 100% pure Python. |

---

## 10. Exact Files to Create and Modify

### Files Created:
1. `backend/services/discovery/base_provider.py` (Provider base class & `DiscoveredItem` DTO)
2. `backend/services/discovery/crtsh_provider.py` (Certificate Transparency provider)
3. `backend/services/discovery/wayback_provider.py` (Archive.org CDX provider)
4. `backend/services/discovery/alienvault_provider.py` (AlienVault OTX passive DNS provider)
5. `backend/services/discovery/dns_provider.py` (Passive DNS record processor)
6. `backend/services/discovery/asset_service.py` (Asset ingestion, deduplication, scope gating, and DB persistence)
7. `backend/tests/test_passive_providers.py` (Unit tests for all 4 providers using `MockTransport`)
8. `backend/tests/test_asset_service.py` (Integration tests for ingestion, scope classification, and deduplication)
9. `scripts/verify_phase5_1_providers.py` (Standalone 10-case verification runner)

### Files Modified:
1. `backend/services/discovery/__init__.py` (Export providers, `DiscoveredItem`, and `AssetService`)
2. `backend/agents/recon_agent.py` (Modernize to use `AssetService` + passive providers instead of subprocesses)
3. `backend/services/db_service.py` (Add repository helper queries for `Asset`, `Endpoint`, `AssetObservation`)

---

## 11. Test Plan

1. **Provider Isolation Tests (`backend/tests/test_passive_providers.py`)**:
   - Mocked HTTP responses for CRT.sh, Wayback, AlienVault, and DNS.
   - Wildcard SAN extraction, domain deduplication, malformed domain handling.
   - URL dot segment normalization, query sorting, endpoint deduplication.
   - Verify zero transport calls to discovered target URLs.
   - Verify HTTP 500/502/timeout/bad JSON safe handling.
   - Verify Request IDs and Evidence IDs generation.
   - Verify zero subprocess / zero raw socket calls.
2. **Asset Ingestion & Scope Classification Tests (`backend/tests/test_asset_service.py`)**:
   - Verify in-scope assets receive `scope_status = IN_SCOPE`.
   - Verify out-of-scope assets receive `scope_status = OUT_OF_SCOPE` and `active_testing_allowed = False`.
   - Verify unconfirmed authorization forces `active_testing_allowed = False`.
   - Verify unique constraint UPSERT semantics.
3. **Full Regression Verification**:
   - Run `pytest backend/tests -v` (ensure all 238+ tests pass with 0 failures).
   - Run `python scripts/verify_phase5_1_providers.py`.
   - Run frontend tests, lint, and build (`npm test -- --run`, `npm run lint`, `npm run build`).
