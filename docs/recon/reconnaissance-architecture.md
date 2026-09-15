# AihaX Reconnaissance & Asset Intelligence Architecture

## 1. Overview & Mission

AihaX Phase 4 introduces an autonomous, scope-governed **Reconnaissance, Asset Intelligence, and Check Orchestration Engine**. Rather than relying on static URL lists or random security checks, AihaX dynamically maps target attack surfaces, classifies assets, discovers endpoints, detects underlying technologies with evidence, identifies authentication requirements, and orchestrates targeted C001–C077 vulnerability check plans.

```text
Bug Bounty Program
        ↓
Explicit Scope (ScopeValidator)
        ↓
Pre-Probe Scope Gating [OUT-OF-SCOPE -> ZERO BYTES]
        ↓
Asset Discovery (Wordlist, Passive Providers)
        ↓
Asset Normalization & Classification
        ↓
HTTP Probe & Redirect Intelligence (Per-Hop Gating)
        ↓
Technology Detection (Headers, Cookies, DOM, Meta)
        ↓
Endpoint Discovery (Robots, Sitemaps, HTML, JS, OpenAPI, GraphQL)
        ↓
Authentication Surface Mapping
        ↓
Capability Derivation (AssetCapabilities)
        ↓
Check Orchestration & Plan Generation
        ↓
C001–C077 Execution Engine
        ↓
VerificationEngine
        ↓
Deduplication & Differential Analysis
        ↓
Verified Bug Bounty Report
```

---

## 2. Core Modules in `backend/recon/`

| Module | Responsibility | Safety Invariant |
| :--- | :--- | :--- |
| `backend/recon/models.py` | Structured data models (`DiscoveredAsset`, `DiscoveredEndpoint`, `DetectedTechnology`, `AssetCapabilities`, `ReconResult`, `ReconDifferential`). | Complete typing, immutable dataclasses, JSON serialization. |
| `backend/recon/asset_discovery.py` | Subdomain enumeration, wordlist generation, passive feed integration, asset classification. | **Pre-probe scope gating**: Out-of-scope assets receive zero network bytes. |
| `backend/recon/http_probe.py` | Baseline HTTP/HTTPS accessibility, server banners, title extraction, soft-404 baseline, rate limit handling. | **Redirect boundary gating**: Multi-hop redirects stop immediately if any hop exits scope. |
| `backend/recon/technology_detector.py` | Deterministic evidence-based tech detection across headers, cookies, meta tags, and DOM markers. | Never hallucinate technologies or versions. Confidence levels: `CERTAIN`, `HIGH`, `MEDIUM`, `LOW`. |
| `backend/recon/endpoint_discovery.py` | Discovers endpoints via `robots.txt`, `sitemap.xml`, HTML forms/links, client-side JS bundles, OpenAPI, GraphQL. | Safe regex extraction without executing untrusted client JS. Scope validation per endpoint. |
| `backend/recon/auth_mapper.py` | Detects login forms, HTTP Basic/Bearer 401/403 challenges, token endpoints, and context bindings. | Safe probing without credential spraying. |
| `backend/recon/capability_mapper.py` | Derives structured `AssetCapabilities` (`http`, `https`, `api`, `graphql`, `authentication`, `file_upload`, `browser_required`, `workflow_required`). | Strictly evidence-backed capability flags. |
| `backend/recon/orchestrator.py` | Coordinates the end-to-end recon pipeline, differential comparison between scans, and maps capabilities to C001–C077 checks. | Deterministic plan generation restricted to valid registered checks in `CheckRegistry`. |

---

## 3. Campaign Execution Modes

Campaigns support three distinct operational modes:
1. **`RECON_ONLY`**: Runs asset discovery, HTTP probing, tech fingerprinting, endpoint extraction, capability derivation, and check planning. Terminates with structured recon intelligence and check plan **without launching vulnerability checks**.
2. **`SAFE_SCAN` (Default)**: Executes recon, check planning, and non-destructive C001–C077 vulnerability checks within rate limits and concurrency controls.
3. **`FULL_AUTHORIZED_SCAN`**: Executes full recon, check planning, and all authorized checks for production-ready security validation.
