# AihaX Reconnaissance Capability Audit Report

## 1. Executive Summary

This audit determines exactly how reconnaissance functions in AihaX, what tools and providers are implemented, how execution modes isolate environments, and how discovered assets are scoped and governed.

Mocks validate architecture, safety, and deterministic parsing.
Real providers perform real reconnaissance only in `AUTHORIZED_LIVE_RECON` mode against an explicitly authorized concrete target under enforced scope, safety, budget, and operator-confirmation controls.

---

## 2. Recon Capability Matrix

| Capability | Exists? | Implementation | Actually Invoked? | Tests? | Network Path | Scope Gated? | Evidence Captured? | Live Mode? | Status Classification |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Subfinder** | YES | `backend/recon/providers.py` (`SubfinderProvider`), `backend/execution/tool_execution_boundary.py` | YES (`UnifiedReconOrchestrator`, `ReconAgent`) | YES (`test_phase24_recon_agent.py`, `test_phase24_tool_execution_boundary.py`, `test_recon_modes_and_security.py`) | Subprocess CLI (`subfinder -d <domain> -silent`) | YES (`ScopeValidator`) | YES (SHA-256 stdout hash, provenance) | YES (Disabled in Audit Mode) | `LIVE_ADAPTER_PRESENT_NOT_LIVE_VALIDATED` |
| **Sublist3r** | NO | `backend/recon/providers.py` (`Sublist3rProvider`) | Formally evaluated | YES (`test_recon_modes_and_security.py`) | None | N/A | N/A | NO | `NOT_IMPLEMENTED` |
| **Amass** | YES | `backend/recon/providers.py` (`AmassProvider`), `backend/execution/tool_execution_boundary.py` | YES (`UnifiedReconOrchestrator`, `ReconAgent`) | YES (`test_phase24_recon_agent.py`, `test_phase24_tool_execution_boundary.py`, `test_recon_modes_and_security.py`) | Subprocess CLI (`amass enum -passive -d <domain>`) | YES (`ScopeValidator`) | YES (SHA-256 stdout hash, provenance) | YES (Disabled in Audit Mode) | `LIVE_ADAPTER_PRESENT_NOT_LIVE_VALIDATED` |
| **CT Enumeration** | YES | `backend/services/discovery/crtsh_provider.py`, `backend/recon/providers.py` (`CertificateTransparencyProvider`) | YES (`UnifiedReconOrchestrator`) | YES (`test_passive_providers.py`, `test_recon_modes_and_security.py`) | `RequestEngine` -> `https://crt.sh/?q=%.<domain>&output=json` | YES (`ScopeValidator`) | YES (`EVD-PASSIVE-*` hash) | YES (Disabled in Audit Mode) | `LIVE_ADAPTER_PRESENT_NOT_LIVE_VALIDATED` |
| **Passive DNS** | YES | `backend/services/discovery/dns_provider.py` | YES (`DNSProviderAdapter`) | YES (`test_passive_providers.py`) | In-memory / passive feeds | YES (`ScopeValidator`) | YES (SHA-256 hash) | YES | `LIVE_ADAPTER_READY` |
| **Active DNS** | YES | `backend/recon/providers.py` (`DNSProviderAdapter`) | YES (`UnifiedReconOrchestrator`) | YES (`test_recon_modes_and_security.py`) | Controlled `dnspython` resolver (A, AAAA, CNAME, MX, NS, TXT, SOA) | YES (`ScopeValidator`) | YES (SHA-256 hash) | YES (Disabled in Audit Mode) | `LIVE_ADAPTER_PRESENT_NOT_LIVE_VALIDATED` |
| **HTTP Probing** | YES | `backend/recon/http_probe.py` (`HttpProbeEngine`), `backend/recon/providers.py` (`HttpProbeProvider`) | YES (`CampaignExecutor`, `UnifiedReconOrchestrator`) | YES (`test_recon_real_http.py`, `test_recon_modes_and_security.py`) | `RequestEngine` -> `ScopeValidator` -> `transport` | YES (Per-hop redirect scope check) | YES (`EvidenceVault`) | YES | `LIVE_ADAPTER_READY` |
| **HTTPS Probing** | YES | `backend/recon/http_probe.py` (`HttpProbeEngine`), `backend/recon/providers.py` (`HttpProbeProvider`) | YES (`CampaignExecutor`, `UnifiedReconOrchestrator`) | YES (`test_recon_real_http.py`, `test_recon_modes_and_security.py`) | `RequestEngine` -> `ScopeValidator` -> `transport` | YES (Per-hop redirect scope check) | YES (`EvidenceVault`) | YES | `LIVE_ADAPTER_READY` |
| **Technology Fingerprinting** | YES | `backend/recon/technology_detector.py`, `backend/recon/providers.py` (`TechnologyFingerprintProvider`) | YES (`UnifiedReconOrchestrator`, `ReconAgent`) | YES (`test_phase24_recon_agent.py`, `test_recon_modes_and_security.py`) | Passive HTTP inspection or `whatweb` CLI | YES (`ScopeValidator`) | YES (Evidence signal hashes) | YES | `LIVE_ADAPTER_READY` |
| **Endpoint Discovery** | YES | `backend/recon/endpoint_discovery.py`, `backend/agents/recon_agent.py` | YES (`CampaignExecutor`, `ReconAgent`) | YES (`test_parameter_discovery.py`, `test_phase24_recon_agent.py`) | `RequestEngine` | YES (`ScopeValidator`) | YES (Endpoint IDs) | YES | `LIVE_ADAPTER_READY` |
| **Attack Surface Graph** | YES | `backend/services/attack_surface_graph.py` | YES (`ReconAgent`, `UnifiedReconOrchestrator`) | YES (`test_phase24_recon_agent.py`, `test_recon_modes_and_security.py`) | Local SQLite / in-memory | YES | YES (SHA-256 graph hash) | YES | `LIVE_ADAPTER_READY` |

---

## 3. Detailed Capability Breakdown

### 3.1 Subfinder
- **File**: `backend/recon/providers.py` (`SubfinderProvider`), `backend/execution/tool_execution_boundary.py` (`ALLOWED_TOOLS["subfinder"]`).
- **Invocation Path**: `UnifiedReconOrchestrator.execute_recon()` -> `SubfinderProvider.discover()` -> `ToolExecutionBoundary.execute()`.
- **Arguments**: `["-d", domain, "-silent"]`. Strictly structured argv array; `shell=False`.
- **Input**: Concrete domain string (e.g. `example.com`).
- **Output**: List of `NormalizedReconAsset` items with status `IN_SCOPE` or `BLOCKED_SCOPE`.
- **Scope Enforcement**: Every discovered hostname is evaluated via `ScopeValidator.validate_target(f"https://{norm}")`.
- **Evidence**: SHA-256 hash of stdout captured and stored in `NormalizedReconAsset.evidence_hash`.
- **Failure Behavior**: If exit code != 0 or timeout, emits explicit `ProviderStatus.LIVE_FAILED` with error category. Never silently converts to 0 findings.
- **Live Gating**: In `AUDIT` mode, real subprocess is blocked; deterministic mock fixture is used. In `AUTHORIZED_LIVE_RECON`, requires valid authorization record and operator confirmation.

### 3.2 Amass
- **File**: `backend/recon/providers.py` (`AmassProvider`), `backend/execution/tool_execution_boundary.py` (`ALLOWED_TOOLS["amass"]`).
- **Invocation Path**: `UnifiedReconOrchestrator.execute_recon()` -> `AmassProvider.discover()` -> `ToolExecutionBoundary.execute()`.
- **Arguments**: `["enum", "-passive", "-d", domain]`. Restricts strictly to passive enumeration.
- **Input**: Concrete domain string.
- **Output**: Normalized subdomains with provenance `amass`.
- **Scope Enforcement**: Evaluated through `ScopeValidator`.
- **Evidence**: SHA-256 stdout hash.
- **Failure Behavior**: Emits `ProviderStatus.LIVE_FAILED` with stderr details on nonzero exit code.

### 3.3 Sublist3r
- **Decision**: `SUBLIST3R_NOT_IMPLEMENTED — COVERAGE DUPLICATED BY SUBFINDER/AMASS/CT`.
- **Rationale**: Sublist3r is an unmaintained Python 2/3 legacy scraping tool. Its search engine scrapers are brittle and blocked by rate limits, yielding a subset of data already comprehensively discovered by Subfinder, Amass, and Certificate Transparency.

### 3.4 Certificate Transparency (CT)
- **File**: `backend/services/discovery/crtsh_provider.py`, `backend/recon/providers.py` (`CertificateTransparencyProvider`).
- **Invocation Path**: `UnifiedReconOrchestrator` -> `CertificateTransparencyProvider.discover()` -> `CRTShProvider.discover()` -> `RequestEngine.execute()`.
- **URL**: `https://crt.sh/?q=%.<domain>&output=json`.
- **Network Path**: Central network boundary exclusively (`RequestEngine`). Direct `requests`/`httpx`/`urllib` strictly forbidden.
- **Evidence**: `generate_passive_evidence_id(source_code, domain, norm_val)` with SHA-256 digest.

### 3.5 DNS Reconnaissance
- **File**: `backend/recon/providers.py` (`DNSProviderAdapter`).
- **Invocation Path**: `UnifiedReconOrchestrator` -> `DNSProviderAdapter.discover()`.
- **Queries**: A, AAAA, CNAME, MX, NS, TXT, SOA records.
- **Network Path**: Controlled `dnspython` resolver with 5s timeout, 10s lifetime, bounded queries.
- **Safety**: Separate from SSRF safety resolver (`validate_destination_safety`). Mock resolver utilized in Audit Mode.

### 3.6 HTTP / HTTPS Probing
- **File**: `backend/recon/http_probe.py` (`HttpProbeEngine`), `backend/recon/providers.py` (`HttpProbeProvider`).
- **Invocation Path**: `UnifiedReconOrchestrator` -> `HttpProbeProvider.discover()` -> `HttpProbeEngine.probe_asset()` -> `RequestEngine.execute()`.
- **Method**: Read-only `GET`. No mutating methods (`POST`, `PUT`, `DELETE`).
- **Safety**: Per-hop redirect scope evaluation (if redirect leads outside scope, redirect is blocked). SSRF destination safety checked before any request.

### 3.7 Technology Fingerprinting
- **File**: `backend/recon/technology_detector.py` (`TechnologyDetector`), `backend/recon/providers.py` (`TechnologyFingerprintProvider`).
- **Signals**: Headers (`Server`, `X-Powered-By`), HTML meta tags, script patterns, cookies.
- **Confidence**: `CERTAIN`, `HIGH`, `MEDIUM`, `LOW`. Clear separation of fact from inference.

### 3.8 Endpoint Discovery
- **File**: `backend/recon/endpoint_discovery.py` (`EndpointDiscoveryEngine`).
- **Behavior**: In-scope HTML/JS crawler bounded by max depth and max endpoints per asset.
- **Critical Invariant**: Discovered endpoints are tagged `NOT_EXECUTABLE` by default. Discovered endpoints do NOT automatically launch vulnerability checks.

### 3.9 Attack Surface Graph Integration
- **File**: `backend/services/attack_surface_graph.py` (`AttackSurfaceGraphEngine`).
- **Entities**: Target nodes, Endpoint nodes, Parameter nodes, Link relationships.
- **Integrity**: Deterministic SHA-256 snapshot hash across unique nodes and edges.
