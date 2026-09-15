# Bug Bounty Phase 5.1: Passive Reconnaissance & Asset Discovery Audit

## Executive Summary
This document provides the architectural audit and technical design for **Phase 5.1: Passive Reconnaissance & Asset Discovery** for AihaX. 

The primary objective of Phase 5.1 is to build a deterministic, evidence-backed passive asset discovery system for **AUTHORIZED bug bounty programs only**.

```
Program & ProgramScope
          ↓
Passive Discovery Providers (crt.sh, Wayback, AlienVault, Public DNS)
          ↓ (Managed via RequestEngine with per-provider rate limits)
Raw Observations + Provenance Evidence
          ↓
Deterministic Asset Normalizer & Deduplicator
          ↓
ScopeValidator Gating (IN_SCOPE vs OUT_OF_SCOPE vs UNKNOWN)
          ↓
Structured Asset Inventory (Assets, Observations, Endpoints, Technologies)
          ↓
Strict Gate: Active Testing Allowed = (IN_SCOPE && authorization_confirmed)
```

> [!IMPORTANT]
> **Core Invariant: Discovered ≠ Authorized**
> An asset discovered through passive reconnaissance (Certificate Transparency, DNS, Wayback Machine, etc.) **must NEVER automatically become authorized for active testing**.
> Only `ProgramScope` and explicit user authorization determine whether active testing is permitted.

---

## 1. What Passive Reconnaissance Functionality Already Exists
In the existing codebase (`backend/agents/recon_agent.py` and `backend/services/orchestrator.py`):
1. **Subdomain Enumeration**: `ReconAgent._run_subfinder()` calls the external binary `subfinder -d <domain> -silent`.
2. **Technology Detection**: `ReconAgent._run_whatweb()` calls `whatweb <url> --log-brief`.
3. **Endpoint Discovery**: `ReconAgent._discover_endpoints()` calls `gau --subs <domain>`.
4. **Port Scanning**: `ReconAgent._run_nmap()` calls `nmap -sV --top-ports 100 -T4 <target>`.
5. **Attack Surface Caching**: Results are combined into an ephemeral dictionary `attack_surface` and stored in Redis via `set_attack_surface(scan_id, attack_surface)`.
6. **Scan Column**: `Scan.tech_stack` is updated with a JSON string of detected technologies.

---

## 2. What Existing Recon Code Uses Subprocesses
`backend/agents/recon_agent.py` relies entirely on asynchronous CLI subprocesses via `_run_subprocess()`:
- `subfinder`: Unmanaged external binary for subdomain enumeration.
- `whatweb`: Unmanaged external binary for technology detection.
- `gau` (GetAllUrls): Unmanaged external binary for URL archive scraping.
- `nmap`: Unmanaged external binary for active TCP port scanning and banner grabbing.

### Defects of Existing Subprocess Approach:
- **No Scope Enforcement**: Subprocesses can query or probe arbitrary targets without passing through `ScopeValidator`.
- **No RequestEngine Tracking**: Subprocesses bypass `RequestEngine`, generating zero `RequestEvidence`, zero request IDs, and ignoring global rate limits.
- **Environment Dependency**: Requires CLI binaries (`subfinder`, `gau`, `whatweb`, `nmap`) pre-installed in the OS `$PATH`, failing on standard Windows or lightweight container environments.
- **Active / Passive Conflation**: Active network probing (`nmap`, `whatweb`) is conflated with passive archive lookups (`gau`, `subfinder`).

---

## 3. What Existing Code Performs Network Requests
1. **Direct Active Requests (Target Probing)**:
   - `whatweb`: Sends raw HTTP GET/HEAD requests to target web servers.
   - `nmap`: Sends raw TCP SYN/connect packets to ports 1–100 on target IP addresses.
2. **Passive External Provider Requests**:
   - `subfinder` & `gau`: Query external third-party endpoints (crt.sh, Wayback Machine `web.archive.org`, AlienVault OTX, URLScan, Common Crawl).
3. **Internal Pipeline Requests**:
   - `RequestEngine` in `backend/services/request_engine.py` manages HTTP requests for checks and verification strategies through `AiohttpTransport` or `MockTransport`.

---

## 4. Which Recon Functionality Can Safely Be Reused
- **ScopeValidator Rule Engine** (`backend/core/scope_validator.py`): Reusable for evaluating discovered hostnames, domains, and URLs against program scope.
- **RequestEngine** (`backend/services/request_engine.py`): Reusable for sending managed HTTP requests to passive data providers (e.g., crt.sh, web.archive.org) with rate limiting, timeouts, and evidence collection.
- **Redis Attack Surface Caching** (`backend/core/redis_client.py`): Reusable for ephemeral real-time UI updates during scan orchestration.
- **Program & ProgramScope ORM Models** (`backend/models/database.py`): Existing tables (`programs`, `program_scopes`) represent the root anchor for discovered assets.

---

## 5. What Must Be Migrated
1. **Decommission Unmanaged Subprocesses**: Eliminate `subfinder`, `gau`, `whatweb`, and `nmap` calls from `ReconAgent`.
2. **Decommission Active Probing from Recon**: Move active port scanning (`nmap`) out of passive discovery entirely.
3. **Native Python Passive Providers**: Implement pure Python passive discovery providers using `RequestEngine`:
   - `CrtShPassiveProvider` (Certificate Transparency logs via `https://crt.sh/?q=%.{domain}&output=json`)
   - `WaybackPassiveProvider` (Historical endpoints via `https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey`)
   - `AlienVaultOtxProvider` (Passive DNS/URL endpoints via `https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns` and `/url_list`)
   - `HackerTargetDnsProvider` (Public DNS record queries)
   - `DnsLookupProvider` (Standard Python `dnspython` / `socket` resolver for A/AAAA/CNAME records)
4. **Relational Asset Inventory**: Migrate ephemeral Redis dicts to persistent database tables (`assets`, `asset_observations`, `discovery_sources`, `endpoints`, `technology_fingerprints`).

---

## 6. Required Database Models

### Model 1: `Asset`
Represents a canonical, normalized asset associated with a Program.
- **`id`**: String (UUIDv4 primary key)
- **`program_id`**: String (FK -> `programs.id`, indexed, non-nullable)
- **`asset_type`**: Enum/String (`DOMAIN`, `SUBDOMAIN`, `IP_ADDRESS`, `CIDR`, `URL`)
- **`raw_value`**: String (Original discovered string, e.g., `https://API.Example.com:443/`)
- **`normalized_value`**: String (Normalized string, e.g., `api.example.com`, indexed)
- **`scope_status`**: Enum/String (`DISCOVERED`, `IN_SCOPE`, `OUT_OF_SCOPE`, `UNKNOWN`)
- **`active_testing_allowed`**: Boolean (Default: `False`, strictly gated)
- **`dns_records`**: Text/JSON (Resolved A, AAAA, CNAME, MX, TXT records)
- **`first_seen_at`**: UTCDateTime (Timestamp of initial discovery)
- **`last_seen_at`**: UTCDateTime (Timestamp of latest observation)
- **`created_at`**: UTCDateTime
- **`updated_at`**: UTCDateTime
- **Unique Constraint**: `(program_id, asset_type, normalized_value)`

### Model 2: `DiscoverySource`
Catalog of discovery providers and ingestion channels.
- **`id`**: String (Primary key, e.g., `SRC_CRTSH`, `SRC_WAYBACK`, `SRC_ALIENVAULT_OTX`, `SRC_DNS_RESOLVER`, `SRC_MANUAL_SCOPE`)
- **`source_name`**: String (e.g., "crt.sh Certificate Transparency")
- **`source_category`**: Enum/String (`PASSIVE_CT`, `PASSIVE_ARCHIVE`, `PASSIVE_DNS`, `PASSIVE_HEADER`, `MANUAL`)
- **`is_passive`**: Boolean (Default: `True`)
- **`rate_limit_rps`**: Integer (e.g., `1` for crt.sh, `2` for Wayback)
- **`reliability_score`**: Integer (0–100, confidence weighting)
- **`created_at`**: UTCDateTime

### Model 3: `AssetObservation`
Immutable audit log of each time an asset or endpoint was observed.
- **`id`**: String (UUIDv4 primary key)
- **`asset_id`**: String (FK -> `assets.id`, indexed, non-nullable)
- **`source_id`**: String (FK -> `discovery_sources.id`, indexed, non-nullable)
- **`scan_id`**: String (FK -> `scans.id`, nullable, indexed)
- **`observation_type`**: String (`CERTIFICATE_SUBJECT_ALT_NAME`, `WAYBACK_SNAPSHOT`, `DNS_A_RECORD`, `DNS_CNAME`, `HEADER_METADATA`)
- **`raw_data`**: Text/JSON (Raw snippet returned by provider)
- **`request_id`**: String (FK / reference to RequestEvidence request ID)
- **`evidence_id`**: String (Deterministic evidence ID)
- **`confidence`**: Integer (0–100)
- **`observed_at`**: UTCDateTime

### Model 4: `Endpoint`
Represents an HTTP/HTTPS endpoint path or URL discovered on an asset.
- **`id`**: String (UUIDv4 primary key)
- **`asset_id`**: String (FK -> `assets.id`, indexed, non-nullable)
- **`program_id`**: String (FK -> `programs.id`, indexed, non-nullable)
- **`normalized_url`**: String (e.g., `https://api.example.com/v1/users`, indexed)
- **`scheme`**: String (`http` or `https`)
- **`host`**: String (`api.example.com`)
- **`port`**: Integer (`443`)
- **`path`**: String (`/v1/users`)
- **`query_params`**: Text/JSON (Sorted parameter keys/examples)
- **`method`**: String (Default: `GET`)
- **`status_code`**: Integer (Observed response status, nullable)
- **`scope_status`**: Enum/String (`IN_SCOPE`, `OUT_OF_SCOPE`, `UNKNOWN`)
- **`active_testing_allowed`**: Boolean (Default: `False`)
- **`discovered_by_source_id`**: String (FK -> `discovery_sources.id`)
- **`evidence_id`**: String (Deterministic evidence ID)
- **`first_seen_at`**: UTCDateTime
- **`last_seen_at`**: UTCDateTime
- **Unique Constraint**: `(asset_id, normalized_url, method)`

### Model 5: `TechnologyFingerprint`
Detected software, frameworks, and infrastructure components on an asset/endpoint.
- **`id`**: String (UUIDv4 primary key)
- **`asset_id`**: String (FK -> `assets.id`, indexed, non-nullable)
- **`endpoint_id`**: String (FK -> `endpoints.id`, nullable)
- **`tech_name`**: String (e.g., "React", "Cloudflare", "Nginx", "Django", "GraphQL")
- **`category`**: String (`Web Server`, `CDN`, `Frontend Framework`, `API Framework`, `Operating System`)
- **`version`**: String (nullable, e.g., "1.24.0")
- **`confidence`**: Integer (0–100)
- **`match_rule`**: String (e.g., "Header: Server", "Header: X-Powered-By", "Cookie: csrftoken", "Body Token")
- **`evidence_id`**: String (Deterministic evidence ID)
- **`created_at`**: UTCDateTime

---

## 7. How Discovered Assets Will Be Linked to Program and ProgramScope
1. **Program Scoping Anchor**: Every discovery scan or inventory sync is initiated against a specific `Program` (`program_id`).
2. **ProgramScope Ingestion**:
   - The program's `ProgramScope` record is fetched (`in_scope_assets`, `out_of_scope_assets`, `allowed_schemes`, `allowed_ports`, `excluded_paths`).
   - A `ScopeValidator` instance is configured with these rules.
3. **Asset Ingestion Pipeline**:
   - As passive providers yield candidate domain strings or URLs, the ingestion engine passes each asset string through `ScopeValidator.validate_target(candidate)`.
   - The asset record is linked via `asset.program_id = program.id`.
   - The asset's `scope_status` is computed immediately and saved.

---

## 8. How ScopeValidator Will Be Applied to Discovered Assets
`ScopeValidator` evaluates candidate assets using hierarchical precedence:
1. **Explicit Exclusion (`out_of_scope_assets`)**: If `candidate` matches any out-of-scope pattern (e.g., `admin.example.com`, `billing.example.com`), it is immediately assigned `scope_status = OUT_OF_SCOPE` and `active_testing_allowed = False`.
2. **Explicit / Wildcard Inclusion (`in_scope_assets`)**: If `candidate` matches an in-scope pattern (e.g., `*.example.com`, `example.com`), it is assigned `scope_status = IN_SCOPE`.
3. **Unmatched / Third-Party**: If `candidate` is discovered (e.g., an external CNAME target `cdn.thirdparty.com` or unrelated domain), it is assigned `scope_status = UNKNOWN` or `OUT_OF_SCOPE`.
4. **Port / Scheme Restrictions**: When full URLs/endpoints are evaluated, `allowed_schemes` and `allowed_ports` are applied to the `Endpoint.scope_status`.

---

## 9. How Duplicate Assets Will Be Normalized
Normalization converts raw provider strings into canonical representations:

### Domain / Hostname Normalization Rules:
- Convert to lower-case: `API.EXAMPLE.COM` $\rightarrow$ `api.example.com`.
- Strip URI scheme prefixes: `https://api.example.com/` $\rightarrow$ `api.example.com`.
- Strip port suffixes if standard (80/443): `api.example.com:443` $\rightarrow$ `api.example.com`.
- Strip trailing dots: `api.example.com.` $\rightarrow$ `api.example.com`.
- Strip leading wildcards when normalizing discrete host: `*.api.example.com` $\rightarrow$ `api.example.com`.
- Trim leading and trailing whitespace and control characters.
- Punycode decode internationalized domain names (IDN).

### URL / Endpoint Normalization Rules:
- Lowercase scheme (`http`, `https`) and hostname.
- Remove default port numbers (:80 for HTTP, :443 for HTTPS).
- Resolve dot segments in path (`/a/b/../c` $\rightarrow$ `/a/c`).
- Eliminate multiple consecutive slashes (`//v1//users` $\rightarrow$ `/v1/users`).
- Strip URL fragments (`#section-1`).
- Sort query parameters alphabetically (`?role=admin&id=10` $\rightarrow$ `?id=10&role=admin`).

---

## 10. How Evidence Will Be Attached to Every Discovery
Every discovery record carries cryptographic and traceable provenance:
- **`request_id`**: The `RequestEngine` request ID (`REQ-...`) that queried the public provider (e.g., the crt.sh API call).
- **`evidence_id`**: A deterministic hash-based evidence ID (`EVD-RECON-...`).
- **`AssetObservation`**: Records the exact raw JSON / payload returned by the provider, the discovery timestamp, and provider metadata.
- **Audit Trace**:
  $$\text{DiscoverySource (e.g. crt.sh)} \rightarrow \text{RequestEvidence} \rightarrow \text{AssetObservation} \rightarrow \text{Asset} / \text{Endpoint}$$

---

## 11. How Passive and Active Discovery Must Remain Separated
Phase 5.1 strictly enforces the boundary between passive discovery and active scanning:

| Feature | Phase 5.1 Passive Recon | Active Vulnerability Scanning (Phase 4 / Later) |
| :--- | :--- | :--- |
| **Network Traffic** | Only to 3rd-party public databases (crt.sh, Archive.org) or reading baseline responses | Direct active testing requests to target hosts |
| **Target Modification** | Zero target state changes | Security payload injection, auth boundary tests |
| **Gating** | Runs on all program domains for mapping | Strictly restricted to `active_testing_allowed == True` |
| **Port Probing** | Passive DNS / Historical ports only | Prohibited in Phase 5.1 |
| **Vulnerability Checks** | NONE | CheckRegistry checks (C001–C007) |

---

## 12. How to Prevent Discovered Out-of-Scope Assets from Entering Active Testing
**Three-Layer Defense in Depth**:
1. **Database Layer**:
   `assets` and `endpoints` tables store `scope_status` and `active_testing_allowed`. Out-of-scope assets have `active_testing_allowed = False` guaranteed by model constraints.
2. **Orchestrator Layer**:
   When preparing target queues for active testing, the orchestrator queries ONLY:
   ```sql
   SELECT normalized_value FROM assets
   WHERE program_id = :pid
     AND scope_status = 'IN_SCOPE'
     AND active_testing_allowed = 1;
   ```
3. **Network Boundary Layer (`RequestEngine` + `ScopeValidator`)**:
   Even if an out-of-scope asset were somehow queued, `RequestEngine.execute(spec)` passes the target through `ScopeValidator` prior to transmitting any packet. Any out-of-scope URL is rejected with `SCOPE_DENIED` and produces **zero network transport calls**.

---

## 13. How to Prevent Discovered Assets from Automatically Becoming Authorized
- **Invariant**: Discovery is purely informational; authorization is legal and contractual.
- When an asset is discovered via CT logs or DNS, its initial state is `scope_status = DISCOVERED` and `active_testing_allowed = False`.
- `active_testing_allowed` can ONLY transition to `True` if:
  1. The asset matches an explicit or wildcard rule in `ProgramScope.in_scope_assets`.
  2. The asset DOES NOT match any rule in `ProgramScope.out_of_scope_assets`.
  3. The scan/program has `authorization_confirmed == True` signed off by the user.
- If an asset is outside defined scope or matches an exclusion rule, `active_testing_allowed` remains `False` perpetually.

---

## 14. Handling Specific Asset Types

| Asset Type | Storage Model | Normalization | Ingestion Source |
| :--- | :--- | :--- | :--- |
| **Domain** | `Asset` (`asset_type='DOMAIN'`) | Lowercase, strip protocols/ports/trailing dots | User Scope Input, Root Program Domains |
| **Subdomain** | `Asset` (`asset_type='SUBDOMAIN'`) | Lowercase, strip wildcards, resolve parent domain | crt.sh, AlienVault OTX, DNS CNAME/A |
| **IP Address** | `Asset` (`asset_type='IP_ADDRESS'`) | Standard IPv4/IPv6 notation | Public DNS A/AAAA record resolution |
| **Port** | `AssetObservation` / `Endpoint.port` | Standard integer port number | Passive historical records / default ports |
| **Path / Endpoint**| `Endpoint` | Lowercase scheme/host, sorted query params | Wayback CDX, Common Crawl, AlienVault |
| **Technology** | `TechnologyFingerprint` | Canonical tech name + category + version | Passive HTTP header inspection, response tokens |

---

## 15. Asset States & State Lifecycle
```
[External Provider Discovery]
             ↓
        DISCOVERED
             ↓
    [ScopeValidator Check]
      ├── Matches in_scope AND NOT out_of_scope ──→ IN_SCOPE
      ├── Matches out_of_scope ───────────────────→ OUT_OF_SCOPE
      └── Outside program boundary ───────────────→ UNKNOWN
             ↓
   [Authorization Gate]
      ├── IN_SCOPE + authorization_confirmed ────→ ACTIVE_TESTING_ALLOWED = True
      └── OUT_OF_SCOPE / UNKNOWN ─────────────────→ ACTIVE_TESTING_ALLOWED = False
```

---

## 16. Deterministic Asset Normalization Strategy
```python
def normalize_domain(raw_domain: str) -> str:
    cleaned = raw_domain.strip().lower()
    # Strip URL schemes
    if "://" in cleaned:
        parsed = urlparse(cleaned)
        cleaned = parsed.netloc or parsed.path
    # Strip port if present
    if ":" in cleaned:
        cleaned = cleaned.split(":")[0]
    # Strip leading wildcard
    if cleaned.startswith("*."):
        cleaned = cleaned[2:]
    # Strip trailing dot
    cleaned = cleaned.rstrip(".")
    # IDNA Punycode conversion
    try:
        cleaned = cleaned.encode("idna").decode("ascii")
    except Exception:
        pass
    return cleaned
```

---

## 17. Deduplication Rules
1. **Composite Unique Key**: `(program_id, asset_type, normalized_value)` in database.
2. **UPSERT Semantics**: On insertion collision, update `last_seen_at = excluded.last_seen_at` and increment observation counter, preventing duplicate entity rows.
3. **Endpoint Deduplication**: `(asset_id, normalized_url, method)` ensures unique endpoints while accumulating parameter variations.

---

## 18. Evidence Provenance
Each discovery records:
1. `source_id`: The exact discovery provider (`SRC_CRTSH`, `SRC_WAYBACK`, etc.).
2. `request_id`: The HTTP request ID generated when `RequestEngine` queried the provider API.
3. `raw_data`: Full response snippet or record.
4. `evidence_id`: SHA-256 hash formatted as `EVD-RECON-<hash[:8]>`.

---

## 19. Rate Limits for Passive Discovery Providers
Passive discovery providers are shared public services with strict rate limits. AihaX configures dedicated token-bucket rate limiters per provider in `RequestEngine`:

| Provider | Base Endpoint | Rate Limit | Max Concurrency | Timeout |
| :--- | :--- | :--- | :--- | :--- |
| **crt.sh** | `https://crt.sh/` | 1 request / 2.0 sec | 1 | 30s |
| **Wayback CDX** | `https://web.archive.org/cdx/search/cdx` | 2 requests / 1.0 sec | 2 | 20s |
| **AlienVault OTX** | `https://otx.alienvault.com/api/v1/` | 3 requests / 1.0 sec | 3 | 15s |
| **HackerTarget** | `https://api.hackertarget.com/` | 1 request / 3.0 sec | 1 | 15s |
| **DNS Resolvers** | Standard system / 8.8.8.8 | 20 requests / 1.0 sec | 5 | 5s |

---

## 20. Security Risks & Mitigations

| Identified Risk | Potential Impact | Architectural Mitigation |
| :--- | :--- | :--- |
| **Scope Overreach / Wildcard Collisions** | Passive sources find subdomains pointing to shared multi-tenant cloud services (e.g. S3 buckets, GitHub Pages) | Strict `ScopeValidator` boundary + CNAME verification + explicit authorization gate. |
| **External API Rate Limiting / IP Bans** | Public providers (crt.sh, Wayback) blocking scanner IP due to excessive queries | Centralized token-bucket rate limiters with jitter, exponential backoff, and caching. |
| **Malicious URL Content from Web Archives** | Historical archive dumps containing control characters, binary blobs, or injection payloads | Strict URL normalization, character sanitization, and length bounds. |
| **Credential / Token Leakage in URLs** | Wayback URLs containing embedded tokens or session keys (`?token=secret`) | Sensitive parameter redaction (`redact_body`, `redact_headers`) applied to all ingested endpoint records. |
| **Unintended Active Probing** | Recon agent attempting active port scanning against discovered infrastructure | Active port scans (`nmap`) strictly excluded from Phase 5.1; all passive lookups run through third-party APIs. |
