# Check Orchestration & Capability Mapping

## 1. Evidence-Driven Check Planning

AihaX does not blindly execute every check against every target. Instead, the `ReconOrchestrator` derives an `AssetCapabilities` model for each asset and generates a **deterministic check plan** mapping observable capabilities to eligible C001–C077 vulnerability checks.

```text
Asset Evidence (Headers, Cookies, Endpoints, Technologies)
                    ↓
        Capability Derivation (CapabilityMapper)
                    ↓
          AssetCapabilities
          ├── http: bool
          ├── https: bool
          ├── api: bool
          ├── graphql: bool
          ├── authentication: bool
          ├── file_upload: bool
          ├── browser_required: bool
          └── workflow_required: bool
                    ↓
        Check Planning Engine (ReconOrchestrator)
                    ↓
          Eligible C001–C077 Checks Filtered Against CheckRegistry
```

---

## 2. Capability to Check Mapping Matrix

| Discovered Capability | Triggering Condition | Eligible C001–C077 Checks |
| :--- | :--- | :--- |
| **Universal Web** | Any reachable HTTP/HTTPS service | `C001`, `C002`, `C003`, `C004`, `C006`, `C007`, `C010`, `C011`, `C013`, `C014`, `C015`, `C016`, `C047`, `C048`, `C049`, `C050`, `C051`, `C052`, `C053`, `C054`, `C057`, `C058`, `C059`, `C060`, `C061`, `C062`, `C064`, `C065`, `C066` |
| **GraphQL** | `/graphql` discovered or introspection signature | `C005_GraphQL_Introspection` |
| **File Upload** | `multipart/form-data` form or upload API | `C055_Dangerous_File_Upload` |
| **Client-Side SPA** | React, Next.js, Nuxt.js, Vue DOM markers | `C039_DOM_XSS_Indicators` |
| **REST / JSON API** | `/api/` endpoints, OpenAPI specs, JSON responses | `C067_IDOR_Numeric_IDs`, `C068_IDOR_UUIDs`, `C069_BOLA_API`, `C070_Mass_Assignment`, `C071_Privilege_Escalation`, `C072_Function_Access_Control` |
| **Authentication Surface** | 401/403 challenges, login forms, auth routes | `C012`, `C017`, `C018`, `C019`, `C020`, `C021`, `C022`, `C077_Missing_Reauthentication` |
| **Multi-Step Workflow** | Multi-stage checkout, shopping carts, step forms | `C073`, `C074`, `C075_Race_Condition`, `C076_Replay_Attack` |
| **Input / Injection Points** | Query parameters, form inputs, dynamic routes | `C023`–`C027` (SQLi/NoSQL), `C028` (SSTI), `C029`–`C030` (Header/CRLF), `C031`–`C032` (Traversal/LFI), `C033` (XXE), `C034` (LDAP), `C035` (EL), `C036` (SSRF), `C037`–`C038` (XSS), `C040`–`C046` (Contextual XSS/HTML Injection), `C056` (Path Normalization) |

---

## 3. Reconnaissance Differential Analysis

AihaX provides continuous monitoring capabilities by computing deterministic differentials between successive reconnaissance runs (`ReconDifferential`):
- `new_assets`: Assets discovered in current run not present in baseline.
- `removed_assets`: Assets no longer reachable or discovered.
- `new_endpoints`: New API routes or web endpoints.
- `new_technologies`: Upgraded or newly deployed technology components.
- `new_capabilities`: Newly emerged application surfaces (e.g. file upload added).
