# Technology Fingerprinting & Evidence-Backed Detection

## 1. Principles of Deterministic Fingerprinting

The `TechnologyDetector` in AihaX enforces the following invariant:
- **No Hallucinations**: Detect only technologies with verifiable, observable artifacts in HTTP responses.
- **Evidence Snippets**: Every `DetectedTechnology` object retains the exact `evidence_source` (`HEADER`, `COOKIE`, `META_TAG`, `BODY_MATCH`, `URL_PATH`) and `evidence_snippet` (e.g., `Server: nginx/1.22.1`).
- **Granular Confidence**:
  - `Confidence.CERTAIN`: Direct version banners in headers (e.g. `X-Powered-By: PHP/8.1.0`).
  - `Confidence.HIGH`: Distinct framework session cookies (e.g., `laravel_session`, `PHPSESSID`, `JSESSIONID`, `django_session`).
  - `Confidence.MEDIUM`: Generator meta tags or DOM container signatures (e.g., `__NEXT_DATA__`, `__NUXT__`, `wp-content`).
  - `Confidence.LOW`: Generic header patterns or default file names.

---

## 2. Fingerprint Signatures

| Technology | Category | Detection Marker | Confidence |
| :--- | :--- | :--- | :--- |
| **Nginx** | Web Server | `Server: nginx/[version]` | `CERTAIN` |
| **Apache** | Web Server | `Server: Apache/[version]` | `CERTAIN` |
| **Microsoft IIS** | Web Server | `Server: Microsoft-IIS/[version]` | `CERTAIN` |
| **PHP** | Application Framework | `X-Powered-By: PHP/[version]` or `PHPSESSID` | `CERTAIN` / `HIGH` |
| **ASP.NET** | Application Framework | `X-AspNet-Version: [version]` or `ASP.NET_SessionId` | `CERTAIN` / `HIGH` |
| **Django** | Python Framework | `csrftoken` or `sessionid` with Django signatures | `HIGH` |
| **Laravel** | PHP Framework | `laravel_session` cookie | `HIGH` |
| **Express / Node** | Application Framework | `X-Powered-By: Express` or `connect.sid` | `CERTAIN` / `HIGH` |
| **WordPress** | CMS | `<meta name="generator" content="WordPress [version]">` | `HIGH` |
| **Next.js** | Frontend Framework | `<script id="__NEXT_DATA__">` or `/_next/` | `HIGH` |
| **Nuxt.js** | Frontend Framework | `<div id="__nuxt">` or `__NUXT__` | `HIGH` |
| **GraphQL** | API Architecture | `/__schema` query response, `{"__typename":...}` | `HIGH` |

---

## 3. Technology Data Model

```python
@dataclass(frozen=True)
class DetectedTechnology:
    name: str
    version: Optional[str]
    category: str
    confidence: Confidence
    evidence_source: str
    evidence_snippet: str
    discovered_at: str
```
