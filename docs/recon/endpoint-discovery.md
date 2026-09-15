# Endpoint Discovery & Surface Extraction

## 1. Multi-Vector Endpoint Discovery

The `EndpointDiscoveryEngine` extracts API surfaces and application routes across six distinct discovery vectors:

```text
Target Asset
     ├── 1. robots.txt (Disallow / Allow path extraction)
     ├── 2. sitemap.xml (XML URL location parsing)
     ├── 3. OpenAPI / Swagger (/openapi.json, /swagger.json)
     ├── 4. GraphQL Probing (/graphql, /api/graphql)
     ├── 5. HTML Crawler (<a href>, <form action>, parameters)
     └── 6. JavaScript Route Scanner (Regex route extraction)
```

---

## 2. Discovery Vectors in Detail

### 1. `robots.txt` & `sitemap.xml`
- Extracts declared crawl boundaries and site structure.
- Handles namespace-prefixed and root XML documents safely with standard `xml.etree.ElementTree`.

### 2. OpenAPI & Swagger Specification Parsing
- Automatically checks well-known paths: `/openapi.json`, `/swagger.json`, `/api/openapi.json`, `/v1/api-docs`.
- Parses documented HTTP methods (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`), route paths, and parameter names (`path`, `query`, `header`).

### 3. Safe GraphQL Introspection
- Probes `/graphql` with non-destructive lightweight queries: `{"query":"{__typename}"}`.
- Registers endpoint type as `EndpointType.GRAPHQL` upon valid JSON response.

### 4. HTML Links & Form Extraction
- Crawls HTML pages up to `max_crawl_depth` (default: 2).
- Extracts `<a href="...">` anchor links.
- Extracts `<form>` elements, capturing:
  - `action` URL and HTTP `method` (`GET` or `POST`).
  - `is_upload` flag based on `enctype="multipart/form-data"` or `<input type="file">`.
  - Input field names (`input`, `select`, `textarea`).

### 5. Static JavaScript Analysis
- Fetches in-scope `<script src="...">` bundles.
- Scans JS content with regular expressions for API route literals (e.g. `"/api/v1/users"`, `fetch(...)`, `axios.get(...)`).
- **No execution of untrusted client code**: Scanning is purely static and regex-driven.

---

## 3. Discovered Endpoint Model

```python
@dataclass
class DiscoveredEndpoint:
    endpoint_id: str
    url: str
    path: str
    method: str
    endpoint_type: EndpointType
    source: DiscoverySource
    parameters: list[str]
    auth_required: AuthRequirement
    content_type: Optional[str]
    status_code: Optional[int]
    is_api: bool
    is_graphql: bool
    is_upload: bool
    discovered_at: str
```
