# Parameter Discovery Engine & Provenance Specification

## 1. Overview

The `ParameterDiscoveryEngine` (`backend/execution/parameter_discovery.py`) extracts all testable input parameters from discovered endpoints and crawled application assets.

In accordance with strict bug bounty testing standards, **AihaX forbids inventing synthetic parameters without verifiable provenance**. Every `DiscoveredParameter` records its source and origin proof.

---

## 2. Discovery Sources & Extraction Logic

### 2.1 URL Query Strings
- **Extraction**: Parses standard RFC 3986 URL query strings (`?k1=v1&k2=v2`).
- **Location**: `ParameterLocation.QUERY`
- **Source**: `ParameterSource.URL_QUERY`
- **Baseline Value**: Preserves the originally observed query parameter values for accurate baseline restoration.

### 2.2 Path Parameters
- **Extraction**: Matches URI template patterns such as `/api/v1/accounts/{account_id}` or `/users/:user_id`.
- **Location**: `ParameterLocation.PATH`
- **Source**: `ParameterSource.PATH_TEMPLATE`

### 2.3 HTML Forms & Inputs
- **Extraction**: Analyzes HTML response bodies for `<form action="..." method="...">`.
- **Elements Extracted**:
  - `<input type="text|password|hidden|email|number" name="...">`
  - `<select name="...">` (extracts `<option value="...">` options)
  - `<textarea name="...">`
  - Multipart upload forms (`enctype="multipart/form-data"` with `<input type="file">`)
- **Location**: `ParameterLocation.FORM` or `ParameterLocation.MULTIPART`
- **Source**: `ParameterSource.HTML_FORM`

### 2.4 Observed JSON Payloads
- **Extraction**: Traverses structured JSON request/response bodies and maps JSONPath expressions (`$.user.id`, `$.score`).
- **Location**: `ParameterLocation.JSON`
- **Source**: `ParameterSource.JSON_BODY`
- **Type Mapping**: Automatically distinguishes between `STRING`, `INTEGER`, `FLOAT`, `BOOLEAN`, `ARRAY`, and `OBJECT`.

### 2.5 OpenAPI / Swagger Specifications
- **Extraction**: Parses OpenAPI 3.x and Swagger 2.0 definitions (`parameters[].in`, `requestBody.content.application/json.schema`).
- **Source**: `ParameterSource.OPENAPI_SCHEMA`

---

## 3. Data Model (`DiscoveredParameter`)

```python
@dataclass
class DiscoveredParameter:
    parameter_id: str
    endpoint_url: str
    method: str
    name: str
    location: ParameterLocation
    param_type: ParameterType
    source: ParameterSource
    provenance: str
    baseline_value: Any = None
    json_path: Optional[str] = None
    acceptable_values: list[Any] = field(default_factory=list)
    is_required: bool = False
    is_sensitive: bool = False
```

---

## 4. Anti-Synthetic Parameter Guarantee

AihaX explicitly rejects probing unproven parameters (e.g. fuzzing dictionary wordlists against random endpoints without crawl or OpenAPI evidence). This keeps request volume bounded, reduces server load, and avoids polluting bug bounty audit logs with noise.
