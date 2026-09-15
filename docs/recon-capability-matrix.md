# AihaX Recon Capability Matrix

## Authoritative Capability Matrix

| Capability                | Adapter | Audit Mode | Dry Run | Authorized Live | Status Classification | Notes |
| :------------------------ | :-----: | :--------: | :-----: | :-------------: | :-------------------- | :---- |
| **Subfinder**             | YES     | YES        | YES     | YES             | `LIVE_ADAPTER_PRESENT_NOT_LIVE_VALIDATED` | CLI tool via ToolExecutionBoundary (`-d <domain> -silent`). Requires authorization; mock fixture in Audit Mode. |
| **Sublist3r**             | NO      | YES        | YES     | NO              | `NOT_IMPLEMENTED`     | Formally evaluated: search engine scrapers are brittle and duplicate data comprehensively covered by Subfinder/CT. Classified `SUBLIST3R_NOT_IMPLEMENTED — COVERAGE DUPLICATED BY SUBFINDER/AMASS/CT`. |
| **Amass**                 | YES     | YES        | YES     | YES             | `LIVE_ADAPTER_PRESENT_NOT_LIVE_VALIDATED` | CLI tool via ToolExecutionBoundary (`enum -passive -d <domain>`). Restricted to passive mode; requires authorization. |
| **Certificate Transparency** | YES  | YES        | YES     | YES             | `LIVE_ADAPTER_PRESENT_NOT_LIVE_VALIDATED` | Queries `https://crt.sh/?q=%.<domain>&output=json` strictly via RequestEngine. Mock in Audit Mode. |
| **Passive DNS**           | YES     | YES        | YES     | YES             | `LIVE_ADAPTER_READY`  | Processes passive DNS records and zone dumps deterministically without external queries. |
| **Active DNS**            | YES     | YES        | YES     | YES             | `LIVE_ADAPTER_PRESENT_NOT_LIVE_VALIDATED` | Controlled `dnspython` resolver querying A, AAAA, CNAME, MX, NS, TXT, SOA with query budgets. Mock in Audit Mode. |
| **HTTP/HTTPS Probing**    | YES     | YES        | YES     | YES             | `LIVE_ADAPTER_READY`  | Read-only GET probing through central RequestEngine -> ScopeValidator -> transport with per-hop redirect validation. |
| **Technology Fingerprinting** | YES | YES        | YES     | YES             | `LIVE_ADAPTER_READY`  | Deterministic header, body, and marker detector (`TechnologyDetector`) plus WhatWeb boundary adapter. |
| **Endpoint Discovery**    | YES     | YES        | YES     | YES             | `LIVE_ADAPTER_READY`  | In-scope crawler extracting links, scripts, and API routes. Discovered endpoints tagged `NOT_EXECUTABLE` by default. |
| **Attack Surface Graph**  | YES     | YES        | YES     | YES             | `LIVE_ADAPTER_READY`  | Maps targets, subdomains, endpoints, parameters, and technologies to deterministic SHA-256 graph snapshots. |

---

## Status Classification Taxonomy

* **`MOCK_ONLY`**: The capability only operates via deterministic mock fixtures or synthetic data; no external invocation code exists.
* **`LIVE_ADAPTER_PRESENT_NOT_LIVE_VALIDATED`**: The real adapter, safe command builder, argument validator, timeout bounds, and authorization gate are fully wired and functional, but has not yet been validated against a real target in this environment because no authorized concrete live target was provided.
* **`LIVE_VALIDATED_CONTROLLED`**: Validated against an explicitly authorized concrete target under recorded operator confirmation.
* **`LIVE_ADAPTER_READY`**: Fully implemented and tested with RequestEngine/mock transports.
* **`NOT_IMPLEMENTED`**: Intentionally omitted or evaluated as non-additive.
