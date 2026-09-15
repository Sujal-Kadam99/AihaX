# Reconnaissance Safety & Boundary Enforcement

## 1. Pre-Probe Scope Gating Invariant

The fundamental safety guarantee of AihaX Reconnaissance is:
> **OUT-OF-SCOPE ASSET -> ZERO NETWORK BYTES.**

Discovered assets must pass `ScopeValidator.validate_target` before:
- Opening any TCP socket
- Initiating any TLS handshake
- Sending any DNS lookup beyond in-scope root zones
- Transmitting any HTTP request

---

## 2. Redirect Scope Boundary Enforcement

Redirect loops and multi-hop redirects are handled manually with per-hop scope validation:

```python
# Multi-Hop Redirect Intelligence
for _ in range(self.max_redirects):
    next_hop = urljoin(current_url, location)
    hop_scope = self.scope_validator.validate_target(next_hop)
    
    if not hop_scope.allowed:
        redirect_chain.append({
            "source": current_url,
            "status": curr_status,
            "destination": next_hop,
            "scope_allowed": False,
            "block_reason": "Redirect hop exits authorized scope",
        })
        break  # STOP IMMEDIATELY. DO NOT PROBE DESTINATION.
```

If an authorized target issues a 301/302 redirect to an out-of-scope host (e.g. `http://evil-attacker.com`), AihaX records the redirect metadata and **aborts immediately without fetching the external target**.

---

## 3. Error Resilience & Malformed Data Handling

The recon pipeline is hardened against malformed remote responses:
- **XML Entities & Sitemaps**: Safe non-resolving XML parser without external entity evaluation.
- **HTML Crawling**: Tolerant regex-based extraction resilient to unclosed tags, scripts, and broken HTML.
- **JSON OpenAPI**: Graceful fallback when Swagger/OpenAPI specifications contain syntax errors.
- **Soft-404 Detection**: Randomized canary paths (`/.well-known/probe-soft404-...`) establish an empirical 404 baseline to prevent deceptive 200 responses from poisoning endpoint inventories.
- **Rate Limit Adherence**: Automatically captures HTTP 429 status codes and respects `Retry-After` headers.
