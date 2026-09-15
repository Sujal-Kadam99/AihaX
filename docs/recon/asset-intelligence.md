# Asset Intelligence & Classification Engine

## 1. Asset Discovery & Pre-Probe Scope Gating

Asset discovery operates under a strict **pre-probe scope gating invariant**:
> Every candidate asset discovered via user input, seed lists, wordlists, or passive providers must be validated by `ScopeValidator.validate_target` **BEFORE** any HTTP connection or socket byte is transmitted.

```python
# Strict Pre-Probe Scope Evaluation
scope_decision = self.scope_validator.validate_target(canonical.canonical_url)

if scope_decision.allowed:
    discovered_asset.scope_status = "IN_SCOPE"
    in_scope.append(discovered_asset)
else:
    discovered_asset.scope_status = "OUT_OF_SCOPE"
    out_of_scope.append(discovered_asset)
    safety_events.append({
        "action": "asset_blocked_out_of_scope",
        "reason": scope_decision.reason,
        "target": canonical.canonical_url,
    })
```

Out-of-scope assets are recorded in the reconnaissance report for audit visibility but are never probed or sent to network transport.

---

## 2. Asset Classification Taxonomy

Discovered assets are categorized into standardized asset types:
- `WEB_APPLICATION`: Standard web application with HTML interface.
- `API`: REST or JSON API surface (e.g. `api.example.com` or `/api/v1/`).
- `GRAPHQL`: GraphQL endpoint (e.g. `graphql.example.com` or `/graphql`).
- `AUTHENTICATED_APPLICATION`: Login portal or OAuth gateway.
- `SUBDOMAIN`: Discovered host with subdomain hierarchy.
- `STATIC_STORAGE`: Static asset bucket or CDN endpoint.

---

## 3. Subdomain Discovery Providers

AihaX provides extensible discovery interfaces:
1. `ScopedWordlistProvider`: Applies authorized subdomain prefixes (e.g., `api`, `app`, `dev`, `auth`, `admin`, `graphql`) against target root domain, immediately passing candidates through `ScopeValidator`.
2. `PassiveFeedProvider`: Certificate Transparency and OSINT provider interface. Defaults to `PROVIDER_UNAVAILABLE` when external API credentials are not supplied, avoiding runtime exceptions or mock data.
