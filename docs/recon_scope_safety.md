# AihaX Reconnaissance Scope & Safety Policies

## The Critical Scope Rule

Discovered assets are not automatically authorized targets.

A wildcard program boundary such as `*.example.com` permits passive discovery and scope classification of subdomains, but does **not** authorize active vulnerability testing against them.

### State Transitions for Discovered Assets

1. **`DISCOVERED`**: Candidate hostname or URL surfaced by passive or active providers.
2. **`IN_SCOPE`**: Passed `ScopeValidator.validate_target()`; confirmed within program boundary.
3. **`BLOCKED_SCOPE`**: Excluded explicitly or outside program boundary; zero further probing permitted.
4. **`BLOCKED_SAFETY`**: Destination resolves to private IP, loopback, or cloud metadata (169.254.169.254).
5. **`NOT_EXECUTABLE`**: Default state for all discovered assets. Reconnaissance does not attack discoveries.
6. **`EXECUTABLE_AFTER_AUTHORIZATION`**: Requires separate, explicit authorization record to perform testing.

## Central Network Boundary

All external HTTP/HTTPS traffic must route strictly through:

```text
RequestEngine → ScopeValidator → transport
```

Direct calls using `requests`, `urllib`, `aiohttp.ClientSession`, `httpx`, or raw `socket.connect` outside the central engine are forbidden.
Redirects are validated per-hop: if an HTTP redirect leads to an out-of-scope domain or private IP, the redirect is blocked immediately.
