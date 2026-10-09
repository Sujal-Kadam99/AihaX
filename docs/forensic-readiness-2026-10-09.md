# Forensic readiness — 2026-10-09

## Scope and worktree audit

- Integration worktree: `codex/aihax-evidence-first-merge` only. No commits were created because this checkout already contains a broad, dirty integration diff; committing it would capture unowned changes.
- Original Main checkout (`master`) and VTA checkout (`codex/vta-tool-integration`) were inspected read-only and left untouched by this work. Both already contain unrelated dirty changes; preserve those edits.
- Integration diff areas are recon agent/orchestrator/endpoint discovery, campaign worker, VTA/hypothesis/selector/execution/verifier, request engine, tool policy/adapters, registry/check strategies, tests, Docker config, and tool docs. No billing/auth/frontend files are modified in this integration worktree.
- Existing Docker Compose config only defines app services/ZAP; it does not provide a per-campaign default-deny network, logging DNS, connection capture, or blocked-egress telemetry. Host subprocess execution is fail-closed until that runner exists.

## Implemented and locally checked

- Campaign worker shares its scoped `RequestEngine` with AihaX-managed recon HTTP and VTA; subprocess scanners are still a separate path.
- Endpoint observations preserve observed query/body/header/path inputs. Parameter-driven hypotheses without a location-appropriate observed input are marked `PREREQUISITE_MISSING`; synthetic fallback names are removed.
- Request counters now expose attempted/sent/denied/redirected/reused. The specified case is tested: `attempted=2, sent=2, denied=1, redirected=1, reused=1`. `record_reused()` is caller-side instrumentation; no production cache/reuse path was found.
- HTTPS tests cover scope/mock behavior and a real local TLS handshake using a test trust store; certificate validation remains enabled. No live campaign-worker HTTPS positive control has been run.
- Fresh local VTA fixture test demonstrates a candidate claim linked to actual request IDs, HTTP 500 response, and a resolvable evidence vault record in the same scratch database. No external target or network is used.

## 86-check strategy and evidence contract

The registry currently has 86 entries, including 16 injection-category checks. Each injection check now either requires an observed input in declared locations or carries an explicit reason why its protocol-level probe has no application parameter. `CHECK_NATIVE` means the registered check implementation is the primary strategy; the other names are check-specific strategies. The table reports declared requirements, not proof each strategy satisfies them at runtime.

| Check | Strategy | Requires observed parameters | Input locations | Parameterless input rationale | Required evidence | Required capabilities |
|---|---|---:|---|---|---|---|
| C001 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response | http |
| C002 | `SECURITY_HEADER_INSPECTION` | no | not required | — | affected_url, required_header | http |
| C003 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, sensitive_keyword | http |
| C004 | `CHECK_NATIVE` | no | not required | — | affected_url, origin_header, acao_header | http |
| C005 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response | http |
| C006 | `DIRECTORY_LISTING_PROBE` | no | not required | — | affected_url, proof_response | http |
| C007 | `OPEN_REDIRECT_PROBE` | no | not required | — | affected_url, redirect_param, proof_response | http |
| C008 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, service_fingerprint | http |
| C009 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, admin_marker | http |
| C010 | `SECURITY_HEADER_INSPECTION` | no | not required | — | affected_url, proof_response | http |
| C011 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, disclosed_version | http |
| C012 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, bypass_technique | http |
| C013 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, cookie_header | http |
| C014 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, cookie_header | http |
| C015 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, cookie_header | http |
| C016 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, cookie_header | http |
| C017 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, fixed_session_token | http |
| C018 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, replayed_token | http |
| C019 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, tested_weak_password | http |
| C020 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, forged_token | http |
| C021 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, expired_token | http |
| C022 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, consecutive_attempts | http |
| C023 | `SQLI_DIFFERENTIAL_ERROR` | yes | query, body | — | affected_url, affected_param, payload, proof_request, proof_response | http |
| C024 | `SQLI_DIFFERENTIAL_ERROR` | yes | query, body | — | affected_url, proof_response, differential_proof | http |
| C025 | `CHECK_NATIVE` | yes | query, body | — | affected_url, proof_response, nosql_operator_payload | http |
| C026 | `CHECK_NATIVE` | yes | query, body | — | affected_url, proof_response, command_error_signature | http |
| C027 | `CHECK_NATIVE` | yes | query, body | — | affected_url, proof_response, evaluated_canary | http |
| C028 | `CHECK_NATIVE` | yes | query, body | — | affected_url, proof_response, evaluated_expression | http |
| C029 | `CHECK_NATIVE` | yes | query | — | affected_url, proof_response, injected_header | http |
| C030 | `CHECK_NATIVE` | yes | query | — | affected_url, proof_response, injected_cookie | http |
| C031 | `PATH_TRAVERSAL_PROBE` | yes | query, body, path | — | affected_url, proof_response, file_marker | http |
| C032 | `PATH_TRAVERSAL_PROBE` | yes | query, body, path | — | affected_url, proof_response, decoded_source_snippet | http |
| C033 | `CHECK_NATIVE` | yes | body | — | affected_url, proof_response, expanded_entity_canary | http |
| C034 | `CHECK_NATIVE` | yes | query, body | — | affected_url, proof_response, ldap_error_snippet | http |
| C035 | `CHECK_NATIVE` | yes | query, body | — | affected_url, proof_response, evaluated_expression | http |
| C036 | `CHECK_NATIVE` | yes | query, body | — | affected_url, proof_response, fetched_resource | http |
| C037 | `XSS_CANARY_PROBE` | yes | query, body | — | affected_url, proof_response, reflected_canary | http |
| C038 | `XSS_CANARY_PROBE` | yes | body | — | affected_url, proof_response, persisted_canary | http |
| C039 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, sink_source_pattern | http |
| C040 | `XSS_CANARY_PROBE` | yes | query, body | — | affected_url, proof_response, injected_tag | http |
| C041 | `CHECK_NATIVE` | yes | query, body | — | affected_url, proof_response, injected_attribute | http |
| C042 | `CHECK_NATIVE` | yes | query, body | — | affected_url, proof_response, injected_script_breakout | http |
| C043 | `CHECK_NATIVE` | yes | query, body | — | affected_url, proof_response, injected_scheme | http |
| C044 | `CHECK_NATIVE` | yes | query, body | — | affected_url, proof_response, mxss_payload | http |
| C045 | `CHECK_NATIVE` | yes | query, body | — | affected_url, proof_response, bypassed_payload | http |
| C046 | `CHECK_NATIVE` | yes | query, body | — | affected_url, proof_response, rendered_html_tag | http |
| C047 | `SECURITY_HEADER_INSPECTION` | no | not required | — | affected_url, proof_response, headers_analyzed | http |
| C048 | `SECURITY_HEADER_INSPECTION` | no | not required | — | affected_url, proof_response, csp_header | http |
| C049 | `SECURITY_HEADER_INSPECTION` | no | not required | — | affected_url, proof_response, framing_headers | http |
| C050 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, headers_analyzed | http |
| C051 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, policy_content | http |
| C052 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, enabled_methods | http |
| C053 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, setup_page_indicator | http |
| C054 | `VERBOSE_ERROR_PROBE` | no | not required | — | affected_url, proof_response, stack_trace_snippet | http |
| C055 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, accepted_extension | http |
| C056 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, normalization_discrepancy | http |
| C057 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, secret_type | http |
| C058 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, source_map_indicator | http |
| C059 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, sensitive_parameter | http |
| C060 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, comment_snippet | http |
| C061 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, backup_file_indicator | http |
| C062 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, sql_dump_indicator | http |
| C063 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, bucket_url | http |
| C064 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, git_head_content | http |
| C065 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, http_status | http |
| C066 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, storage_pattern | http |
| C067 | `BOLA_CROSS_ACCOUNT_PROBE` | no | not required | — | affected_url, proof_response, target_id | http |
| C068 | `BOLA_CROSS_ACCOUNT_PROBE` | no | not required | — | affected_url, proof_response, target_uuid | http |
| C069 | `BOLA_CROSS_ACCOUNT_PROBE` | no | not required | — | affected_url, proof_response, tampered_path_id | http |
| C070 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, bound_privileged_field | http |
| C071 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, unauthorized_access_proof | http |
| C072 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, exposed_function | http |
| C073 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, tampered_value | http |
| C074 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, skipped_endpoint | http |
| C075 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, concurrent_successes | http |
| C076 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, replayed_status | http |
| C077 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_response, sensitive_endpoint | http |
| C078 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_request | http |
| C079 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_request | http |
| C080 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_request | http |
| C081 | `CHECK_NATIVE` | no | not required | The check injects the protocol-level Host and X-Forwarded-Host headers directly; it does not rely on an application parameter. | affected_url, proof_request | http |
| C082 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_request | http |
| C083 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_request | http |
| C084 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_request | http |
| C085 | `CHECK_NATIVE` | no | not required | — | affected_url, proof_request | http |
| C086 | `CHECK_NATIVE` | yes | body | — | affected_url, proof_request | http |

## Tool state contract

The runtime tool catalog now reports registered, installed, runnable, selected, executed, and produced-evidence separately. Available CLI binaries are reported installed but `RUNNER_UNAVAILABLE` and not runnable until campaign-scoped Docker isolation exists; ZAP API readiness is reported separately. Readiness is not execution. The saved benchmark reports predate this schema and cannot be retroactively credited with per-tool execution evidence. CLI execution remains blocked on the host until Docker isolation and network telemetry are implemented.

## Historical evidence-vault audit

Read-only query of benchmark databases, restricted to rows marked `VERIFIED`:

| Build | Positive findings | Evidence references | Unresolved references | Findings with unresolved IDs |
|---|---:|---:|---:|---:|
| Main | 1 | 1 | 1 | 1 |
| VTA | 72 | 164 | 164 | 72 |

This is a complete audit of the saved databases’ positive findings, not a statement about future merged-code runs. The historical VERIFIED counts are not evidence-backed in those databases. The fresh fixture test separately demonstrates the current write-and-resolve path.

## Gates and remaining acceptance work

- **Gate A — PARTIAL, NOT PASSED:** a disposable Docker internal network positive control (`gate-a-20261009-02`) used pinned CoreDNS, Nginx, and netshoot images. Nmap probed the fixture; CoreDNS logged the scanner query; tcpdump captured DNS and target HTTP/TLS packets; normal TLS verification passed; a direct documentation-range egress attempt failed `ENETUNREACH` with zero matching pcap packets. Evidence is in [`docker/gate-a/evidence`](../docker/gate-a/evidence/gate-a-positive-control.md). This did not run through `campaign_worker`, and authorization-specific external egress allowlisting/redirect enforcement remains unimplemented and untested. Keep production subprocess execution fail-closed; do not run the live benchmark.
- **Gate B — PASSED for one local fixture:** the test produces one candidate with a claim, actual request IDs, HTTP request/response, and a resolved vault row. This does not establish all check families or positive verdicts.
- **HTTPS:** mock/scope tests, local TLS transport tests, and this controlled scanner's HTTP/HTTPS positive controls pass with certificate validation enabled. Campaign-worker-vs-direct HTTPS comparison remains unrun.
- **Ground truth:** [`dvwa-ground-truth-source-matrix.md`](dvwa-ground-truth-source-matrix.md) now maps 12 check families to the official DVWA source at a pinned commit and records conservative per-level source expectations. This is a source oracle, not runtime proof; the remaining check families are explicitly `NOT_COVERED` and need separate fixtures. Do not score level sensitivity from aggregate finding counts.
- **Request-budget divergence:** historical harness reports show Main at 500 used / 319 denied with 621 hypotheses per level, versus VTA at 20 / 0 with 306 hypotheses. The old harness attaches its own request-budget callback to `RequestEngine`, applies an HTTP-only target gate, and sets `Campaign.check_budget=20` alongside campaign/target/request budgets of 500. The campaign recon constructor also omitted the shared `RequestEngine`. These are concrete harness/path differences, but they do not yet explain the full 480-request gap.
- **Legacy benchmark entry points:** `run_dvwa_scan.py` and `run_dvwa_scan_direct.py` now exit before making requests. The former made direct HTTP calls and reset DVWA state; the latter monkey-patched scope and destination validation. Both remain disabled until a gated campaign runner is available.
- **Live 12-campaign DVWA benchmark:** not run or scheduled. It remains blocked until Gate A passes and level-specific ground truth is reviewed.

## Verification evidence

- Passed targeted suites: 120 tests covering all 86 registry contracts and declared strategies, location-specific parameter gating, request counters and local HTTPS, shared-engine recon, fresh VTA-to-vault trace, and tool-state reporting.
- Both legacy DVWA entry points were invoked and exited with the expected blocked status before any scan setup or HTTP request.
- The DVWA source-matrix `NOT_COVERED` inventory was checked against the current registry: 71 listed IDs match the 86-check registry minus the 15 mapped IDs.
- Gate A fixture control produced independent DNS, packet-capture, and blocked-connect evidence; it does not satisfy campaign-worker integration or scoped external egress acceptance.
- Broader test suite was not run to completion; do not treat the targeted pass as whole-repository validation.
- Original Main/VTA checkouts were only read for their status/branch and were not modified by this work.
