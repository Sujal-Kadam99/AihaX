# Real-Target Validation Strategy for the 86-Check Registry

**Status:** Strategy, registry inventory, and a live loopback Juice Shop assessment. The run proves the recon-to-C023 SQL injection path; it does not certify broad platform coverage.
**Evidence policy:** Do not use mocks, simulated HTTP responses, the in-process security fixture, or generated findings. Every executed check must use the production `RequestEngine` and a real HTTP/TLS endpoint in an explicitly authorized, operator-controlled environment. Persist the captured request and response evidence, verifier outcome, and report output.

## Gate before any live run

1. Use an application deployment controlled by the operator. Record application name/version, deployment source or image digest, host, operator authorization record, and test window. Never substitute an external organization without explicit scope authorization.
2. Run the assessment from a dedicated host with an egress allowlist limited to the target host and required DNS. Keep the target local or in a private assessment environment; record the resolved addresses and confirm they belong to the operator-controlled environment.
3. Run one selected check at a time first. Confirm scope validation, request method, budget, and rate limits from the actual outgoing request log. Stop immediately on an out-of-scope redirect, unexpected write, or unrelated host connection.
4. Establish a baseline request and response before testing. Capture response headers/body and SHA-256 digest. Store credentials and real secrets encrypted/redacted; never include secret values in a report. Use a synthetic value only if it was deliberately provisioned in the actual application under test and label it as test data.
5. Execute every network-producing check via the real request boundary. For checks that analyze discovered URLs without making a request themselves, require the URL to come from live in-scope recon evidence and record that input provenance. A candidate is not a finding. Run its declared independent verification strategy with a separate verification request and save evidence IDs, request IDs when present, verifier version, verdict, confidence, and reason.
6. Report only independently verified findings. Include exact target path, reproducible request, relevant redacted response excerpt, response hash, impact supported by evidence, remediation, and report-integrity hash. Keep inferred impact visibly separate from observed fact.
7. Run the full 86-check campaign only after the single-check gates pass. Record per-check status as `VERIFIED`, `REJECTED`, `INCONCLUSIVE`, `BLOCKED_SCOPE`, `BLOCKED_CAPABILITY`, `BLOCKED_SAFETY`, or `NOT_RUN`; never convert a skip or error into a pass. Reconcile planned/executed/skipped IDs against the registry and preserve the final coverage report.

## Required acceptance evidence per check

- Registry identity, contract version, severity, risk level, declared method and prerequisites.
- Authorization ID, scope snapshot hash, target URL, resolved IP and assessment timestamp.
- RequestEngine request ID, exact sanitized request, actual status/headers/body excerpt, response SHA-256, and transport outcome.
- For candidates: independent verifier request/evidence IDs, verifier name/version, final verdict/reason/confidence.
- Coverage status and audit events; all requests must remain in the allowlisted target scope and within configured limits.
- For verified findings: a generated report with fact/inference separation, reproduction steps, safe/redacted proof, remediation, and integrity digest.

## Registry-derived execution plan

The table below is generated from the currently registered check contracts. It is a planning inventory, not evidence that checks ran or that their declarations have been independently validated. The `Declared method` column is only the contract's primary/default method; actual source inspection found checks that issue additional request methods (see the audit below). Actual runtime behavior and emitted requests must be inspected during each live run.

| Check ID | Check | Severity | Contract risk | Contract method | Source-observed methods | Capabilities | Prerequisites | Verification strategy |
|---|---|---|---|---|---|---|---|---|
| `C001_Open_Port_80` | Open Port / HTTP Exposure | info | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `transport_security` |
| `C002_Missing_Security_Headers` | Missing Security Headers | low | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `http_response_property` |
| `C003_Sensitive_Files_Exposure` | Sensitive Files Exposure | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `sensitive_file_exposure` |
| `C004_CORS_Misconfiguration` | CORS Misconfiguration | medium | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `cors_misconfiguration` |
| `C005_GraphQL_Introspection` | GraphQL Introspection Enabled | low | SAFE_ACTIVE / production=True / destructive=False | GET | POST | http | auth=False, browser=False, workflow=False | `graphql_introspection` |
| `C006_Directory_Listing` | Directory Listing Enabled | low | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `directory_listing` |
| `C007_Open_Redirect` | Open Redirect | medium | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `open_redirect` |
| `C008_Subdomain_Takeover` | Subdomain Takeover / Dangling DNS | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `subdomain_takeover` |
| `C009_Exposed_Admin_Interface` | Exposed Administrative Interface | medium | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `sensitive_file_exposure` |
| `C010_TLS_Configuration_Weakness` | TLS / HTTPS Configuration Weakness | low | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `http_response_property` |
| `C011_Technology_Exposure` | Technology / Version Exposure | info | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `http_response_property` |
| `C012_Auth_Bypass_Indicators` | Authentication Bypass Indicators | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `authentication_comparison` |
| `C013_Weak_Session_Cookie` | Weak Session Cookie Configuration | low | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `http_response_property` |
| `C014_Missing_Secure_Cookie` | Missing Secure Cookie Attribute | medium | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `http_response_property` |
| `C015_Missing_HttpOnly_Cookie` | Missing HttpOnly Cookie Attribute | medium | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `http_response_property` |
| `C016_Missing_SameSite_Cookie` | Missing SameSite Cookie Attribute | low | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `http_response_property` |
| `C017_Session_Fixation` | Session Fixation Indicators | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C018_Session_Invalidation` | Session Invalidation Failure | medium | SAFE_ACTIVE / production=True / destructive=False | GET | GET, POST | http | auth=False, browser=False, workflow=False | `authentication_comparison` |
| `C019_Password_Policy_Weakness` | Password Policy Weakness Indicators | low | SAFE_ACTIVE / production=True / destructive=False | GET | POST | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C020_JWT_Algorithm_Weakness` | JWT Algorithm / Configuration Weakness | critical | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `authentication_comparison` |
| `C021_JWT_Claim_Validation` | JWT Claim Validation Weakness | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `authentication_comparison` |
| `C022_Auth_Rate_Limit` | Authentication Rate-Limit Weakness | medium | SAFE_ACTIVE / production=True / destructive=False | GET | POST | http | auth=False, browser=False, workflow=False | `auth_rate_limit` |
| `C023_SQL_Injection` | SQL Injection | critical | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C024_Blind_SQL_Injection` | Blind SQL Injection | critical | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C025_NoSQL_Injection` | NoSQL Injection | critical | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C026_Command_Injection_Indicators` | Command Injection Indicators | critical | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C027_OS_Command_Injection` | OS Command Injection | critical | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C028_SSTI` | Server-Side Template Injection | critical | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C029_Header_Injection` | Header Injection | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `http_response_property` |
| `C030_CRLF_Injection` | CRLF Injection / HTTP Response Splitting | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `http_response_property` |
| `C031_Path_Traversal` | Path Traversal | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C032_Local_File_Inclusion` | Local File Inclusion Indicators | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C033_XXE_Indicators` | XML External Entity (XXE) Indicators | high | SAFE_ACTIVE / production=True / destructive=False | GET | POST | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C034_LDAP_Injection` | LDAP Injection Indicators | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C035_EL_Injection` | Expression Language Injection | critical | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C036_SSRF_Indicators` | Server-Side Request Forgery Indicators | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C037_Reflected_XSS` | Reflected XSS | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C038_Stored_XSS` | Stored XSS Verification | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET, POST | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C039_DOM_XSS_Indicators` | DOM XSS Indicators | medium | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C040_HTML_Context_Injection` | HTML Context Injection | medium | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C041_Attribute_Context_Injection` | Attribute Context Injection | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C042_JavaScript_Context_Injection` | JavaScript Context Injection | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C043_URL_Context_Injection` | URL Context Injection | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C044_Mutation_XSS` | Mutation-Based XSS Indicators | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C045_XSS_Filter_Bypass` | XSS Filter / Sanitization Bypass Indicators | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C046_Unsafe_HTML_Rendering` | Unsafe HTML Rendering | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C047_Missing_CSP` | Missing Content Security Policy (CSP) | medium | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `http_response_property` |
| `C048_Weak_CSP` | Weak Content Security Policy (CSP) | low | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `http_response_property` |
| `C049_Clickjacking` | Clickjacking / Missing Frame Options | medium | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `http_response_property` |
| `C050_MIME_Sniffing` | MIME Sniffing Vulnerability | low | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `http_response_property` |
| `C051_Cross_Domain_Policy` | Cross-Domain Policy Misconfiguration | low | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C052_Insecure_HTTP_Methods` | Insecure HTTP Methods Enabled | low | SAFE_ACTIVE / production=True / destructive=False | GET | OPTIONS, TRACE | http | auth=False, browser=False, workflow=False | `http_response_property` |
| `C053_Default_Setup_Page` | Default / Installation Setup Page Exposed | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `sensitive_file_exposure` |
| `C054_Verbose_Error_Disclosure` | Verbose Error / Stack Trace Disclosure | low | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C055_Dangerous_File_Upload` | Dangerous File Upload Permitted | high | SAFE_ACTIVE / production=True / destructive=False | GET | POST | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C056_Path_Normalization` | Path Normalization Inconsistency | medium | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C057_Exposed_API_Keys` | Hardcoded API Keys / Secrets Exposed | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `sensitive_file_exposure` |
| `C058_Source_Map_Exposure` | Source Map Exposure | low | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `sensitive_file_exposure` |
| `C059_PII_URL_Exposure` | PII / Sensitive Data in URL Query Parameters | medium | SAFE_ACTIVE / production=True / destructive=False | GET | No request constructed | http | auth=False, browser=False, workflow=False | `http_response_property` |
| `C060_Comment_Information_Disclosure` | Information Disclosure in Source Comments | low | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C061_Backup_File_Exposure` | Backup / Temporary File Exposure | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `sensitive_file_exposure` |
| `C062_Database_Dump_Exposure` | Database Dump Exposure | critical | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `sensitive_file_exposure` |
| `C063_Cloud_Bucket_Exposure` | Cloud Storage Bucket Exposure | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C064_Git_Metadata_Exposure` | Version Control Metadata (.git) Exposure | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `sensitive_file_exposure` |
| `C065_Unencrypted_Transmission` | Unencrypted Transmission of Sensitive Data | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `transport_security` |
| `C066_Cleartext_Storage_Indicators` | Cleartext Sensitive Storage Indicators | low | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C067_IDOR_Numeric_IDs` | Insecure Direct Object Reference (IDOR) on Numeric IDs | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `authorization_comparison` |
| `C068_IDOR_UUIDs` | Insecure Direct Object Reference (IDOR) on UUIDs | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `authorization_comparison` |
| `C069_BOLA_API` | Broken Object Level Authorization (BOLA) in API Endpoints | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `authorization_comparison` |
| `C070_Mass_Assignment` | Mass Assignment / Parameter Pollution | high | SAFE_ACTIVE / production=True / destructive=False | GET | POST | http | auth=False, browser=False, workflow=False | `authorization_comparison` |
| `C071_Privilege_Escalation` | Privilege Escalation Indicators | critical | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `authorization_comparison` |
| `C072_Function_Access_Control` | Function-Level Access Control Bypass | high | SAFE_ACTIVE / production=True / destructive=False | GET | OPTIONS | http | auth=False, browser=False, workflow=False | `authorization_comparison` |
| `C073_Parameter_Tampering` | Price / Parameter Tampering Vulnerability | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C074_Workflow_Step_Skipping` | Step Skipping in Multi-Step Workflows | high | SAFE_ACTIVE / production=True / destructive=False | GET | POST | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C075_Race_Condition` | Race Condition / Concurrency Vulnerability | high | SAFE_ACTIVE / production=True / destructive=False | GET | POST | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C076_Replay_Attack` | Replay Attack Vulnerability | medium | SAFE_ACTIVE / production=True / destructive=False | GET | POST | http | auth=False, browser=False, workflow=False | `generic_reproducibility` |
| `C077_Missing_Reauthentication` | Missing Re-Authentication on Sensitive Actions | medium | SAFE_ACTIVE / production=True / destructive=False | GET | POST | http | auth=False, browser=False, workflow=False | `authorization_comparison` |
| `C078_HTTP_Request_Smuggling` | HTTP Request Smuggling (CL.TE / TE.CL Desync) | critical | SAFE_ACTIVE / production=True / destructive=False | GET | POST | http | auth=False, browser=False, workflow=False | `http_request_smuggling` |
| `C079_Web_Cache_Poisoning` | Web Cache Poisoning / Cache Deception | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `web_cache_poisoning` |
| `C080_Cross_Site_WebSocket_Hijacking` | Cross-Site WebSocket Hijacking (CSWSH) | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `cswsh` |
| `C081_Host_Header_Injection` | Host Header Injection | medium | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `host_header_injection` |
| `C082_GraphQL_Batching_Nested_Query_DoS` | GraphQL Batching / Nested Query DoS Indicators | medium | SAFE_ACTIVE / production=True / destructive=False | GET | POST | http | auth=False, browser=False, workflow=False | `graphql_batching` |
| `C083_GraphQL_Resolver_Auth_Bypass` | GraphQL Resolver-Level Authorization Bypass | high | SAFE_ACTIVE / production=True / destructive=False | GET | POST | http | auth=False, browser=False, workflow=False | `graphql_resolver_auth` |
| `C084_OAuth_Redirect_URI_Validation` | OAuth/SSO Redirect URI Validation Weakness | high | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `oauth_redirect_uri` |
| `C085_Missing_OAuth_State_Parameter` | Missing OAuth state Parameter (CSRF on OAuth flow) | medium | SAFE_ACTIVE / production=True / destructive=False | GET | GET | http | auth=False, browser=False, workflow=False | `oauth_state_parameter` |
| `C086_Insecure_Deserialization_Indicators` | Insecure Deserialization Indicators | high | SAFE_ACTIVE / production=True / destructive=False | GET | POST | http | auth=False, browser=False, workflow=False | `insecure_deserialization` |
## Source-level request-method audit

Before a live run, inspect the implementation as well as its contract. The current registry labels all 86 checks `SAFE_ACTIVE`, `production_allowed=True`, `destructive=False`, and declares `GET` as the primary method. Direct source inspection nevertheless found non-GET requests in these implementations:

- **POST (16 check IDs):** `C005_GraphQL_Introspection`, `C018_Session_Invalidation`, `C019_Password_Policy_Weakness`, `C022_Auth_Rate_Limit`, `C033_XXE_Indicators`, `C038_Stored_XSS`, `C055_Dangerous_File_Upload`, `C070_Mass_Assignment`, `C074_Workflow_Step_Skipping`, `C075_Race_Condition`, `C076_Replay_Attack`, `C077_Missing_Reauthentication`, `C078_HTTP_Request_Smuggling`, `C082_GraphQL_Batching_Nested_Query_DoS`, `C083_GraphQL_Resolver_Auth_Bypass`, and `C086_Insecure_Deserialization_Indicators`.
- **OPTIONS (2 check IDs):** `C052_Insecure_HTTP_Methods` and `C072_Function_Access_Control`.
- **TRACE (1 check ID):** `C052_Insecure_HTTP_Methods` also issues an HTTP TRACE request.
- **No request constructed (1 check ID):** `C059_PII_URL_Exposure` parses only the campaign target URL; it does not itself inspect live-recon endpoint URLs. With a plain root URL it cannot prove PII exposure elsewhere in the application.

POST does not automatically mean destructive, but the contract currently understates runtime methods. Review each request body, endpoint, and state effect against the real target before the full campaign. In particular, run race, replay, upload, workflow, password, mass-assignment, and stored-XSS checks only on a disposable operator-owned deployment with a reset procedure. TRACE should be tested only if the actual server supports it and the test is within scope. If source review or observed traffic contradicts the declared risk/method, mark that check blocked and fix the contract/guard before certifying it. A full 86-check pass must include actual emitted-method evidence, not just a coverage count.

## Current pipeline status and evidence

The SAFE_SCAN path can now opt into live, host-bounded recon. Discovered endpoints and input parameter names are passed to checks with their discovery source; C023 consumes discovered GET parameters and uses its dedicated verifier to replay the exact candidate payload against a benign baseline. Endpoint and recon metadata are preserved with request/response evidence.

The current live run is `reports/live-86-assessments/2e0a7697-a7a6-40c2-a3e1-8e64ff29f343`. It reconciled all 86 registry IDs, executed 70 checks, marked 16 prerequisite checks skipped, discovered 57 endpoints and 9 parameter names, and made 235 budgeted requests under the default per-check budget. C023 found and independently reproduced a SQLite error response on the discovered Juice Shop route `/rest/products/search?q=...`; the exact request returned the same database error during verification. The run produced one verified lab finding, four rejected candidates, and four inconclusive results. This is real evidence for one check on one intentionally vulnerable web application, not a claim that all checks or platforms are validated.

The real-traffic runner is `scripts/run_real_86_assessment.py`. It uses the production `RequestEngine`/`AiohttpTransport`, refuses non-loopback URLs, verifies a live Juice Shop identity response before scanning, captures redacted request/response evidence with raw-response SHA-256 values, reconciles coverage IDs against the loaded registry, and writes endpoint metadata plus a verified-only report and hashed artifact manifest. To repeat the local assessment:

```powershell
.venv\Scripts\python.exe scripts\run_real_86_assessment.py --target http://127.0.0.1:3001 --authorization-record "Operator-owned local Juice Shop deployment"
```

Recon is host-bounded in this runner. C023 currently consumes discovered endpoint parameters; most other checks still execute against the campaign root. Treat the endpoint count as discovery evidence, not proof that all endpoints were assessed. Authentication, browser, and multi-step workflow checks remain blocked when their prerequisites are not supplied.


