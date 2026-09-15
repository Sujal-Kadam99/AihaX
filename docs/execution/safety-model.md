# AihaX — Production Safety Model & Operational Invariants

## Operational Safety Principles

AihaX enforces strict safety boundaries across all 77 checks to ensure zero unintended disruption against target systems.

---

## 1. Safe Mode Enforcement (`SAFE_MODE = True`)

Production execution operates with `SAFE_MODE = True` by default:

1. **Non-Destructive Payloads**: All injection checks use benign mathematical canaries (`expr 31330 + 7 -> 31337`, `{{31330+7}} -> 31337`). Destructive commands (`rm`, `drop`, `truncate`, `kill`) are prohibited.
2. **Safe Multipart Uploads**: Executable extension tests upload harmless text files containing `Audit verification token` without executable web shell code.
3. **Safe SSRF Probing**: Checks test exclusively against in-scope target resources (such as `/robots.txt`). Zero requests are sent to cloud metadata services (`169.254.169.254`), `localhost`, or RFC1918 private subnets.

---

## 2. Default-Deny Scope Invariant

- Every URL and redirect target is evaluated by `ScopeValidator` before any network socket is opened.
- Precedence: `EXPLICIT EXCLUSION > EXPLICIT INCLUSION > WILDCARD INCLUSION > DEFAULT DENY`.
- Out-of-scope requests produce **0 network bytes**.

---

## 3. Secret & Credential Redaction

- Passwords, Bearer tokens, and session cookie secrets are automatically redacted in `RequestEngine` (`redact_headers` and `redact_url`).
- Cookie security attributes (`Secure`, `HttpOnly`, `SameSite`, `Domain`, `Path`) are preserved for auditing without exposing sensitive token secrets.
- Audit logs and reports are strictly scrubbed of credentials.
