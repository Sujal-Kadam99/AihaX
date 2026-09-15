# False-Positive Defense & Response Differential Analysis

## 1. Overview

A critical flaw in legacy web security scanners is reporting generic application anomalies (such as uncaught exceptions, HTML-encoded reflection, or soft-404 status codes) as security vulnerabilities.

AihaX enforces rigorous **Response Differential Analysis** (`backend/execution/differential.py`) and multi-layer false-positive rejection rules.

---

## 2. False-Positive Defense Rules

### 2.1 Generic 500 Error Rejection (Anti-SQLi Hallucination)
- **Problem**: Applications often return `500 Internal Server Error` when receiving unexpected punctuation (`'`, `"`) due to standard unhandled type conversion or input validation exceptions.
- **Defense Rule**: A status change from `200` to `500` is **rejected** unless the response body contains verified, vendor-specific database syntax error signatures (e.g., `you have an error in your sql syntax`, `pg_query() error`, `sqlite3.operationalerror`, `ora-00933`).
- **Implementation**:
  ```python
  if mutated_status >= 500 and not has_db_syntax_error:
      diff.generic_500_detected = True
      diff.is_candidate = False  # REJECT FALSE POSITIVE
  ```

### 2.2 HTML Encoded Reflection Defense (Anti-XSS False Positive)
- **Problem**: Scanners find the reflected string in HTML and flag XSS even when the application correctly applied `html.escape()` or templating auto-escaping.
- **Defense Rule**:
  - If `<canary>` appears unencoded (`<aihax_refl...>`) $\rightarrow$ Classified as `ReflectionContext.RAW_HTML` (True Vulnerability Candidate).
  - If `<canary>` appears entity-encoded (`&lt;aihax_refl...&gt;`) $\rightarrow$ Classified as `ReflectionContext.HTML_ENCODED` (Candidate = `False`).

### 2.3 Paired Negative Control Cancellation
- **Problem**: Static application pages or echo services return identical text regardless of input expressions.
- **Defense Rule**: When testing arithmetic or SSTI expressions (`$((1000*20))`), the engine simultaneously issues a negative control probe with a static literal. If the control probe produces the target signal without evaluating the arithmetic, the candidate is automatically cancelled.

### 2.4 Soft-404 Suppression
- **Problem**: Single-page applications (SPAs) return `200 OK` with a "Page Not Found" template for all URLs, misleading sensitive file exposure checks.
- **Defense Rule**: Structural fingerprinting and title analysis detect soft-404 templates and discard non-existent file exposure candidates.
