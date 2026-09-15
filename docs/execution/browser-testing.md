# Browser Automation & Client-Side DOM Testing

## 1. Overview

Client-side vulnerability checks (such as C039 DOM-based XSS, C048 Tabnabbing / Target Blank, C049 Clickjacking / Missing Frame Options, and C066 LocalStorage Sensitive Token Storage) operate on rendered DOM trees and client-side JavaScript runtimes.

---

## 2. Browser Capability Prerequisite Enforcement

When executing browser-dependent checks:
- **`requires_browser = True` Contract**: Declares that raw HTTP response parsing alone is insufficient to evaluate DOM sinks and client-side storage.
- **`ExecutionContext` Validation**: If no headless browser runtime is available or configured, `ExecutionContext.evaluate_prerequisites()` returns `PrerequisiteStatus.MISSING_BROWSER`. The check is gracefully skipped rather than failing with runtime socket errors.

---

## 3. Client-Side Check Execution Patterns

### 3.1 DOM XSS Sink Execution (C039)
- **Source**: `location.search`, `location.hash`, `document.referrer`, `window.name`.
- **Sink**: `innerHTML`, `document.write`, `eval()`, `setTimeout()`.
- **Methodology**: Injects unique high-entropy canaries into URL fragments (`#<aihax_canary>`) and inspects the live JavaScript DOM tree for unescaped node insertion.

### 3.2 Clickjacking Frame Defense (C049)
- **Evaluation**: Evaluates presence and validity of `X-Frame-Options: DENY|SAMEORIGIN` and `Content-Security-Policy: frame-ancestors ...`.
- **Negative Control**: Pages enforcing `frame-ancestors 'none'` or `X-Frame-Options: DENY` are verified as secure.

### 3.3 Web Storage Exposure (C066)
- **Evaluation**: Queries `localStorage` and `sessionStorage` keys for unencrypted session tokens, bearer tokens, or API credentials stored in client script scope.
