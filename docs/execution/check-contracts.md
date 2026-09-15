# Enhanced Check Contracts & Prerequisite Validation

## 1. Overview

In Phase 5, all 77 checks (C001–C077) are governed by extended declarative `CheckContract` specifications in `backend/core/check_registry.py`. The contract explicitly specifies what capabilities, methods, parameters, authentication contexts, browser runtimes, and request budgets are required before execution.

---

## 2. CheckContract Schema Extension

```python
@dataclass
class CheckContract:
    id: str
    name: str
    category: CheckCategory
    description: str
    severity: Severity
    vulnerability_type: str = "General"
    cwe: Optional[str] = None
    owasp_category: Optional[str] = None
    security_property: Optional[str] = None
    remediation_guidance: Optional[str] = None
    references: list[str] = field(default_factory=list)
    verification_strategy: str = "http_response_property"
    required_evidence: list[str] = field(default_factory=list)
    destructive: bool = False
    
    # Phase 5 Execution Matrix Fields:
    required_capabilities: list[str] = field(default_factory=lambda: ["http"])
    supported_methods: list[str] = field(default_factory=lambda: ["GET"])
    requires_parameters: bool = False
    requires_auth: bool = False
    requires_browser: bool = False
    requires_workflow: bool = False
    max_requests: int = 10
    target_surface: str = "ENDPOINT"
    false_positive_risks: list[str] = field(default_factory=list)
```

---

## 3. Prerequisite Evaluation Matrix

The `ExecutionContext` evaluates each check's prerequisites against the target asset and environment:

```
                  ┌───────────────────────────────┐
                  │ Check Contract & Target Asset │
                  └───────────────┬───────────────┘
                                  │
                       [Target In Scope?]
                                 ├── NO ──> PrerequisiteStatus.MISSING_SCOPE (0 network bytes)
                                 └── YES
                                  │
                   [Asset Capabilities Matched?]
                                 ├── NO ──> PrerequisiteStatus.MISSING_CAPABILITY
                                 └── YES
                                  │
                     [Parameters Required?]
                                 ├── YES & None ──> PrerequisiteStatus.MISSING_PARAMETER
                                 └── SATISFIED
                                  │
                      [Authentication Required?]
                                 ├── YES & None ──> PrerequisiteStatus.MISSING_AUTH
                                 └── SATISFIED
                                  │
                        [Browser Required?]
                                 ├── YES & None ──> PrerequisiteStatus.MISSING_BROWSER
                                 └── SATISFIED
                                  │
                        [Budget Available?]
                                 ├── NO ──> PrerequisiteStatus.BUDGET_EXHAUSTED
                                 └── YES
                                  │
                                  ▼
                   PrerequisiteStatus.SATISFIED
```

---

## 4. Contract Validation Guarantee

All 77 check contracts in AihaX are verified by unit test `test_all_77_contracts_valid_and_non_destructive`:
- `validate_contract()` returns `True` for all 77 checks.
- `destructive` is strictly `False` for all 77 checks.
- `max_requests` is bounded ($1 \le \text{max\_requests} \le 50$).
