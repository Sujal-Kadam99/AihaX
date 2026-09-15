"""Check Registry Architecture for AihaX — Modernized BaseCheck & Metadata Contract."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Type, Union

from pydantic import BaseModel, Field


class CheckCategory(str, Enum):
    RECON = "recon"
    AUTH = "auth"
    INJECTION = "injection"
    XSS = "xss"
    MISCONFIG = "misconfig"
    MISCONFIGURATION = "misconfig"
    SENSITIVE_DATA = "sensitive_data"
    BUSINESS_LOGIC = "business_logic"
    INPUT_VALIDATION = "input_validation"
    INFRASTRUCTURE = "infrastructure"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CheckRiskLevel(str, Enum):
    PASSIVE = "PASSIVE"
    SAFE_ACTIVE = "SAFE_ACTIVE"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    PROHIBITED = "PROHIBITED"


class CheckContract(BaseModel):
    """Standardized metadata and execution contract for a security check."""
    id: str = Field(..., description="Unique check ID, e.g. C001_Open_Port_80")
    name: str = Field(..., description="Human readable name")
    category: CheckCategory
    description: str
    severity: Severity
    vulnerability_type: str = Field(default="Security Finding", description="Canonical vulnerability type")
    cwe: Optional[str] = Field(None, description="CWE identifier, e.g. CWE-16")
    owasp_category: Optional[str] = Field(None, description="OWASP Top 10 category, e.g. A05:2021-Security Misconfiguration")
    security_property: Optional[str] = Field(None, description="Formal security property being tested")
    remediation_guidance: Optional[str] = Field(None, description="Default generic remediation guidance")
    references: List[str] = Field(default_factory=list, description="Trusted references like OWASP, CWE, or CVE links")
    verification_strategy: Optional[str] = Field(None, description="Verification strategy used to deterministically verify candidate finding")
    required_evidence: List[str] = Field(default_factory=list, description="List of required evidence fields")
    evidence_required: List[str] = Field(default_factory=list, description="Explicit list of required evidence fields")
    destructive: bool = Field(default=False, description="Whether check performs destructive actions (must be False)")

    # Phase 19 Risk Classification & Production Policy
    risk_level: CheckRiskLevel = Field(default=CheckRiskLevel.SAFE_ACTIVE, description="Risk classification: PASSIVE, SAFE_ACTIVE, REVIEW_REQUIRED, PROHIBITED")
    production_allowed: bool = Field(default=True, description="Whether check is allowed in production execution mode")
    estimated_requests: int = Field(default=1, ge=1, description="Estimated number of requests executed by this check")
    authentication_required: bool = Field(default=False, description="Whether check requires authenticated credentials")
    method: str = Field(default="GET", description="Primary HTTP method used by check")

    # Phase 5 Execution Prerequisites & Capabilities
    required_capabilities: set[str] = Field(default_factory=lambda: {"http"}, description="Required asset capabilities (http, https, api, graphql, authentication, file_upload, browser_required, workflow_required)")
    supported_methods: set[str] = Field(default_factory=lambda: {"GET", "POST"}, description="Supported HTTP methods for this check")
    requires_parameters: bool = Field(default=False, description="Whether check requires testable input parameters")
    requires_auth: bool = Field(default=False, description="Whether check requires authenticated session context")
    requires_browser: bool = Field(default=False, description="Whether check requires headless browser evaluation")
    requires_workflow: bool = Field(default=False, description="Whether check requires multi-step workflow context")
    max_requests: int = Field(default=10, ge=1, description="Maximum requests budgeted for single execution of this check")
    target_surface: str = Field(default="web", description="Target surface: web, api, graphql, headers, cookies, upload, workflow")
    false_positive_risks: List[str] = Field(default_factory=list, description="Known false-positive risk factors to guard against")

    @property
    def check_id(self) -> str:
        return self.id

    def is_production_allowed(self) -> bool:
        """Check if check is permitted in production profile."""
        if not self.production_allowed:
            return False
        if self.destructive:
            return False
        if self.risk_level not in (CheckRiskLevel.PASSIVE, CheckRiskLevel.SAFE_ACTIVE):
            return False
        return True

    def validate_contract(self) -> bool:
        """Validate that execution contract parameters are coherent and safe."""
        if not self.id or not self.name or not self.description:
            raise ValueError(f"Check {self.id} is missing essential descriptive metadata.")
        if self.destructive:
            raise ValueError(f"Check {self.id} is marked destructive=True. All production checks must be non-destructive.")
        if self.risk_level == CheckRiskLevel.PROHIBITED and self.production_allowed:
            raise ValueError(f"Check {self.id} is marked PROHIBITED but production_allowed=True.")
        if self.max_requests < 1:
            raise ValueError(f"Check {self.id} has invalid max_requests={self.max_requests} (must be >= 1).")
        valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
        for method in self.supported_methods:
            if method.upper() not in valid_methods:
                raise ValueError(f"Check {self.id} specifies unsupported HTTP method: {method}")
        return True


class CheckResult(BaseModel):
    """Standardized output of a security check producing a CANDIDATE finding."""
    finding_id: Optional[str] = None
    check_id: str
    title: str
    target: str
    vulnerability_type: str
    severity: Severity
    candidate_reason: str
    evidence_ids: List[str] = Field(default_factory=list)
    request_ids: List[str] = Field(default_factory=list)
    observed_data: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    verification_status: str = "CANDIDATE"
    affected_url: str
    affected_param: Optional[str] = None
    payload: Optional[str] = None
    proof_request: Optional[str] = None
    proof_response: Optional[str] = None
    screenshot_path: Optional[str] = None
    confidence: int = Field(default=50, ge=0, le=100)


class EvidenceContract(CheckResult):
    """Backwards-compatible alias/subclass for legacy EvidenceContract references."""
    check_id: str = "GENERIC_CHECK"
    title: str = "Candidate Security Finding"
    target: str = ""
    vulnerability_type: str = "Candidate Finding"
    severity: Severity = Severity.INFO
    candidate_reason: str = "Candidate condition observed during security check."
    affected_url: str = ""

    def __init__(self, **data: Any) -> None:
        if "affected_url" in data and not data.get("target"):
            data["target"] = data["affected_url"]
        super().__init__(**data)


class BaseCheck:
    """Base class for all deterministic security checks."""
    contract: CheckContract

    async def execute(
        self,
        request_engine: Any,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        """Execute check using RequestEngine and return CheckResult candidate finding if observed."""
        raise NotImplementedError("Check subclass must implement execute()")


class CheckRegistry:
    """Registry to manage and validate available security checks."""

    def __init__(self) -> None:
        self._checks: Dict[str, Type[BaseCheck]] = {}

    def register(self, check_class: Type[BaseCheck]) -> None:
        contract = getattr(check_class, "contract", None)
        if not isinstance(contract, CheckContract):
            raise TypeError(f"Invalid contract for check {check_class.__name__}")
        if contract.id in self._checks:
            raise ValueError(f"Check {contract.id} is already registered.")
        self._checks[contract.id] = check_class

    def get_check(self, check_id: str) -> Type[BaseCheck]:
        if check_id in self._checks:
            return self._checks[check_id]
        # Case-insensitive lookup
        for k, v in self._checks.items():
            if k.lower() == check_id.lower():
                return v
        # Prefix / Canonical ID lookup (e.g. C001 matches C001_...)
        for k, v in self._checks.items():
            if k.split("_")[0].upper() == check_id.split("_")[0].upper():
                return v
        raise KeyError(f"Check {check_id} not found in registry.")

    def list_checks(self) -> List[CheckContract]:
        return [check.contract for check in self._checks.values()]

    def get_all_checks(self) -> List[Type[BaseCheck]]:
        return list(self._checks.values())

    def get_checks_by_category(self, category: CheckCategory) -> List[Type[BaseCheck]]:
        return [c for c in self._checks.values() if c.contract.category == category]

    def get_registry_metadata(self) -> Dict[str, Any]:
        """Compute deterministic registry versioning, check list, contract hash, and registry hash."""
        import hashlib
        import json
        contracts = sorted([check.contract for check in self._checks.values()], key=lambda c: c.id)
        contract_data = [
            {
                "id": c.id,
                "name": c.name,
                "category": c.category.value if hasattr(c.category, "value") else str(c.category),
                "severity": c.severity.value if hasattr(c.severity, "value") else str(c.severity),
                "cwe": c.cwe,
                "owasp_category": c.owasp_category,
                "destructive": c.destructive,
                "required_capabilities": sorted(list(c.required_capabilities)),
                "supported_methods": sorted(list(c.supported_methods)),
            }
            for c in contracts
        ]
        serialized = json.dumps(contract_data, sort_keys=True, separators=(",", ":"))
        contract_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        check_ids = [c.id for c in contracts]
        raw_reg = f"v1.0.0|{len(check_ids)}|{','.join(check_ids)}|{contract_hash}"
        registry_hash = hashlib.sha256(raw_reg.encode("utf-8")).hexdigest()
        return {
            "registry_version": "1.0.0",
            "registry_hash": registry_hash,
            "contract_hash": contract_hash,
            "check_count": len(check_ids),
            "check_ids": check_ids,
        }

    def clear(self) -> None:
        """Clear registry (useful for testing)."""
        self._checks.clear()


# Global registry instance
registry = CheckRegistry()

