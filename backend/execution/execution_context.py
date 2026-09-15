"""AihaX Execution Context & Prerequisite Enforcement."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from backend.core.check_registry import CheckContract
from backend.execution.parameter_model import DiscoveredParameter
from backend.recon.models import AssetCapabilities, DiscoveredAsset, DiscoveredEndpoint
from backend.services.campaign_executor import CampaignRequestBudget
from backend.services.request_engine import AuthenticationContext, ScopeValidator

logger = logging.getLogger("backend.execution.execution_context")


class ExecutionPhase(str, Enum):
    PLANNING = "PLANNING"
    BASELINE = "BASELINE"
    MUTATION = "MUTATION"
    CONTROL = "CONTROL"
    VERIFICATION = "VERIFICATION"
    COMPLETED = "COMPLETED"


class PrerequisiteStatus(str, Enum):
    SATISFIED = "SATISFIED"
    MISSING_SCOPE = "MISSING_SCOPE"
    MISSING_PARAMETER = "MISSING_PARAMETER"
    MISSING_AUTH = "MISSING_AUTH"
    MISSING_BROWSER = "MISSING_BROWSER"
    MISSING_WORKFLOW = "MISSING_WORKFLOW"
    MISSING_CAPABILITY = "MISSING_CAPABILITY"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    KILL_SWITCH_ACTIVE = "KILL_SWITCH_ACTIVE"


@dataclass
class ExecutionContext:
    """Manages runtime state, prerequisite enforcement, and budget accounting for active security testing."""

    campaign_id: str
    asset: DiscoveredAsset
    endpoint: DiscoveredEndpoint
    parameter: Optional[DiscoveredParameter]
    contract: CheckContract
    capabilities: AssetCapabilities
    scope_validator: ScopeValidator
    budget: CampaignRequestBudget
    auth_context: Optional[AuthenticationContext] = None
    has_browser_capability: bool = False
    has_workflow_capability: bool = False
    kill_switch_active: bool = False
    current_phase: ExecutionPhase = ExecutionPhase.PLANNING
    requests_used: int = 0
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def evaluate_prerequisites(self) -> tuple[PrerequisiteStatus, str]:
        """Check if all execution prerequisites are satisfied before sending any network request."""
        # 1. Kill Switch
        if self.kill_switch_active:
            return PrerequisiteStatus.KILL_SWITCH_ACTIVE, "Global kill switch is active."

        # 2. Scope Validation
        scope_res = self.scope_validator.validate_target(self.endpoint.url)
        if not scope_res.allowed:
            return PrerequisiteStatus.MISSING_SCOPE, f"Target {self.endpoint.url} is out of scope: {scope_res.reason}"

        # 3. Budget Check
        if self.budget.is_exhausted(self.endpoint.url, self.contract.id):
            return PrerequisiteStatus.BUDGET_EXHAUSTED, f"Budget exhausted for check {self.contract.id} on {self.endpoint.url}."

        # 4. Parameter Requirements
        if self.contract.requires_parameters and not self.parameter:
            return PrerequisiteStatus.MISSING_PARAMETER, f"Check {self.contract.id} requires parameters, but no parameter was discovered."

        # 5. Authentication Requirements
        if self.contract.requires_auth and not self.auth_context:
            return PrerequisiteStatus.MISSING_AUTH, f"Check {self.contract.id} requires authenticated context, but none was provided."

        # 6. Browser Requirements
        if self.contract.requires_browser and not self.has_browser_capability:
            return PrerequisiteStatus.MISSING_BROWSER, f"Check {self.contract.id} requires browser capability, but current context is HTTP-only."

        # 7. Workflow Requirements
        if self.contract.requires_workflow and not self.has_workflow_capability:
            return PrerequisiteStatus.MISSING_WORKFLOW, f"Check {self.contract.id} requires multi-step workflow capability."

        # 8. Required Capabilities
        if "graphql" in self.contract.required_capabilities and not self.capabilities.graphql:
            return PrerequisiteStatus.MISSING_CAPABILITY, f"Check {self.contract.id} requires GraphQL capability."
        if "file_upload" in self.contract.required_capabilities and not self.capabilities.file_upload:
            return PrerequisiteStatus.MISSING_CAPABILITY, f"Check {self.contract.id} requires file upload capability."

        return PrerequisiteStatus.SATISFIED, "All prerequisites satisfied."
