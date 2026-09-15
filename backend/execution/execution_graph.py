"""AihaX Inspectable Execution Graph & Attack-Surface Planner."""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.core.check_registry import CheckContract
from backend.execution.parameter_model import DiscoveredParameter
from backend.recon.models import AssetCapabilities, DiscoveredAsset, DiscoveredEndpoint
from backend.services.campaign_executor import CampaignRequestBudget
from backend.services.request_engine import AuthenticationContext, ScopeValidator

logger = logging.getLogger("backend.execution.execution_graph")


@dataclass
class ExecutionGraphNode:
    """Represents a planned testing node for a specific endpoint and its parameters."""

    node_id: str
    endpoint_url: str
    method: str
    parameters: list[DiscoveredParameter]
    eligible_checks: list[dict[str, Any]]
    skipped_checks: list[dict[str, Any]]
    estimated_requests: int
    auth_context_name: Optional[str] = None


@dataclass
class ExecutionGraph:
    """Complete inspectable attack-surface execution plan for a campaign."""

    campaign_id: str
    target_root: str
    nodes: list[ExecutionGraphNode] = field(default_factory=list)
    total_assets: int = 0
    total_endpoints: int = 0
    total_parameters: int = 0
    total_eligible_checks: int = 0
    total_estimated_requests: int = 0
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "target_root": self.target_root,
            "total_assets": self.total_assets,
            "total_endpoints": self.total_endpoints,
            "total_parameters": self.total_parameters,
            "total_eligible_checks": self.total_eligible_checks,
            "total_estimated_requests": self.total_estimated_requests,
            "nodes": [
                {
                    "node_id": n.node_id,
                    "endpoint_url": n.endpoint_url,
                    "method": n.method,
                    "parameters": [p.to_dict() for p in n.parameters],
                    "eligible_checks": n.eligible_checks,
                    "skipped_checks": n.skipped_checks,
                    "estimated_requests": n.estimated_requests,
                    "auth_context_name": n.auth_context_name,
                }
                for n in self.nodes
            ],
            "generated_at": self.generated_at,
        }

    @classmethod
    def build_graph(
        cls,
        campaign_id: str,
        target_root: str,
        assets: list[DiscoveredAsset],
        endpoints: list[DiscoveredEndpoint],
        endpoint_parameters: dict[str, list[DiscoveredParameter]],
        capabilities: AssetCapabilities,
        all_contracts: list[CheckContract],
        scope_validator: ScopeValidator,
        budget: CampaignRequestBudget,
        auth_context: Optional[AuthenticationContext] = None,
    ) -> ExecutionGraph:
        """Construct the attack surface execution graph mapping endpoints and parameters to eligible checks."""
        graph = cls(campaign_id=campaign_id, target_root=target_root)
        graph.total_assets = len(assets)
        graph.total_endpoints = len(endpoints)

        total_params = 0
        total_eligible = 0
        total_reqs = 0

        for ep in endpoints:
            params = endpoint_parameters.get(ep.endpoint_id, [])
            total_params += len(params)

            eligible: list[dict[str, Any]] = []
            skipped: list[dict[str, Any]] = []
            ep_reqs = 1  # 1 baseline request

            for contract in all_contracts:
                # Evaluate preconditions
                scope_res = scope_validator.validate_target(ep.url)
                if not scope_res.allowed:
                    skipped.append({"check_id": contract.id, "reason": f"Out of scope: {scope_res.reason}"})
                    continue

                if ep.method.upper() not in contract.supported_methods:
                    skipped.append({"check_id": contract.id, "reason": f"Method {ep.method} not supported by check."})
                    continue

                if contract.requires_parameters and not params:
                    skipped.append({"check_id": contract.id, "reason": "Check requires parameters, but none discovered."})
                    continue

                if contract.requires_auth and not auth_context:
                    skipped.append({"check_id": contract.id, "reason": "Check requires authenticated context."})
                    continue

                if "graphql" in contract.required_capabilities and not (ep.is_graphql or capabilities.graphql):
                    skipped.append({"check_id": contract.id, "reason": "Target lacks GraphQL capability."})
                    continue

                if "file_upload" in contract.required_capabilities and not (ep.is_upload or capabilities.file_upload):
                    skipped.append({"check_id": contract.id, "reason": "Target lacks file upload capability."})
                    continue

                # If passed, add to eligible
                multiplier = len(params) if (contract.requires_parameters and params) else 1
                check_cost = min(contract.max_requests, multiplier * 3)
                ep_reqs += check_cost

                eligible.append({
                    "check_id": contract.id,
                    "name": contract.name,
                    "category": contract.category.value,
                    "severity": contract.severity.value,
                    "target_surface": contract.target_surface,
                    "max_requests": check_cost,
                    "parameters_targeted": [p.name for p in params] if contract.requires_parameters else [],
                })
                total_eligible += 1

            total_reqs += ep_reqs

            graph.nodes.append(
                ExecutionGraphNode(
                    node_id=f"node-{ep.endpoint_id}",
                    endpoint_url=ep.url,
                    method=ep.method,
                    parameters=params,
                    eligible_checks=eligible,
                    skipped_checks=skipped,
                    estimated_requests=ep_reqs,
                    auth_context_name=auth_context.name if auth_context else None,
                )
            )

        graph.total_parameters = total_params
        graph.total_eligible_checks = total_eligible
        graph.total_estimated_requests = total_reqs

        return graph
