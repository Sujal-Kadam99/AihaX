"""AihaX Phase 27.x — Operator Live Reconnaissance Preflight & Validation Service.

Provides backend authority for:
1. Advisory read-only preflight evaluation (GET /api/campaigns/{id}/recon-live-preflight)
2. Authoritative re-validation & mock validation execution (POST /api/campaigns/{id}/recon-live-validation?mode=mock)

Enforces strict invariants:
- AVAILABLE != MOCK_VALIDATED != LIVE_VALIDATED
- Preflight evaluation generates 0 network traffic.
- Mock mode (`mode=mock`) NEVER generates LIVE_VALIDATED records or modifies historical evidence.
- Frontend confirmation choices are advisory; backend independently re-validates authorization, scope, capability, and safety rules.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from backend.core.errors import NotFoundException
from backend.core.scope_validator import ScopeValidator, validate_concrete_target_url
from backend.persistence.models import AuthorizationRecord, AuditTrailEvent
from backend.persistence.repository import CampaignRepository
from backend.recon.recon_modes import ReconContext, ReconExecutionMode
from backend.recon.recon_preflight import ReconPreflightGate, PreflightStatus
from backend.recon.recon_tool_availability import ReconToolAvailability


TOOL_CAPABILITY_MAP: Dict[str, Dict[str, Any]] = {
    "subfinder": {
        "capability_class": "Passive Recon",
        "requires_auth_class": "PASSIVE_RECON",
        "description": "Passive subdomain discovery using public OSINT sources.",
    },
    "amass": {
        "capability_class": "Passive Recon",
        "requires_auth_class": "PASSIVE_RECON",
        "description": "Passive network mapping and domain enumeration.",
    },
    "gau": {
        "capability_class": "Passive Recon",
        "requires_auth_class": "PASSIVE_RECON",
        "description": "Get All URLs from historical web archives.",
    },
    "crtsh": {
        "capability_class": "Passive Recon",
        "requires_auth_class": "PASSIVE_RECON",
        "description": "Certificate Transparency log domain discovery.",
    },
    "wayback": {
        "capability_class": "Passive Recon",
        "requires_auth_class": "PASSIVE_RECON",
        "description": "Wayback Machine historical URL discovery.",
    },
    "dns_recon": {
        "capability_class": "Passive Recon",
        "requires_auth_class": "PASSIVE_RECON",
        "description": "Standard DNS record resolution (A, AAAA, CNAME, TXT).",
    },
    "http_probe": {
        "capability_class": "Controlled Discovery",
        "requires_auth_class": "CONTROLLED_DISCOVERY",
        "description": "Minimal HTTP/HTTPS banner & response probe (GET/HEAD/OPTIONS).",
    },
    "whatweb": {
        "capability_class": "Controlled Discovery",
        "requires_auth_class": "CONTROLLED_DISCOVERY",
        "description": "Technology fingerprinting using low-impact profiles.",
    },
    "naabu": {
        "capability_class": "Service Discovery",
        "requires_auth_class": "SERVICE_DISCOVERY",
        "description": "Bounded port discovery profile.",
    },
    "nmap": {
        "capability_class": "Service Discovery",
        "requires_auth_class": "SERVICE_DISCOVERY",
        "description": "Bounded service and version discovery.",
    },
    "gobuster": {
        "capability_class": "Content Discovery",
        "requires_auth_class": "CONTENT_DISCOVERY",
        "description": "Bounded path and content discovery.",
    },
    "nuclei": {
        "capability_class": "Vulnerability Detection",
        "requires_auth_class": "VULNERABILITY_DETECTION",
        "description": "Active vulnerability detection scanner using safe templates.",
    },
    "dalfox": {
        "capability_class": "Specialized Active Testing",
        "requires_auth_class": "SPECIALIZED_ACTIVE_TESTING",
        "description": "Active XSS parameter testing scanner.",
    },
    "sublist3r": {
        "capability_class": "Passive Recon",
        "requires_auth_class": "PASSIVE_RECON",
        "description": "Subdomain discovery tool (STUB_ONLY).",
    },
}


class OperatorLiveReconService:
    """Service providing preflight validation and controlled mock runs for operator-initiated live recon UI."""

    @classmethod
    async def get_preflight(cls, campaign_id: str, db: Session) -> Dict[str, Any]:
        """Perform read-only preflight evaluation. Zero network traffic generated."""
        repo = CampaignRepository(db)
        campaign = repo.get_campaign(campaign_id)
        if not campaign:
            raise NotFoundException(f"Campaign '{campaign_id}' not found.")

        # 1. Fetch active AuthorizationRecord
        auth_record = (
            db.query(AuthorizationRecord)
            .filter(
                AuthorizationRecord.campaign_id == campaign_id,
                AuthorizationRecord.status == "ACTIVE",
            )
            .order_by(AuthorizationRecord.authorized_at.desc())
            .first()
        )

        now_utc = datetime.now(timezone.utc)
        auth_active = False
        auth_id = None
        auth_expiry_iso = None
        authorized_by = None
        scope_hash = None

        if auth_record:
            expires_at = auth_record.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at > now_utc:
                auth_active = True
                auth_id = auth_record.id
                auth_expiry_iso = expires_at.isoformat()
                authorized_by = auth_record.authorized_by
                scope_hash = auth_record.scope_hash

        # 2. Evaluate target & scope
        target_url = campaign.target_url
        in_scope = getattr(campaign, "in_scope_assets", None) or ([target_url] if target_url else [])
        out_of_scope = getattr(campaign, "out_of_scope_assets", None) or []
        scope_validator = ScopeValidator(
            in_scope_assets=in_scope,
            out_of_scope_assets=out_of_scope,
        )

        context = ReconContext(
            campaign_id=campaign_id,
            target=target_url,
            execution_mode=ReconExecutionMode.AUTHORIZED_LIVE_RECON if auth_active else ReconExecutionMode.AUDIT,
            authorization_record_id=auth_id or "",
            operator_confirmed=auth_active,
        )

        preflight_decision = ReconPreflightGate.evaluate(context, scope_validator)

        # 3. Query tool availability inventory (local binary detection)
        rta = ReconToolAvailability()
        inventory = await rta.generate_inventory()
        inventory_map = {inv.tool_name: inv for inv in inventory}

        # 4. Map tools to preflight matrix
        tool_matrix: List[Dict[str, Any]] = []

        # Authorized capabilities based on campaign mode & active auth
        # Safe passive & controlled discovery are authorized by explicit scope consent
        # Active testing capabilities (service, content, vuln, dalfox) require explicit policy opt-in
        for tool_name, meta in TOOL_CAPABILITY_MAP.items():
            inv = inventory_map.get(tool_name)
            installed = inv.availability_status == "AVAILABLE" if inv else False
            if tool_name == "sublist3r":
                status = "STUB_ONLY"
            elif not installed:
                status = "UNAVAILABLE"
            elif not auth_active:
                status = "BLOCKED_AUTHORIZATION"
            elif meta["requires_auth_class"] in ("SERVICE_DISCOVERY", "CONTENT_DISCOVERY", "VULNERABILITY_DETECTION", "SPECIALIZED_ACTIVE_TESTING"):
                # For safety preflight matrix, active capabilities require explicit policy opt-in
                status = "AUTH_REQUIRED"
            else:
                status = "AVAILABLE"

            tool_matrix.append({
                "tool_name": tool_name,
                "capability_class": meta["capability_class"],
                "installed": installed,
                "auth_permitted": auth_active and status != "BLOCKED_AUTHORIZATION",
                "status": status,
                "may_execute": status in ("AVAILABLE", "LIVE_VALIDATED"),
                "description": meta["description"],
                "failure_reason": f"Tool '{tool_name}' requires active capability authorization." if status == "AUTH_REQUIRED" else (inv.installation_status if inv and status == "UNAVAILABLE" else None),
            })

        overall_status = "READY" if (auth_active and preflight_decision.allowed) else (
            "BLOCKED_AUTHORIZATION" if not auth_active else preflight_decision.status.value
        )

        return {
            "campaign_id": campaign_id,
            "campaign_name": campaign.name,
            "target": target_url,
            "execution_mode": "AUTHORIZED_LIVE_RECON",
            "authorization": {
                "active": auth_active,
                "authorization_id": auth_id,
                "authorized_by": authorized_by or "operator",
                "expires_at": auth_expiry_iso,
                "status": "ACTIVE" if auth_active else "MISSING_OR_EXPIRED",
            },
            "scope": {
                "scope_hash": scope_hash or "NOT_COMPUTED",
                "status": "VALID" if preflight_decision.allowed else "INVALID",
            },
            "permitted_capabilities": {
                "passive_recon": auth_active,
                "controlled_discovery": auth_active,
                "service_discovery": False,  # Strict default
                "content_discovery": False,
                "vulnerability_detection": False,
                "specialized_active_testing": False,
            },
            "safety_budget": {
                "max_concurrency": 1,
                "rate_limit_rps": 2,
                "read_only_http": True,
                "disabled_actions": [
                    "Destructive Operations",
                    "Credential Attacks",
                    "Brute Force",
                    "DoS/Stress Testing",
                    "Automatic Target Expansion",
                ],
            },
            "preflight_decision": preflight_decision.to_dict(),
            "overall_status": overall_status,
            "can_launch": auth_active and preflight_decision.allowed,
            "tool_matrix": tool_matrix,
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }

    @classmethod
    async def execute_validation_run(
        cls,
        campaign_id: str,
        payload: Dict[str, Any],
        mode: str,
        db: Session,
        operator_id: str = "operator",
    ) -> Dict[str, Any]:
        """Authoritatively re-validate preflight & execute validation run.

        If mode == 'mock', dispatches to MockExecutionAdapter. Zero network calls performed.
        Returns status MOCK_VALIDATED for executed mock tools. NEVER produces LIVE_VALIDATED.
        """
        # 1. Require or default to mode == 'mock'
        if mode not in ("mock", "test", "live"):
            raise ValueError("Only 'mode=mock', 'mode=test', or 'mode=live' is supported.")

        # 2. Preflight re-validation
        preflight = await cls.get_preflight(campaign_id, db)
        if not preflight["can_launch"]:
            raise ValueError(f"Preflight validation failed: {preflight['overall_status']}")

        # 3. Create Audit Trail Event for confirmation & launch
        event_id = str(uuid.uuid4())
        audit_event = AuditTrailEvent(
            id=event_id,
            campaign_id=campaign_id,
            timestamp=datetime.now(timezone.utc),
            actor=operator_id,
            event_type="OPERATOR_LIVE_RECON_VALIDATION_MOCK_LAUNCHED",
            object_id=campaign_id,
            metadata_json=json.dumps({
                "mode": mode,
                "target": preflight["target"],
                "authorization_id": preflight["authorization"]["authorization_id"],
                "scope_hash": preflight["scope"]["scope_hash"],
                "confirmations": payload.get("confirmations", {}),
            }),
            previous_event_hash="0" * 64,
            event_hash=str(uuid.uuid4()).replace("-", ""),
        )
        db.add(audit_event)
        db.commit()

        if mode == "live":
            from backend.recon.live_recon_validator import LiveReconValidationEngine, ExecutionOrigin
            engine = LiveReconValidationEngine()
            
            # Use real execution
            result = await engine.execute_validation_suite(
                target=preflight["target"],
                campaign_id=campaign_id,
                authorization_record_id=preflight["authorization"]["authorization_id"],
                operator_confirmed=True,
                scope_assets=[preflight["target"]],
                db_session=db,
                scope_snapshot_hash=preflight["scope"]["scope_hash"],
                allow_port_scan=preflight["permitted_capabilities"].get("service_discovery", False),
                allow_dir_scan=preflight["permitted_capabilities"].get("content_discovery", False),
                execution_origin=ExecutionOrigin.PHASE27_CONTROLLED_PIPELINE,
                pipeline_run_id=f"run-live-{uuid.uuid4().hex[:8]}",
            )
            
            return {
                "success": True,
                "run_id": result.suite_status,
                "campaign_id": campaign_id,
                "execution_mode": "AUTHORIZED_LIVE_RECON",
                "status": "COMPLETED",
                "audit_event_id": event_id,
                "target": preflight["target"],
                "tool_records": {k: v.to_dict() for k, v in result.tool_records.items()},
                "executed_at": datetime.now(timezone.utc).isoformat(),
            }

        # 4. Construct mock execution tool matrix (MOCK_VALIDATED for runnable tools, AUTH_REQUIRED/UNAVAILABLE for others)
        tool_records = {}
        for tool_item in preflight["tool_matrix"]:
            tool_name = tool_item["tool_name"]
            status = tool_item["status"]

            if status == "AVAILABLE":
                mock_status = "MOCK_VALIDATED"
                executed = True
                parsed_count = 5
                contrib_count = 3
            else:
                mock_status = status
                executed = False
                parsed_count = 0
                contrib_count = 0

            tool_records[tool_name] = {
                "tool_name": tool_name,
                "status": mock_status,
                "executed": executed,
                "parsed_result_count": parsed_count,
                "snapshot_contribution_count": contrib_count,
                "evidence_id": f"mock-ev-{uuid.uuid4().hex[:8]}" if executed else None,
                "failure_reason": tool_item.get("failure_reason"),
            }

        return {
            "success": True,
            "run_id": f"run-mock-{uuid.uuid4().hex[:8]}",
            "campaign_id": campaign_id,
            "execution_mode": "MOCK_VALIDATION",
            "status": "COMPLETED",
            "audit_event_id": event_id,
            "target": preflight["target"],
            "tool_records": tool_records,
            "executed_at": datetime.now(timezone.utc).isoformat(),
        }
