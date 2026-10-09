"""Single authorized reconnaissance entry point for campaign workers."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict

from sqlalchemy.orm import Session

from backend.persistence.repository import CampaignRepository
from backend.services.operator_live_recon_service import OperatorLiveReconService


class CampaignReconService:
    """Revalidate campaign authorization and run the canonical live recon suite."""

    @classmethod
    async def execute(cls, campaign_id: str, db: Session) -> Dict[str, Any]:
        repo = CampaignRepository(db)
        campaign = repo.get_campaign(campaign_id)
        run = repo.get_recon_run(campaign_id)
        authorization = repo.get_authorization(campaign_id)
        if not campaign or not run:
            raise ValueError("Campaign or queued recon run no longer exists.")
        if campaign.status != "RUNNING":
            raise ValueError(f"Campaign is {campaign.status}; recon cannot run.")
        if not authorization or authorization.status != "ACTIVE":
            raise ValueError("Active campaign authorization is required before recon traffic.")
        if authorization.id != run.authorization_id:
            raise ValueError("Campaign authorization changed after recon was queued; refusing to run.")
        if authorization.scope_hash != run.scope_hash:
            raise ValueError("Authorized scope changed after recon was queued; refusing to run.")
        if authorization.expires_at:
            expires_at = authorization.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at <= datetime.now(timezone.utc):
                raise ValueError("Campaign authorization expired before recon started.")

        capabilities = json.loads(run.selected_capabilities_json or "[]")
        payload = {
            "selected_capabilities": capabilities,
            "port_scan_profile": "web_common",
            # Campaign start requires and records a written authorization reference.
            # These attestations carry that explicit approval into the worker path.
            "confirmations": {
                "authActive": True,
                "targetCorrect": True,
                "capabilitiesReviewed": True,
                "liveTrafficAcknowledged": True,
            },
        }
        result = await OperatorLiveReconService.execute_validation_run(
            campaign_id=campaign_id,
            payload=payload,
            mode="live",
            db=db,
            operator_id="campaign_worker",
        )
        if not result.get("success"):
            raise RuntimeError(result.get("failure_reason") or "Recon pipeline did not complete successfully.")
        if result.get("run_id") != "VALIDATION_COMPLETE":
            raise RuntimeError(f"Recon safety gate returned {result.get('run_id')}; dependent checks are blocked.")
        return result
