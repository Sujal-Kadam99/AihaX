"""Agent 4 — Deterministic Evidence-Based Verification Engine."""

import logging
from typing import Any, Optional

from backend.agents.base_agent import BaseAgent
from backend.core.scope_validator import ScopeValidator
from backend.evidence.evidence_store import EvidenceVault
from backend.models.database import Finding, Scan
from backend.persistence.repository import CampaignRepository
from backend.services.request_engine import AuthenticationContext, RequestEngine
from backend.services.verification_engine import (
    VerificationConclusion,
    VerificationEngine,
    VerificationStatus,
)

logger = logging.getLogger("aihax.verify_agent")


class VerifyAgent(BaseAgent):
    agent_id = 4

    async def execute(self) -> dict[str, Any]:
        findings = (
            self.db.query(Finding)
            .filter(
                Finding.scan_id == self.scan_id,
                Finding.false_positive.is_(False),
                Finding.verification_status.in_(("CANDIDATE", "DETECTED", "VALIDATED", "EXPLOITABLE")),
            )
            .all()
        )

        verified = 0
        potential = 0
        inconclusive = 0
        rejected = 0
        total = len(findings)

        # Build ScopeValidator and RequestEngine for verification
        target_url = self.config.get("target_url", "")
        rate_rps = self.config.get("rate_limit_rps", 10)
        max_concurrency = self.config.get("max_concurrency", 5)
        in_scope = self.config.get("in_scope_assets", [target_url] if target_url else [])
        out_of_scope = self.config.get("out_of_scope_assets", [])

        validator = ScopeValidator(
            in_scope_assets=in_scope,
            out_of_scope_assets=out_of_scope,
        )
        request_engine = RequestEngine(
            scope_validator=validator,
            rate_limit_rps=rate_rps,
            max_concurrency=max_concurrency,
        )
        engine = VerificationEngine()
        auth_confirmed = bool(self.config.get("authorization_confirmed", True))
        auth_context = self._extract_auth_context()
        repo = CampaignRepository(self.db)
        evidence_vault = EvidenceVault(repo) if repo.get_campaign(self.scan_id) else None

        for i, finding in enumerate(findings):
            await self.check_cancelled()
            progress = int((i / max(total, 1)) * 100)
            await self.publish_update(
                "running", progress,
                f"Verifying: {finding.title}...",
            )

            conclusion = await engine.verify_finding(
                finding=finding,
                request_engine=request_engine,
                auth_context=auth_context,
                authorization_confirmed=auth_confirmed,
                evidence_vault=evidence_vault,
            )

            if conclusion.status == VerificationStatus.VERIFIED:
                verified += 1
            elif conclusion.status == VerificationStatus.INCONCLUSIVE:
                inconclusive += 1
            elif conclusion.status == VerificationStatus.CANDIDATE:
                potential += 1
            else:
                rejected += 1

            self.db.commit()

        scan = self.db.query(Scan).filter_by(id=self.scan_id).first()
        if scan:
            scan.total_findings = verified
            self.db.commit()

        return {
            "verified": verified,
            "potential": potential,
            "inconclusive": inconclusive,
            "rejected": rejected,
        }

    def _extract_auth_context(self) -> Optional[AuthenticationContext]:
        import json as _json
        from backend.models.database import AuthContextRecord
        cookies: dict[str, str] = {}
        try:
            records = self.db.query(AuthContextRecord).filter_by(campaign_id=self.scan_id).all()
            for rec in records:
                if rec.metadata_json:
                    meta = _json.loads(rec.metadata_json)
                    rec_cookies = meta.get("cookies", {})
                    if isinstance(rec_cookies, dict):
                        cookies.update({str(k): str(v) for k, v in rec_cookies.items()})
        except Exception as e:
            logger.warning(f"Could not load auth cookies from DB: {e}")
        if not cookies:
            return None
        return AuthenticationContext(
            name="shared_authenticated_session",
            auth_type="session_cookie",
            cookies=cookies,
            headers={},
        )

    async def _run_verification_pipeline(self, finding: Finding) -> VerificationConclusion:
        """Legacy helper bridge for backward compatibility with unit tests."""
        target_url = finding.affected_url or "https://example.com"
        validator = ScopeValidator(in_scope_assets=[target_url])
        request_engine = RequestEngine(scope_validator=validator)
        engine = VerificationEngine()
        auth_context = self._extract_auth_context()
        repo = CampaignRepository(self.db)
        return await engine.verify_finding(
            finding=finding,
            request_engine=request_engine,
            auth_context=auth_context,
            authorization_confirmed=True,
            evidence_vault=EvidenceVault(repo) if repo.get_campaign(self.scan_id) else None,
        )
