"""Agent 4 — Deterministic Evidence-Based Verification Engine."""

from typing import Any, Optional

from backend.agents.base_agent import BaseAgent
from backend.core.scope_validator import ScopeValidator
from backend.models.database import Finding, Scan
from backend.services.request_engine import AuthenticationContext, RequestEngine
from backend.services.verification_engine import (
    VerificationConclusion,
    VerificationEngine,
    VerificationStatus,
)


class VerifyAgent(BaseAgent):
    agent_id = 4

    async def execute(self) -> dict[str, Any]:
        findings = (
            self.db.query(Finding)
            .filter_by(scan_id=self.scan_id, false_positive=False)
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
                authorization_confirmed=auth_confirmed,
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

    async def _run_verification_pipeline(self, finding: Finding) -> VerificationConclusion:
        """Legacy helper bridge for backward compatibility with unit tests."""
        target_url = finding.affected_url or "https://example.com"
        validator = ScopeValidator(in_scope_assets=[target_url])
        request_engine = RequestEngine(scope_validator=validator)
        engine = VerificationEngine()
        return await engine.verify_finding(
            finding=finding,
            request_engine=request_engine,
            authorization_confirmed=True,
        )
