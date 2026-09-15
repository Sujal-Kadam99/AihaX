"""Agent 8 — Business Impact: Claude API risk assessment translation."""

import json
from typing import Any

from backend.agents.base_agent import BaseAgent
from backend.core.config import get_settings
from backend.core.encryption import CredentialVault
from backend.models.database import Finding, Scan


class ImpactAgent(BaseAgent):
    agent_id = 8

    async def execute(self) -> dict[str, Any]:
        settings = get_settings()
        vault = CredentialVault(settings.config_path)
        api_key = vault.get("claude_api_key")

        findings = (
            self.db.query(Finding)
            .filter_by(scan_id=self.scan_id, false_positive=False)
            .all()
        )

        if not api_key:
            await self.publish_update("running", 100, "Claude API key not configured — skipping business impact")
            return {"skipped": True, "reason": "no_api_key"}

        scan = self.db.query(Scan).filter_by(id=self.scan_id).first()
        industry = scan.industry if scan else "General"

        analyzed = 0
        for i, finding in enumerate(findings):
            await self.check_cancelled()
            progress = int((i / max(len(findings), 1)) * 100)
            await self.publish_update("running", progress, f"Analyzing business impact: {finding.title}...")

            try:
                impact = await self._call_claude(api_key, finding, industry, settings)
                finding.business_impact = json.dumps(impact)
                self.db.commit()
                analyzed += 1
            except Exception as e:
                self.log("warning", f"Impact analysis failed for {finding.title}: {e}")
                finding.business_impact = json.dumps({"status": "pending", "error": str(e)})
                self.db.commit()

        return {"analyzed": analyzed}

    async def _call_claude(
        self,
        api_key: str,
        finding: Finding,
        industry: str,
        settings,
    ) -> dict[str, Any]:
        import anthropic

        client = anthropic.Anthropic(api_key=api_key, timeout=settings.claude_timeout)
        response = client.messages.create(
            model=settings.claude_model,
            max_tokens=1500,
            system="You translate technical security findings into business-readable risk assessments.",
            messages=[{
                "role": "user",
                "content": f"""
                Vulnerability: {finding.vuln_type}
                Severity: {finding.severity}
                Affected URL: {finding.affected_url}
                Industry: {industry}

                Provide: Financial impact estimate, GDPR/PCI exposure, CEO-language summary,
                breach probability, regulatory exposure
                """,
            }],
        )
        return {
            "content": response.content[0].text,
            "model": settings.claude_model,
        }
