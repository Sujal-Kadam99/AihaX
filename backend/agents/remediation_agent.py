"""Agent 7 — Remediation: Claude API framework-specific fix generation."""

import json
from typing import Any

from backend.agents.base_agent import BaseAgent
from backend.core.config import get_settings
from backend.core.encryption import CredentialVault
from backend.models.database import Finding, Scan


class RemediationAgent(BaseAgent):
    agent_id = 7

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
            await self.publish_update("running", 100, "Claude API key not configured — skipping remediation")
            return {"skipped": True, "reason": "no_api_key"}

        scan = self.db.query(Scan).filter_by(id=self.scan_id).first()
        tech_stack = json.loads(scan.tech_stack) if scan and scan.tech_stack else []

        remediated = 0
        for i, finding in enumerate(findings):
            await self.check_cancelled()
            progress = int((i / max(len(findings), 1)) * 100)
            await self.publish_update("running", progress, f"Generating remediation for: {finding.title}...")

            try:
                remediation = await self._call_claude(api_key, finding, tech_stack, settings)
                finding.remediation = json.dumps(remediation)
                self.db.commit()
                remediated += 1
            except Exception as e:
                self.log("warning", f"Remediation failed for {finding.title}: {e}")
                finding.remediation = json.dumps({"status": "pending", "error": str(e)})
                self.db.commit()

        return {"remediated": remediated}

    async def _call_claude(
        self,
        api_key: str,
        finding: Finding,
        tech_stack: list,
        settings,
    ) -> dict[str, Any]:
        import anthropic

        client = anthropic.Anthropic(api_key=api_key, timeout=settings.claude_timeout)
        response = client.messages.create(
            model=settings.claude_model,
            max_tokens=2000,
            system="You are a senior security engineer. Generate framework-specific remediation code.",
            messages=[{
                "role": "user",
                "content": f"""
                Vulnerability: {finding.vuln_type}
                Tech Stack: {tech_stack}
                URL: {finding.affected_url}
                Parameter: {finding.affected_param}

                Provide: 1) Plain-English explanation 2) Framework-specific code fix
                3) Priority label 4) CWE/OWASP/CVE refs 5) Estimated fix time
                """,
            }],
        )
        return {
            "content": response.content[0].text,
            "model": settings.claude_model,
        }
