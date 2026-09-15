"""Agent 5 — Learning: upsert confirmed vulns and FP patterns to ChromaDB."""

import json
from typing import Any

from backend.agents.base_agent import BaseAgent
from backend.models.database import Finding


class LearningAgent(BaseAgent):
    agent_id = 5

    async def execute(self) -> dict[str, Any]:
        findings = self.db.query(Finding).filter_by(scan_id=self.scan_id).all()
        learned = 0

        for i, finding in enumerate(findings):
            await self.check_cancelled()
            progress = int((i / max(len(findings), 1)) * 100)
            await self.publish_update("running", progress, f"Learning from: {finding.title}...")

            try:
                from backend.core.chroma_client import upsert_document

                if finding.false_positive:
                    upsert_document(
                        "false_positive_patterns",
                        finding.id,
                        finding.payload or finding.title,
                        {
                            "vuln_type": finding.vuln_type,
                            "reason": "unconfirmed",
                            "confidence": finding.confidence,
                        },
                    )
                else:
                    upsert_document(
                        "confirmed_vulnerabilities",
                        finding.id,
                        finding.payload or finding.title,
                        {
                            "vuln_type": finding.vuln_type,
                            "severity": finding.severity,
                            "confidence": finding.confidence,
                        },
                    )
                learned += 1
            except Exception as e:
                self.log("warning", f"ChromaDB upsert failed: {e}")

        return {"learned": learned}
