"""Agent 9 — Bug Bounty Export: HackerOne/Bugcrowd format reports and PoC packages."""

import json
import zipfile
from pathlib import Path
from typing import Any

from backend.agents.base_agent import BaseAgent
from backend.core.config import get_settings
from backend.models.database import Finding


class BugBountyAgent(BaseAgent):
    agent_id = 10

    async def execute(self) -> dict[str, Any]:
        if self.config.get("scan_mode") != "bugbounty":
            await self.publish_update("running", 100, "Bug bounty mode not enabled — skipping")
            return {"skipped": True}

        settings = get_settings()
        findings = (
            self.db.query(Finding)
            .filter_by(scan_id=self.scan_id, false_positive=False)
            .all()
        )

        exports = []
        for i, finding in enumerate(findings):
            await self.check_cancelled()
            progress = int((i / max(len(findings), 1)) * 100)
            await self.publish_update("running", progress, f"Exporting: {finding.title}...")

            try:
                from jinja2 import Environment, FileSystemLoader

                template_dir = Path(__file__).resolve().parent.parent.parent / "templates" / "bugbounty"
                env = Environment(loader=FileSystemLoader(str(template_dir)))
                h1_template = env.get_template("hackerone.html")
                h1_report = h1_template.render(finding=finding)

                export_dir = Path(settings.reports_path) / self.scan_id / "bugbounty"
                export_dir.mkdir(parents=True, exist_ok=True)

                h1_path = export_dir / f"{finding.id}_hackerone.html"
                h1_path.write_text(h1_report)

                poc_path = export_dir / f"{finding.id}_poc.zip"
                with zipfile.ZipFile(poc_path, "w") as zf:
                    zf.writestr("report.html", h1_report)
                    if finding.payload:
                        zf.writestr("payload.txt", finding.payload)
                    if finding.proof_response:
                        zf.writestr("response.txt", finding.proof_response)

                exports.append({"finding_id": finding.id, "hackerone": str(h1_path), "poc": str(poc_path)})
            except Exception as e:
                self.log("warning", f"Bug bounty export failed for {finding.title}: {e}")

        return {"exports": exports, "count": len(exports)}
