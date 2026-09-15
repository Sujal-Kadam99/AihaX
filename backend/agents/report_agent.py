"""Agent 6 — Report Generation: WeasyPrint + Jinja2 PDF output."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from backend.agents.base_agent import BaseAgent
from backend.core.config import get_settings
from backend.models.database import ExploitChain, Finding, Scan


class ReportAgent(BaseAgent):
    agent_id = 9

    async def execute(self) -> dict[str, Any]:
        from backend.services.bug_bounty_generator import BugBountyReportGenerator
        from backend.core.encryption import CredentialVault

        settings = get_settings()
        scan: Optional[Scan] = self.db.query(Scan).filter_by(id=self.scan_id).first()
        findings: list[Finding] = (
            self.db.query(Finding)
            .filter_by(scan_id=self.scan_id, false_positive=False)
            .order_by(Finding.severity)
            .all()
        )

        await self.publish_update("running", 20, "Gathering scan data...")
        report_data = self._build_report_data(scan, findings)

        vault = CredentialVault(settings.config_path)
        api_key = vault.get("claude_api_key")
        
        await self.publish_update("running", 40, "Generating Bug Bounty detailed findings...")
        bug_bounty_generator = BugBountyReportGenerator(api_key=api_key, settings=settings)
        report_data["bug_bounty_findings"] = await bug_bounty_generator.generate_for_findings(findings)

        await self.check_cancelled()
        await self.publish_update("running", 50, "Rendering HTML template...")

        try:
            from jinja2 import Environment, FileSystemLoader, select_autoescape

            template_dir = Path(__file__).resolve().parent.parent.parent / "templates" / "report"
            env = Environment(
                loader=FileSystemLoader(str(template_dir)),
                autoescape=select_autoescape(['html', 'xml'])
            )
            template = env.get_template("main.html")
            html = template.render(**report_data)

            await self.publish_update("running", 75, "Generating PDF...")
            from weasyprint import HTML

            report_path = Path(settings.reports_path) / f"{self.scan_id}.pdf"
            report_path.parent.mkdir(parents=True, exist_ok=True)
            HTML(string=html, base_url="file:///dev/null/").write_pdf(str(report_path))

            if scan is not None:
                setattr(scan, "report_path", str(report_path))
                self.db.commit()

            await self.publish_update("running", 100, f"Report saved to {report_path}")
            return {"report_path": str(report_path)}

        except Exception as e:
            self.log("error", f"Report generation failed: {e}")
            return {"error": str(e), "report_path": None}

    def _build_report_data(self, scan: Optional[Scan], findings: list[Finding]) -> dict[str, Any]:
        severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev_key = str(f.severity or "info").lower()
            severity_counts[sev_key] = severity_counts.get(sev_key, 0) + 1

        exploit_chains = (
            self.db.query(ExploitChain)
            .filter_by(scan_id=self.scan_id)
            .order_by(ExploitChain.created_at.desc())
            .all()
        )

        weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}
        risk_score = sum(weights.get(str(f.severity).lower(), 0) for f in findings)
        risk_score = min(risk_score, 100)
        
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        created_at_str = scan.created_at.strftime("%Y-%m-%d %H:%M UTC") if scan and scan.created_at else now_str

        return {
            "scan": scan,
            "findings": findings,
            "exploit_chains": exploit_chains,
            "severity_counts": severity_counts,
            "generated_at": now_str,
            "total_findings": len(findings),
            "target_url": scan.target_url if scan else "",
            "admin_mode": scan.admin_mode if scan else False,
            "scan_mode": scan.scan_mode if hasattr(scan, 'scan_mode') else "standard",
            "scan_depth": scan.scan_depth if hasattr(scan, 'scan_depth') else "light",
            "industry": scan.industry if hasattr(scan, 'industry') else "General",
            "created_at": created_at_str,
            "completed_at": now_str,
            "scan_id": self.scan_id,
            "risk_score": risk_score,
        }
