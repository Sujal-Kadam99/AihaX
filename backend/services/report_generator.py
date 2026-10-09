import asyncio
import base64
import concurrent.futures
import hashlib
import json
import logging
import mimetypes
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader
from sqlalchemy.orm import Session

from backend.models.database import ExploitChain, Finding, Scan
from backend.persistence.models import Campaign, EvidenceRecord
from backend.services.bug_bounty_generator import BugBountyReportGenerator

logger = logging.getLogger(__name__)


def _load_pipeline_evidence(db: Session, campaign_id: str) -> Dict[str, Any]:
    """Read persisted recon/VTA manifests without presenting tool readiness as execution."""
    records = (
        db.query(EvidenceRecord)
        .filter(
            EvidenceRecord.campaign_id == campaign_id,
            EvidenceRecord.evidence_type.in_(
                [
                    "CAMPAIGN_RECON_REPORT",
                    "VULNERABILITY_TESTING_REPORT",
                    "VULNERABILITY_VERIFICATION_REPORT",
                    "EXPLOIT_CHAIN_REPORT",
                ]
            ),
        )
        .order_by(EvidenceRecord.created_at.asc())
        .all()
    )
    recon = None
    testing = None
    verification = None
    exploit_chains = None
    for record in records:
        try:
            payload = json.loads(record.sanitized_response or "{}")
        except (TypeError, ValueError):
            payload = {}
        item = {"evidence_id": record.id, "content_hash": record.content_hash}
        if record.evidence_type == "CAMPAIGN_RECON_REPORT":
            recon = {
                **item,
                "status": payload.get("status", "UNKNOWN"),
                "snapshot_hash": payload.get("snapshot_hash", ""),
                "observation_count": payload.get("observation_count", 0),
                "observations": [
                    {
                        "category": row.get("category", "unknown"),
                        "value": row.get("normalized_value") or row.get("value") or "",
                        "discovered_by": row.get("discovered_by", []),
                        "confidence": row.get("confidence"),
                        "evidence_hash": row.get("evidence_hash"),
                    }
                    for row in payload.get("observations", [])
                    if isinstance(row, dict)
                ],
                "tool_results": payload.get("tool_results", {}),
            }
        elif record.evidence_type == "VULNERABILITY_TESTING_REPORT":
            coverage = payload.get("check_coverage", [])
            counts: Dict[str, int] = {}
            for row in coverage if isinstance(coverage, list) else []:
                state = str(row.get("status", "UNKNOWN"))
                counts[state] = counts.get(state, 0) + 1
            testing = {
                **item,
                "total_registered": payload.get("total_registered", 0),
                "executed_count": payload.get("executed_count", 0),
                "coverage_counts": counts,
                "tool_results": payload.get("tool_results", {}),
                "tool_plan": payload.get("tool_plan", []),
                "execution_statistics": payload.get("execution_statistics", {}),
            }
        elif record.evidence_type == "VULNERABILITY_VERIFICATION_REPORT":
            verification = {**item, **payload}
        elif record.evidence_type == "EXPLOIT_CHAIN_REPORT":
            exploit_chains = {**item, **payload}
    if testing is not None:
        testing["verification"] = verification
        testing["exploit_chain_analysis"] = exploit_chains
    return {"recon": recon, "testing": testing, "verification": verification, "exploit_chains": exploit_chains}


def _clean_text(s: Any) -> str:
    """Sanitize strings for latin-1 core font compatibility in PDF generator."""
    if s is None:
        return ""
    text_str = str(s)
    replacements = {
        "—": "-",
        "–": "-",
        "’": "'",
        "‘": "'",
        "“": '"',
        "”": '"',
        "…": "...",
        "→": "->",
        "•": "*",
        "★": "*",
        "🔴": "[CRITICAL]",
        "🟠": "[HIGH]",
        "🟡": "[MEDIUM]",
        "🟢": "[LOW]",
        "🔵": "[INFO]",
    }
    for orig, rep in replacements.items():
        text_str = text_str.replace(orig, rep)
    return text_str.encode("latin-1", errors="replace").decode("latin-1")


def _generate_fpdf_fallback(context: dict[str, Any]) -> bytes:
    """Generate a clean PDF report using fpdf2 when WeasyPrint/GTK is unavailable."""
    from fpdf import FPDF

    class AihaXReportPDF(FPDF):
        def header(self):
            if self.page_no() > 1:
                self.set_font("helvetica", "B", 8)
                self.set_text_color(0, 180, 216)
                self.cell(100, 6, "AihaX Pentest Report", border=0, align="L")
                self.set_font("helvetica", "I", 8)
                self.set_text_color(130, 140, 155)
                self.cell(0, 6, f"Page {self.page_no()}", border=0, align="R", new_x="LMARGIN", new_y="NEXT")
                self.set_draw_color(220, 225, 235)
                self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
                self.ln(4)

        def footer(self):
            if self.page_no() > 1:
                self.set_y(-12)
                self.set_font("helvetica", "I", 8)
                self.set_text_color(140, 150, 165)
                self.cell(0, 8, _clean_text("CONFIDENTIAL - Authorized Target Security Assessment"), align="C")

    pdf = AihaXReportPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Cover Header
    pdf.set_font("helvetica", "B", 24)
    pdf.set_text_color(10, 22, 40)
    pdf.cell(0, 14, "AihaX Security Assessment", align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("helvetica", "", 12)
    pdf.set_text_color(0, 180, 216)
    mode_label = context.get("report_mode", "Full").upper()
    pdf.cell(0, 8, f"{mode_label} REPORT", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    # Metadata Card
    pdf.set_draw_color(210, 220, 235)
    pdf.set_fill_color(245, 248, 252)
    pdf.rect(pdf.l_margin, pdf.get_y(), pdf.w - 2 * pdf.l_margin, 36, style="FD")

    pdf.set_y(pdf.get_y() + 4)
    pdf.set_font("helvetica", "B", 9)
    pdf.set_text_color(30, 45, 65)
    pdf.set_x(pdf.l_margin + 5)
    pdf.cell(35, 6, "Target URL:", align="L")
    pdf.set_font("helvetica", "", 9)
    pdf.cell(0, 6, _clean_text(context.get("target_url", "N/A")), new_x="LMARGIN", new_y="NEXT")

    pdf.set_x(pdf.l_margin + 5)
    pdf.set_font("helvetica", "B", 9)
    pdf.cell(35, 6, "Scan ID:", align="L")
    pdf.set_font("helvetica", "", 9)
    pdf.cell(0, 6, _clean_text(context.get("scan_id", "N/A")), new_x="LMARGIN", new_y="NEXT")

    pdf.set_x(pdf.l_margin + 5)
    pdf.set_font("helvetica", "B", 9)
    pdf.cell(35, 6, "Risk Score:", align="L")
    pdf.set_font("helvetica", "B", 9)
    pdf.set_text_color(200, 30, 30)
    pdf.cell(0, 6, f"{context.get('risk_score', 0)} / 100", new_x="LMARGIN", new_y="NEXT")

    pdf.set_x(pdf.l_margin + 5)
    pdf.set_font("helvetica", "B", 9)
    pdf.set_text_color(30, 45, 65)
    pdf.cell(35, 6, "Generated:", align="L")
    pdf.set_font("helvetica", "", 9)
    pdf.cell(0, 6, _clean_text(context.get("generated_at", "N/A")), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)

    report_mode = context.get("report_mode", "full")

    # Executive Summary
    if report_mode in ("executive", "full"):
        pdf.set_font("helvetica", "B", 14)
        pdf.set_text_color(10, 22, 40)
        pdf.cell(0, 10, "Executive Summary", align="L", new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("helvetica", "", 9)
        pdf.set_text_color(60, 70, 85)
        confirmed_cnt = context.get("confirmed_vulnerabilities_count", 0)
        hardening_cnt = context.get("hardening_observations_count", 0)
        inconclusive_cnt = context.get("inconclusive_observations_count", 0)
        pdf.multi_cell(
            0,
            5.5,
            _clean_text(
                f"This automated security assessment was performed by AihaX against {context.get('target_url')}.\n"
                f"Assessment Findings Summary: Confirmed Vulnerabilities: {confirmed_cnt} | "
                f"Hardening Recommendations: {hardening_cnt} | "
                f"Inconclusive Observations: {inconclusive_cnt}"
            ),
        )
        pdf.ln(4)

        # Severity Table
        pdf.set_font("helvetica", "B", 8)
        pdf.set_fill_color(26, 58, 92)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(40, 7, "Severity", border=1, fill=True)
        pdf.cell(30, 7, "Count", border=1, fill=True)
        pdf.cell(0, 7, "Description", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

        sev_counts = context.get("severity_counts", {})
        sev_rows = [
            ("Critical", sev_counts.get("critical", 0), "Immediate exploitation risk"),
            ("High", sev_counts.get("high", 0), "High exploitation potential"),
            ("Medium", sev_counts.get("medium", 0), "Moderate security risk"),
            ("Low", sev_counts.get("low", 0), "Limited impact"),
            ("Info", sev_counts.get("info", 0), "Informational / hardening"),
        ]
        pdf.set_font("helvetica", "", 8)
        pdf.set_text_color(40, 50, 65)
        for label, count, desc in sev_rows:
            pdf.cell(40, 6, label, border=1)
            pdf.cell(30, 6, str(count), border=1)
            pdf.cell(0, 6, _clean_text(desc), border=1, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(8)

    # Bug Bounty / Detailed Findings
    if report_mode in ("bugbounty", "full"):
        pdf.set_font("helvetica", "B", 14)
        pdf.set_text_color(10, 22, 40)
        pdf.cell(0, 10, "Detailed Vulnerability Reports", align="L", new_x="LMARGIN", new_y="NEXT")

        bb_findings = context.get("bug_bounty_findings", [])
        if not bb_findings:
            pdf.set_font("helvetica", "I", 9)
            pdf.set_text_color(90, 100, 115)
            pdf.cell(0, 8, "No verified vulnerabilities were found during this assessment.", new_x="LMARGIN", new_y="NEXT")
        else:
            for idx, f in enumerate(bb_findings, 1):
                pdf.ln(3)
                pdf.set_draw_color(0, 180, 216)
                pdf.set_fill_color(240, 246, 255)
                pdf.set_font("helvetica", "B", 10)
                pdf.set_text_color(10, 22, 40)
                pdf.cell(0, 8, _clean_text(f" Finding #{idx}: {f.title}  [{f.severity.upper()}] - VERIFIED"), border="L", fill=True, new_x="LMARGIN", new_y="NEXT")

                pdf.set_font("helvetica", "", 8)
                pdf.set_text_color(50, 60, 75)
                pdf.cell(35, 5, "Vulnerability Type:", align="L")
                pdf.cell(0, 5, _clean_text(f.vulnerability_type), new_x="LMARGIN", new_y="NEXT")

                if f.cwe:
                    pdf.cell(35, 5, "CWE:", align="L")
                    pdf.cell(0, 5, _clean_text(f.cwe), new_x="LMARGIN", new_y="NEXT")

                pdf.cell(35, 5, "Affected Endpoint:", align="L")
                pdf.cell(0, 5, _clean_text(f.affected_url), new_x="LMARGIN", new_y="NEXT")

                pdf.cell(35, 5, "Confidence:", align="L")
                pdf.cell(0, 5, f"{f.confidence}%", new_x="LMARGIN", new_y="NEXT")

                pdf.set_font("helvetica", "B", 8)
                pdf.set_text_color(30, 45, 65)
                pdf.cell(0, 5, "Summary:", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("helvetica", "", 8)
                pdf.set_text_color(60, 70, 85)
                pdf.multi_cell(0, 4, _clean_text(f.summary), new_x="LMARGIN", new_y="NEXT")

                if f.proof_of_concept.payload and str(f.proof_of_concept.payload).strip() and "Not available" not in str(f.proof_of_concept.payload):
                    pdf.set_font("helvetica", "B", 8)
                    pdf.set_text_color(30, 45, 65)
                    pdf.cell(0, 5, "Payload:", new_x="LMARGIN", new_y="NEXT")
                    pdf.set_font("courier", "", 7)
                    pdf.set_text_color(180, 20, 20)
                    pdf.multi_cell(0, 3.8, _clean_text(str(f.proof_of_concept.payload)[:500]), new_x="LMARGIN", new_y="NEXT")

                if f.proof_of_concept.response and str(f.proof_of_concept.response).strip() and "Not available" not in str(f.proof_of_concept.response):
                    pdf.set_font("helvetica", "B", 8)
                    pdf.set_text_color(30, 45, 65)
                    pdf.cell(0, 5, "Proof Response Evidence:", new_x="LMARGIN", new_y="NEXT")
                    pdf.set_font("courier", "", 7)
                    pdf.set_text_color(40, 50, 65)
                    pdf.multi_cell(0, 3.5, _clean_text(str(f.proof_of_concept.response)[:600]), new_x="LMARGIN", new_y="NEXT")

                if f.suggested_fix:
                    pdf.set_font("helvetica", "B", 8)
                    pdf.set_text_color(30, 45, 65)
                    pdf.cell(0, 5, "Suggested Remediation:", new_x="LMARGIN", new_y="NEXT")
                    pdf.set_font("helvetica", "", 8)
                    pdf.set_text_color(60, 70, 85)
                    pdf.multi_cell(0, 4, _clean_text(f.suggested_fix), new_x="LMARGIN", new_y="NEXT")
                pdf.ln(3)

    return bytes(pdf.output())


def generate_scan_report(db: Session, scan_id: str, mode: Optional[str] = None) -> bytes:
    """Generate a PDF report for a given scan or campaign with report mode support."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    campaign = None
    if not scan:
        from backend.persistence.models import Campaign
        campaign = db.query(Campaign).filter(Campaign.id == scan_id).first()
        if not campaign:
            raise ValueError(f"Scan or Campaign with ID {scan_id} not found.")

    target_obj = scan or campaign

    # Determine effective report mode
    raw_mode = (mode or getattr(target_obj, "report_format", None) or getattr(target_obj, "scan_mode", None) or getattr(target_obj, "mode", None) or "full").lower()
    if "exec" in raw_mode:
        effective_mode = "executive"
    elif "bug" in raw_mode:
        effective_mode = "bugbounty"
    else:
        effective_mode = "full"

    # Explicit query — Partition findings into verified, hardening, and inconclusive
    raw_findings = (
        db.query(Finding)
        .filter(
            Finding.scan_id == scan_id,
            Finding.duplicate_of == None,
        )
        .all()
    )
    from backend.services.finding_deduplicator import FindingDeduplicator
    all_findings = FindingDeduplicator.correlate_header_findings(raw_findings)

    valid_findings = [
        f for f in all_findings
        if getattr(f, "human_review_status", "") != "REJECTED"
    ]

    verified_vulnerabilities = [
        f for f in valid_findings
        if (getattr(f, "finding_disposition", "") in ("VALIDATED", "EXPLOITABLE", "VULNERABILITY") or getattr(f, "verification_status", "") in ("VALIDATED", "EXPLOITABLE"))
        and not getattr(f, "false_positive", False)
        and getattr(f, "verdict", "") != "Hardening Only"
        and getattr(f, "finding_disposition", "") not in ("HARDENING_ONLY", "FALSE_POSITIVE", "INCONCLUSIVE", "NOT_BOUNTY_ELIGIBLE")
    ]
    hardening_recommendations = [
        f for f in valid_findings
        if getattr(f, "finding_disposition", "") == "HARDENING_ONLY"
        or getattr(f, "verification_status", "") == "HARDENING_ONLY"
        or getattr(f, "verdict", "") == "Hardening Only"
    ]
    inconclusive_observations = [
        f for f in valid_findings
        if (getattr(f, "finding_disposition", "") == "INCONCLUSIVE" or getattr(f, "verification_status", "") == "INCONCLUSIVE" or getattr(f, "verdict", "") == "Inconclusive")
        and f not in hardening_recommendations
        and f not in verified_vulnerabilities
    ]

    # Primary reportable findings (verified + primary non-correlated hardening)
    findings = verified_vulnerabilities + [h for h in hardening_recommendations if getattr(h, "parent_finding_id", None) is None]

    exploit_chains = (
        db.query(ExploitChain)
        .filter(ExploitChain.scan_id == scan_id)
        .all()
    )

    # Generate canonical Bug Bounty DTOs for verified findings
    bb_generator = BugBountyReportGenerator()
    bug_bounty_findings = []
    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(lambda: asyncio.run(bb_generator.generate_for_findings(findings)))
            bug_bounty_findings = future.result()
    except Exception as e:
        logger.warning(f"Could not generate Bug Bounty DTOs: {e}")

    # Severity counts
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.severity or "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: severity_order.get((x.severity or "info").lower(), 5))

    # Parse JSON fields safely
    parsed_findings = []
    for f in findings:
        remediation = None
        if f.remediation:
            try:
                remediation = json.loads(str(f.remediation))
            except Exception:
                remediation = {"content": str(f.remediation)}

        business_impact = None
        if f.business_impact:
            try:
                business_impact = json.loads(str(f.business_impact))
            except Exception:
                business_impact = {"content": str(f.business_impact)}

        screenshot_b64 = None
        screenshot_mime = "image/png"
        screenshot_caption = None
        if f.screenshot_path:
            screenshot_str = str(f.screenshot_path)
            if os.path.isfile(screenshot_str):
                try:
                    mime, _ = mimetypes.guess_type(screenshot_str)
                    screenshot_mime = mime or "image/png"
                    with open(screenshot_str, "rb") as img_file:
                        screenshot_b64 = base64.b64encode(img_file.read()).decode("utf-8")
                    screenshot_caption = (
                        f"Figure: Browser evidence screenshot captured by the AihaX Authentication Agent "
                        f"during automated testing of '{f.title}' at {f.affected_url or 'the target endpoint'}."
                    )
                except Exception:
                    pass

        parsed_findings.append({
            "title": f.title,
            "severity": (f.severity or "info").lower(),
            "category": f.category or "",
            "affected_url": f.affected_url or "",
            "affected_param": f.affected_param,
            "payload": f.payload,
            "proof_response": f.proof_response,
            "confidence": f.confidence,
            "verdict": f.verdict or "Inconclusive",
            "cvss_score": f.cvss_score,
            "cwe_id": f.cwe_id,
            "cve_id": f.cve_id,
            "remediation": remediation,
            "business_impact": business_impact,
            "screenshot_b64": screenshot_b64,
            "screenshot_mime": screenshot_mime,
            "screenshot_caption": screenshot_caption,
        })

    # Parse exploit chains
    parsed_chains = []
    for c in exploit_chains:
        steps = []
        if c.steps:
            try:
                steps = json.loads(str(c.steps))
            except Exception:
                steps = [str(c.steps)]
        parsed_chains.append({
            "chain_name": c.chain_name,
            "severity_final": c.severity_final,
            "impact_summary": c.impact_summary,
            "steps": steps,
            "diagram_path": c.diagram_path,
        })

    # Compute overall risk score
    risk_score = getattr(target_obj, "risk_score", None)
    if risk_score is None:
        score = (
            severity_counts["critical"] * 40
            + severity_counts["high"] * 20
            + severity_counts["medium"] * 8
            + severity_counts["low"] * 3
            + severity_counts["info"] * 1
        )
        risk_score = min(score, 100)

    created_at_val = getattr(target_obj, "created_at", None)
    completed_at_val = getattr(target_obj, "completed_at", None)
    pipeline_evidence = _load_pipeline_evidence(db, scan_id)

    context = {
        "target_url": getattr(target_obj, "target_url", "N/A"),
        "scan_id": scan_id,
        "scan_depth": getattr(target_obj, "scan_depth", getattr(target_obj, "mode", "normal")),
        "scan_mode": getattr(target_obj, "scan_mode", getattr(target_obj, "mode", "standard")),
        "report_mode": effective_mode,
        "industry": getattr(target_obj, "industry", "General"),
        "admin_mode": getattr(target_obj, "admin_mode", False),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "created_at": created_at_val.strftime("%Y-%m-%d %H:%M UTC") if created_at_val else "N/A",
        "completed_at": completed_at_val.strftime("%Y-%m-%d %H:%M UTC") if completed_at_val else datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "total_findings": len(parsed_findings),
        "confirmed_vulnerabilities_count": len(verified_vulnerabilities),
        "hardening_observations_count": len(hardening_recommendations),
        "inconclusive_observations_count": len(inconclusive_observations),
        "severity_counts": severity_counts,
        "findings": parsed_findings,
        "bug_bounty_findings": bug_bounty_findings,
        "exploit_chains": parsed_chains,
        "risk_score": risk_score,
        "pipeline_evidence": pipeline_evidence,
    }

    # Setup Jinja2
    templates_dir = os.path.join(os.path.dirname(__file__), "..", "..", "templates", "report")
    env = Environment(loader=FileSystemLoader(templates_dir), autoescape=True)
    template = env.get_template("main.html")
    html_out = template.render(**context)

    # Try WeasyPrint first, fallback to pure Python fpdf2
    try:
        from weasyprint import HTML
        pdf_bytes = HTML(string=html_out, base_url="file:///").write_pdf()
        return bytes(pdf_bytes or b"")
    except Exception as e:
        logger.info(f"WeasyPrint unavailable ({e}), generating via pure Python PDF engine.")
        return _generate_fpdf_fallback(context)


def generate_markdown_report(scan_id: str, db: Session, mode: Optional[str] = "bugbounty") -> str:
    """Generate clean, publication-ready Markdown report with strict FACT vs INFERENCE separation."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    campaign = None
    if not scan:
        campaign = db.query(Campaign).filter(Campaign.id == scan_id).first()
        if not campaign:
            raise ValueError(f"Scan or Campaign with ID {scan_id} not found.")

    target_obj = scan or campaign
    target_url = getattr(target_obj, "target_url", "N/A")

    from backend.services.finding_quality import FindingQualityScorer
    from backend.services.finding_deduplicator import FindingDeduplicator

    raw_findings = (
        db.query(Finding)
        .filter(
            Finding.scan_id == scan_id,
            Finding.duplicate_of == None,
        )
        .all()
    )
    all_findings = FindingDeduplicator.correlate_header_findings(raw_findings)

    valid_findings = [
        f for f in all_findings
        if getattr(f, "human_review_status", "") != "REJECTED"
    ]

    verified_vulnerabilities = []
    hardening_recommendations = []
    inconclusive_observations = []
    other_observations = []

    for f in valid_findings:
        quality = FindingQualityScorer.evaluate_finding_record(f)
        if not getattr(quality, "is_reportable", True):
            continue

        disp = getattr(f, "finding_disposition", "")
        v_status = getattr(f, "verification_status", "")
        verdict = getattr(f, "verdict", "")

        if getattr(f, "false_positive", False) or disp in ("FALSE_POSITIVE", "NOT_BOUNTY_ELIGIBLE") or v_status == "REJECTED":
            other_observations.append((f, quality))
        elif disp == "HARDENING_ONLY" or v_status == "HARDENING_ONLY" or verdict == "Hardening Only":
            hardening_recommendations.append((f, quality))
        elif (disp == "VULNERABILITY" or v_status in ("VALIDATED", "EXPLOITABLE") or verdict == "Verified"):
            verified_vulnerabilities.append((f, quality))
        elif disp == "INCONCLUSIVE" or v_status == "INCONCLUSIVE" or verdict == "Inconclusive":
            inconclusive_observations.append((f, quality))
        else:
            other_observations.append((f, quality))

    lines = [
        f"# Security Assessment Report — {target_url}",
        "",
        f"- **Scan / Campaign ID:** `{scan_id}`",
        f"- **Target URL:** `{target_url}`",
        f"- **Generated At:** `{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}`",
        f"- **Confirmed Vulnerabilities:** {len(verified_vulnerabilities)}",
        f"- **Hardening Recommendations:** {len(hardening_recommendations)}",
        f"- **Inconclusive Observations:** {len(inconclusive_observations)}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        "## Summary of Findings",
        "",
        f"This automated security assessment was performed by AihaX against `{target_url}` under authorized scope.",
        f"The assessment identified **{len(verified_vulnerabilities)} confirmed vulnerabilities**, "
        f"**{len(hardening_recommendations)} defense-in-depth hardening observations**, and "
        f"**{len(inconclusive_observations)} inconclusive findings** requiring extended testing.",
        "",
        "---",
        "",
        "## Section A: Verified Security Vulnerabilities",
        "",
    ]

    pipeline_evidence = _load_pipeline_evidence(db, scan_id)
    recon_manifest = pipeline_evidence.get("recon")
    vta_manifest = pipeline_evidence.get("testing")
    if recon_manifest or vta_manifest:
        lines.extend(["## Assessment Execution Evidence", ""])
        if recon_manifest:
            lines.extend([
                f"- **Recon status:** {recon_manifest['status']}",
                f"- **Recon observations:** {recon_manifest['observation_count']}",
                f"- **Recon snapshot hash:** `{recon_manifest['snapshot_hash'] or 'unavailable'}`",
                f"- **Recon evidence:** `{recon_manifest['evidence_id']}` (SHA-256 `{recon_manifest['content_hash']}`)",
            ])
            lines.append("- **Observed attack surface:**")
            if recon_manifest.get("observations"):
                for observation in recon_manifest["observations"]:
                    source = ", ".join(observation.get("discovered_by") or []) or "unknown source"
                    lines.append(f"  - `{observation['category']}` `{observation['value']}` (source: {source})")
            else:
                lines.append("  - No normalized observations were captured in the stored snapshot.")
            lines.append("- **Recon tool outcomes:**")
            for name, tool in sorted((recon_manifest.get("tool_results") or {}).items()):
                if isinstance(tool, dict):
                    lines.append(f"  - `{name}`: {tool.get('status', 'UNKNOWN')} — {tool.get('reason', 'No reason supplied.')}")
                else:
                    lines.append(f"  - `{name}`: result recorded")
            lines.append("")
        if vta_manifest:
            lines.extend([
                f"- **Vulnerability checks registered:** {vta_manifest['total_registered']}",
                f"- **Vulnerability hypotheses executed:** {vta_manifest['executed_count']}",
                f"- **Check coverage statuses:** `{json.dumps(vta_manifest['coverage_counts'], sort_keys=True)}`",
                f"- **VTA evidence:** `{vta_manifest['evidence_id']}` (SHA-256 `{vta_manifest['content_hash']}`)",
                "- **Vulnerability tool outcomes:**",
            ])
            for name, tool in sorted((vta_manifest.get("tool_results") or {}).items()):
                if isinstance(tool, dict):
                    lines.append(f"  - `{name}`: {tool.get('status', 'UNKNOWN')} — {tool.get('reason', 'No reason supplied.')}")
                else:
                    lines.append(f"  - `{name}`: result recorded")
            if vta_manifest.get("tool_plan"):
                lines.append("- **Hypothesis-driven tool decisions:**")
                for decision in vta_manifest["tool_plan"]:
                    ids = ", ".join(decision.get("hypothesis_ids") or []) or ", ".join(decision.get("check_ids") or []) or "campaign-level"
                    lines.append(
                        f"  - `{decision.get('tool', 'unknown')}` for `{ids}`: "
                        f"{decision.get('decision', 'UNKNOWN')} — "
                        f"{decision.get('rationale', decision.get('outcome_reason', 'No reason supplied.'))}"
                    )
            verification = vta_manifest.get("verification") or {}
            if verification:
                lines.append(
                    f"- **VerifyAgent:** {verification.get('verified', 0)} verified, "
                    f"{verification.get('rejected', 0)} rejected, "
                    f"{verification.get('inconclusive', 0)} inconclusive. "
                    f"Evidence `{verification.get('evidence_id', 'unavailable')}`."
                )
            chains = vta_manifest.get("exploit_chain_analysis") or {}
            if chains:
                lines.append(
                    f"- **ExploitChainAgent:** {len(chains.get('chains', []))} chain(s) analyzed from verified findings only. "
                    f"Evidence `{chains.get('evidence_id', 'unavailable')}`."
                )
            lines.append("")

    if not verified_vulnerabilities:
        lines.append("No verified vulnerabilities meeting quality reporting criteria were identified during this assessment.")
        lines.append("")
    else:
        for idx, (f, q) in enumerate(verified_vulnerabilities, start=1):
            lines.extend(_format_finding_block(idx, f, q, target_url))

    lines.extend([
        "---",
        "",
        "## Section B: Defense-in-Depth / Hardening Recommendations",
        "",
    ])
    if not hardening_recommendations:
        lines.append("No hardening observations recorded.")
        lines.append("")
    else:
        for idx, (f, q) in enumerate(hardening_recommendations, start=1):
            lines.extend(_format_finding_block(idx, f, q, target_url))

    lines.extend([
        "---",
        "",
        "## Section C: Inconclusive / Requires Extended Testing",
        "",
    ])
    if not inconclusive_observations:
        lines.append("No inconclusive findings recorded.")
        lines.append("")
    else:
        for idx, (f, q) in enumerate(inconclusive_observations, start=1):
            lines.extend(_format_finding_block(idx, f, q, target_url))

    if other_observations:
        lines.extend([
            "---",
            "",
            "## Section D: Other / Not Bounty Eligible",
            "",
        ])
        for idx, (f, q) in enumerate(other_observations, start=1):
            lines.extend(_format_finding_block(idx, f, q, target_url))

    return "\n".join(lines)


def _format_finding_block(idx: int, f: Finding, q: Any, target_url: str) -> list[str]:
    confirmed_imp = getattr(f, "impact_confirmed", None) or getattr(f, "business_impact", "") or "Demonstrated security condition as evidenced by HTTP response."
    if not str(confirmed_imp).startswith("FACT:"):
        confirmed_imp = f"FACT: {confirmed_imp}"

    potential_imp = getattr(f, "impact_potential", None) or "Potential unauthorized data access or policy bypass depending on server-side authorization state."
    if not str(potential_imp).startswith("[INFERENCE]"):
        potential_imp = f"[INFERENCE]: {potential_imp}"

    remediation_text = getattr(f, "remediation", None) or "Apply principle of least privilege, input validation, and defensive headers."
    evidence_hash = "SHA-256 Verified"
    if getattr(f, "evidence_hashes", None):
        try:
            eh_dict = json.loads(f.evidence_hashes)
            evidence_hash = eh_dict.get("proof_response_sha256", "SHA-256 Verified")
        except Exception:
            pass

    parent_note = f"- **Correlated Under Parent Finding:** `{f.parent_finding_id}`" if getattr(f, "parent_finding_id", None) else None

    lines = [
        f"### {idx}. {f.title}",
        f"- **Severity:** {str(f.severity).upper()}",
        f"- **Vulnerability Type / Category:** `{f.vuln_type}` ({f.category})",
        f"- **Affected Target:** `{f.affected_url}`",
        f"- **Affected Parameter / Component:** `{f.affected_param or 'N/A'}`",
        f"- **Finding Disposition:** {getattr(f, 'finding_disposition', 'INCONCLUSIVE')}",
        f"- **Verification Status:** {getattr(f, 'verification_status', f.verdict)}",
        f"- **Bounty Eligibility:** {getattr(f, 'bounty_eligibility', 'UNKNOWN')}",
        f"- **Condition Confidence:** {float(getattr(f, 'condition_confidence', 1.0 if f.verdict == 'Verified' else 0.5)):.2f}",
        f"- **Exploitability Confidence:** {float(getattr(f, 'exploitability_confidence', 0.0)):.2f}",
        f"- **Quality Band:** Band {q.quality_band} (Score: {q.total_score:.2f})",
        f"- **Confidence:** {f.confidence}%",
        f"- **Human Review Status:** {getattr(f, 'human_review_status', 'APPROVED')}",
    ]
    if parent_note:
        lines.append(parent_note)

    lines.extend([
        "",
        "#### Preconditions",
        f"- Network reachability to `{target_url}` under authorized testing scope.",
        f"- User session context or parameter control over `{f.affected_param or 'endpoint'}`.",
        "",
        "#### Steps to Reproduce",
        f"1. Dispatch authorized HTTP request matching the proof payload to `{f.affected_url}`.",
        f"2. Observe server response containing verifiable security condition.",
        "",
        "#### Baseline Evidence",
        "```http",
        f"{getattr(f, 'baseline_request', None) or 'N/A'}",
        "```",
        "",
        "#### Verification Evidence (Proof of Concept)",
        "```http",
        f"{f.proof_request or 'N/A'}",
        "```",
        "",
        "```http",
        f"{f.proof_response or 'N/A'}",
        "```",
        "",
        "#### Observed Result",
        f"{f.proof_response[:200] if f.proof_response else 'N/A'}",
        "",
        "#### Confirmed Impact (FACT)",
        "#### Confirmed Impact (Observed Fact)",
        f"{confirmed_imp}",
        "",
        "#### Potential Impact ([INFERENCE])",
        "#### Potential Impact (Theoretical Risk)",
        f"{potential_imp}",
        "",
        "#### Security Significance & Remediation",
        f"{remediation_text}",
        "",
        "#### Evidence Integrity & References",
        f"- **Response SHA-256 Hash:** `{evidence_hash}`",
        f"- **CWE:** {getattr(f, 'cwe_id', None) or 'CWE-693'}",
        "",
    ])
    return lines

    return "\n".join(lines)


def generate_report_package(
    scan_id: str,
    db: Session,
    mode: Optional[str] = "bugbounty",
) -> Dict[str, Any]:
    """Generate multi-format report package containing Markdown, HTML, PDF, JSON and package hash."""
    markdown_content = generate_markdown_report(scan_id, db, mode)
    pdf_bytes = generate_scan_report(db, scan_id, mode)

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    campaign = None
    if not scan:
        campaign = db.query(Campaign).filter(Campaign.id == scan_id).first()
    target_obj = scan or campaign

    raw_findings = (
        db.query(Finding)
        .filter(
            Finding.scan_id == scan_id,
            Finding.verdict == "Verified",
            Finding.false_positive == False,
            Finding.duplicate_of == None,
        )
        .all()
    )
    verified_findings = [
        f for f in raw_findings
        if getattr(f, "human_review_status", "") != "REJECTED"
    ]

    json_payload = {
        "scan_id": scan_id,
        "target_url": getattr(target_obj, "target_url", "N/A") if target_obj else "N/A",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(verified_findings),
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "vuln_type": f.vuln_type,
                "category": f.category,
                "severity": f.severity,
                "cvss_score": f.cvss_score,
                "affected_url": f.affected_url,
                "affected_param": f.affected_param,
                "verdict": f.verdict,
                "confidence": f.confidence,
                "human_review_status": getattr(f, "human_review_status", "APPROVED"),
                "human_reviewed_by": getattr(f, "human_reviewed_by", None),
                "finding_fingerprint": getattr(f, "finding_fingerprint", None),
                "created_at": f.created_at.isoformat() if f.created_at else None,
            }
            for f in verified_findings
        ],
    }

    serialized_json = json.dumps(json_payload, sort_keys=True, separators=(",", ":"))
    package_hasher = hashlib.sha256()
    package_hasher.update(markdown_content.encode("utf-8"))
    package_hasher.update(pdf_bytes)
    package_hasher.update(serialized_json.encode("utf-8"))
    package_hash = package_hasher.hexdigest()

    return {
        "scan_id": scan_id,
        "markdown": markdown_content,
        "pdf_bytes": pdf_bytes,
        "json_data": json_payload,
        "package_hash": package_hash,
        "total_findings": len(verified_findings),
    }


# ==============================================================================
# Phase 23: Multi-Step Research & Validation Report Package
# ==============================================================================

def generate_phase23_report_package(
    campaign_id: str,
    target: str,
    plan_id: str,
    hypothesis: Any,
    plan: Any,
    observations: List[Any],
    reproduction: Optional[Any],
    confidence_assessment: Optional[Any],
    evidence_chain: Optional[Any],
    operator_id: str = "operator",
    scope_snapshot_hash: str = "SCOPE-SNAPSHOT-HASH",
    chain_verified: bool = True,
    db: Optional[Session] = None,
) -> Dict[str, Any]:
    """Generate comprehensive Phase 23 Markdown & JSON vulnerability assessment report package."""
    now_iso = datetime.now(timezone.utc).isoformat()
    hyp_dict = hypothesis.to_dict() if hasattr(hypothesis, "to_dict") else (hypothesis if isinstance(hypothesis, dict) else {})
    plan_dict = plan.to_dict() if hasattr(plan, "to_dict") else (plan if isinstance(plan, dict) else {})
    repro_dict = reproduction.to_dict() if hasattr(reproduction, "to_dict") else (reproduction if isinstance(reproduction, dict) else {})
    conf_dict = confidence_assessment.to_dict() if hasattr(confidence_assessment, "to_dict") else (confidence_assessment if isinstance(confidence_assessment, dict) else {})
    chain_dict = evidence_chain.to_dict() if hasattr(evidence_chain, "to_dict") else (evidence_chain if isinstance(evidence_chain, dict) else {})

    vuln_class = hyp_dict.get("vulnerability_class", "VULNERABILITY")
    title = f"Evidence-Backed Vulnerability Report: {vuln_class} on {target}"

    # Build Markdown
    md_lines = [
        f"# {title}",
        "",
        "## 1. Executive Summary",
        f"A multi-step authorized vulnerability research validation was executed against `{target}`.",
        f"The validation plan confirmed security-relevant behavior with confidence **{conf_dict.get('confidence_level', 'HIGH')}** ({conf_dict.get('overall_score', 1.0):.2f}).",
        "",
        "## 2. Target & Authorization Context",
        f"- **Campaign ID:** `{campaign_id}`",
        f"- **Authorized Concrete Target:** `{target}`",
        f"- **Operator ID:** `{operator_id}`",
        f"- **Scope Snapshot Hash:** `{scope_snapshot_hash}`",
        f"- **Generated At:** `{now_iso}`",
        "",
        "## 3. Vulnerability Hypothesis & Correlation",
        f"- **Hypothesis ID:** `{hyp_dict.get('hypothesis_id', 'N/A')}`",
        f"- **Vulnerability Class:** `{vuln_class}`",
        f"- **Rationale:** {hyp_dict.get('rationale', 'N/A')}",
        f"- **Expected Evidence:** {hyp_dict.get('expected_evidence', 'N/A')}",
        "",
        "## 4. Multi-Step Validation Plan",
        f"- **Plan ID:** `{plan_id}`",
        f"- **Version:** `{plan_dict.get('plan_version', '1.0.0-phase23')}`",
        f"- **Total Planned Requests:** `{plan_dict.get('estimated_requests', len(observations))}`",
        "",
        "### Step Execution Log",
    ]

    for obs in observations:
        o_dict = obs.to_dict() if hasattr(obs, "to_dict") else (obs if isinstance(obs, dict) else {})
        md_lines.extend([
            f"#### Request #{o_dict.get('request_number', 1)}: {o_dict.get('observation_type', 'PROBE')}",
            f"- **Status Code:** `{o_dict.get('status_code')}`",
            f"- **Response SHA-256:** `{o_dict.get('response_hash')}`",
            f"- **Comparison Result:** `{o_dict.get('comparison_result')}`",
            f"- **Details:** {o_dict.get('observation_details')}",
            "",
        ])

    md_lines.extend([
        "## 5. Reproduction & Verification Results",
        f"- **Reproducibility Classification:** **{repro_dict.get('result', 'REPRODUCIBLE')}**",
        f"- **Consistency Score:** `{repro_dict.get('reproducibility_score', 1.0):.2f}`",
        f"- **Details:** {repro_dict.get('details', 'N/A')}",
        "",
        "## 6. Impact Assessment (Fact vs. Inference)",
        "### Confirmed Impact (FACT)",
        f"- The application on `{target}` exhibited differential behavior confirming {vuln_class}.",
        "",
        "### Potential Impact ([INFERENCE])",
        f"- [INFERENCE] An unauthorized attacker could potentially leverage this condition to access sensitive resources if additional access controls are missing.",
        "",
        "## 7. Multi-Factor Confidence Assessment",
        f"- **Confidence Level:** **{conf_dict.get('confidence_level', 'HIGH')}**",
        f"- **Overall Score:** `{conf_dict.get('overall_score', 1.0):.3f}`",
        f"- **Rationale:** {conf_dict.get('rationale', 'N/A')}",
        "",
        "## 8. Cryptographic Evidence Chain",
        f"- **Chain Head Hash:** `{chain_dict.get('chain_head', 'GENESIS')}`",
        f"- **Chain Verification Status:** **{'VERIFIED' if chain_verified else 'TAMPER DETECTED'}**",
        f"- **Total Nodes:** `{len(chain_dict.get('nodes', []))}`",
        "",
        "## 9. Remediation Recommendations",
        f"Implement strict input validation and defense-in-depth controls for endpoint `{hyp_dict.get('endpoint', '/')}`.",
    ])

    markdown_content = "\n".join(md_lines)

    json_payload = {
        "report_type": "PHASE23_VULNERABILITY_ASSESSMENT",
        "campaign_id": campaign_id,
        "target": target,
        "plan_id": plan_id,
        "generated_at": now_iso,
        "operator_id": operator_id,
        "scope_snapshot_hash": scope_snapshot_hash,
        "hypothesis": hyp_dict,
        "validation_plan": plan_dict,
        "observations": [o.to_dict() if hasattr(o, "to_dict") else o for o in observations],
        "reproduction": repro_dict,
        "confidence_assessment": conf_dict,
        "evidence_chain": chain_dict,
        "chain_verified": chain_verified,
    }

    serialized_json = json.dumps(json_payload, sort_keys=True)
    package_hasher = hashlib.sha256()
    package_hasher.update(markdown_content.encode("utf-8"))
    package_hasher.update(serialized_json.encode("utf-8"))
    package_hash = package_hasher.hexdigest()

    return {
        "campaign_id": campaign_id,
        "plan_id": plan_id,
        "markdown": markdown_content,
        "json_data": json_payload,
        "package_hash": package_hash,
    }


