import json
from backend.models.database import Finding, Scan, AgentLog, get_session_factory, init_db
from backend.persistence.models import AuditTrailEvent, EvidenceRecord

init_db()
factory = get_session_factory()
db = factory()

scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(3).all()
for scan in scans:
    print("="*80)
    print(f"Scan ID: {scan.id} | Target: {scan.target_url} | Status: {scan.status} | Risk: {scan.risk_score}")
    print("="*80)
    
    # 1. Findings
    findings = db.query(Finding).filter_by(scan_id=scan.id).all()
    print(f"\n[FINDINGS - Total: {len(findings)}]")
    for f in findings:
        print(f"  - [{f.verdict}] {f.title} ({f.vuln_type}) | Severity: {f.severity} | URL: {f.affected_url} | Param: {f.affected_param} | Status: {f.verification_status}")
        
    # 2. Recon Agent Logs
    agent_logs = db.query(AgentLog).filter_by(scan_id=scan.id, agent_id=1).all()
    print(f"\n[RECON AGENT LOGS - Total: {len(agent_logs)}]")
    for i, log in enumerate(agent_logs):
        try:
            d = json.loads(log.message)
            obs = d.get("observations", [])
            print(f"  Log #{i+1}: Observation Count: {len(obs)} | Tools: {list(d.get('tool_results', {}).keys())}")
            endpoints = [o.get("normalized_value") for o in obs if o.get("category") in ("ENDPOINT", "DIRECTORY", "HISTORICAL_URL")]
            params = [o.get("normalized_value") for o in obs if o.get("category") == "PARAMETER"]
            print(f"    Endpoints ({len(endpoints)}): {endpoints[:8]}")
            print(f"    Parameters ({len(params)}): {sorted(list(set(params)))}")
        except Exception as e:
            print(f"  Log #{i+1}: {log.message[:100]}... (parse error: {e})")
            
    # 3. Audit Trail Events
    audit_events = db.query(AuditTrailEvent).filter_by(campaign_id=scan.id).all()
    print(f"\n[AUDIT EVENTS - Total: {len(audit_events)}]")
    hypotheses = []
    verifications = []
    for ev in audit_events:
        meta = json.loads(ev.metadata_json) if ev.metadata_json else {}
        if ev.event_type == "HYPOTHESIS_CREATED":
            hypotheses.append(meta)
        elif ev.event_type in ("VERIFICATION_COMPLETED", "FINDING_CREATED"):
            verifications.append((ev.event_type, meta))
            
    print(f"  Hypotheses Created ({len(hypotheses)}):")
    for h in hypotheses:
        print(f"    - Check: {h.get('check_id')} | Target: {h.get('target_url')} | Test: {h.get('test_id')}")
        
    print(f"  Verifications ({len(verifications)}):")
    for vtype, meta in verifications:
        print(f"    - [{vtype}] Check: {meta.get('check_id')} | Target: {meta.get('target_url')} | Status: {meta.get('status')} | Reason: {meta.get('reason')}")

db.close()
