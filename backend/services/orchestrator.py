"""Scan pipeline orchestrator — runs all 9 agents in sequence."""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from backend.agents.auth_agent import AuthAgent
from backend.agents.bugbounty_agent import BugBountyAgent
from backend.agents.exploit_chain_agent import ExploitChainAgent
from backend.agents.impact_agent import ImpactAgent
from backend.agents.learning_agent import LearningAgent
from backend.agents.recon_agent import ReconAgent
from backend.agents.remediation_agent import RemediationAgent
from backend.agents.report_agent import ReportAgent
from backend.agents.scope_agent import ScopeAgent
from backend.agents.verify_agent import VerifyAgent
from backend.agents.vulnerability_testing_agent import VulnerabilityTestingAgent
from backend.agents.base_agent import ScanCancelledException, BaseAgent
from backend.core.encryption import encrypt_data
from backend.core.redis_client import set_scan_status
from backend.models.database import Scan, ScanConfig, get_session_factory
from backend.services.db_service import AuditLogRepository

async def _run_with_retry(agent: BaseAgent, max_retries: int = 2) -> None:
    for attempt in range(max_retries + 1):
        try:
            result = await agent.run()
            if isinstance(result, dict) and "error" in result:
                raise Exception(result["error"])
            return
        except ScanCancelledException:
            raise
        except Exception as e:
            if attempt == max_retries:
                raise e
            import logging
            logging.warning(f"Agent {agent.__class__.__name__} failed (attempt {attempt + 1}). Retrying...: {e}")
            await asyncio.sleep(2 ** attempt)


async def run_scan_pipeline(scan_id: str, config: dict[str, Any]) -> None:
    """Execute the full 9-agent pipeline for a scan."""
    factory = get_session_factory()
    db = factory()

    try:
        scan = db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            return

        scan.status = "running"
        db.commit()
        await set_scan_status(scan_id, "running")

        AuditLogRepository.log_event(db, "scan_orchestrator", "scan_started", "system", json.dumps({"scan_id": scan_id, "target": scan.target_url}))

        agent_config = {**config, "scan_id": scan_id}

        # Phase 0: Scope authorization gating
        await _run_with_retry(ScopeAgent(scan_id, db, agent_config))

                # Phase 1: Recon + Auth (sequential)
        recon_agent = ReconAgent(scan_id, db, agent_config)
        await _run_with_retry(recon_agent)
        auth_agent = AuthAgent(scan_id, db, agent_config)
        await _run_with_retry(auth_agent)

        # Phase 2: Vuln testing + Learning (parallel)
        learning_task = asyncio.create_task(
            _run_with_retry(LearningAgent(scan_id, db, agent_config))
        )
        vuln_agent = VulnerabilityTestingAgent(scan_id, db, agent_config)
        vuln_agent.recon_snapshot = getattr(recon_agent, "recon_snapshot", None)
        vuln_agent.shared_auth_context = getattr(auth_agent, "shared_context", None)
        await _run_with_retry(vuln_agent)

        # Phase 3: Verification
        await _run_with_retry(VerifyAgent(scan_id, db, agent_config))

        # Phase 4: Exploit chain analysis
        await _run_with_retry(ExploitChainAgent(scan_id, db, agent_config))

        # Wait for learning to finish
        await learning_task

        # Phase 5: AI agents + Report (sequential)
        await _run_with_retry(RemediationAgent(scan_id, db, agent_config))
        await _run_with_retry(ImpactAgent(scan_id, db, agent_config))
        await _run_with_retry(ReportAgent(scan_id, db, agent_config))

        # Phase 5: Bug bounty (optional)
        if config.get("scan_mode") == "bugbounty":
            await _run_with_retry(BugBountyAgent(scan_id, db, agent_config))

        scan.status = "complete"
        scan.completed_at = datetime.now(timezone.utc)
        scan.risk_score = _calculate_risk_score(db, scan_id)
        db.commit()
        await set_scan_status(scan_id, "complete")
        
        AuditLogRepository.log_event(db, "scan_orchestrator", "scan_completed", "system", json.dumps({"scan_id": scan_id}))

    except ScanCancelledException:
        scan = db.query(Scan).filter_by(id=scan_id).first()
        if scan:
            scan.status = "cancelled"
            db.commit()
            AuditLogRepository.log_event(db, "scan_orchestrator", "scan_cancelled", "system", json.dumps({"scan_id": scan_id}))
        await set_scan_status(scan_id, "cancelled")
    except Exception as e:
        scan = db.query(Scan).filter_by(id=scan_id).first()
        if scan:
            scan.status = "error"
            db.commit()
            AuditLogRepository.log_event(db, "scan_orchestrator", "scan_error", "system", json.dumps({"scan_id": scan_id, "error": str(e)}))
        await set_scan_status(scan_id, "error")
    finally:
        db.close()


def _calculate_risk_score(db: Session, scan_id: str) -> int:
    from backend.models.database import Finding

    findings = (
        db.query(Finding)
        .filter_by(scan_id=scan_id, false_positive=False)
        .all()
    )
    weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}
    score = sum(weights.get(str(f.severity), 0) for f in findings)
    return min(score, 100)


def save_scan_config(db: Session, scan_id: str, config: dict[str, Any]) -> None:
    """Encrypt and store scan credentials."""
    scan_config = ScanConfig(
        scan_id=scan_id,
        two_fa_type=config.get("two_fa_type", "none"),
    )

    if config.get("primary_creds"):
        scan_config.primary_creds = encrypt_data(config["primary_creds"])  # type: ignore
    if config.get("secondary_creds"):
        scan_config.secondary_creds = encrypt_data(config["secondary_creds"])  # type: ignore
    if config.get("email_creds"):
        scan_config.email_creds = encrypt_data(config["email_creds"])  # type: ignore
    if config.get("two_fa_config"):
        scan_config.two_fa_config = encrypt_data(config["two_fa_config"])  # type: ignore
    if config.get("api_auth"):
        scan_config.api_auth = encrypt_data(config["api_auth"])  # type: ignore
    if config.get("authorization_confirmed") is not None:
        scan_config.authorization_confirmed = config["authorization_confirmed"]  # type: ignore
    if config.get("scope_notes") is not None:
        scan_config.authorization_notes = config["scope_notes"]
    if config.get("program_id"):
        scan_config.program_id = config["program_id"]
    if config.get("rate_limit_rps") is not None:
        scan_config.rate_limit_rps = config["rate_limit_rps"]
    if config.get("max_concurrency") is not None:
        scan_config.max_concurrency = config["max_concurrency"]

    db.add(scan_config)
    db.commit()
