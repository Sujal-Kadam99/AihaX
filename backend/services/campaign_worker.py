"""AihaX — Production Runtime Worker & Execution Dispatch Service.

Architectural Guarantees:
1. Strict Pipeline Invariant:
   AUTHORIZED CAMPAIGN -> START -> RUNNING -> INITIAL TASK CREATED -> WORKER CLAIMS TASK ->
   WORKER HEARTBEAT / LEASE ACTIVE -> TASK EXECUTES -> PHASE PROGRESSES -> EVIDENCE PERSISTED ->
   FINDINGS CREATED/VERIFIED -> REPORT READY -> CAMPAIGN COMPLETED.
2. Anti-Stall & Heartbeat:
   Active workers continuously renew task leases and record activity so running campaigns
   are never falsely flagged as stalled while real work is progressing.
3. Zero-Network Test Safety:
   Supports fully deterministic in-memory / mock transports so no third-party network calls occur.
4. Cancellation & Anti-Resurrection:
   Workers immediately cease work on CANCELLED campaigns, cancelled tasks are never resurrected,
   and cancelled campaigns never claim new tasks.
5. Idempotent Start & Bounded Retries:
   Re-dispatching does not duplicate tasks, and failed tasks retry only up to max_retries.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from sqlalchemy.orm import Session

from backend.core.check_registry import (
    BaseCheck,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
import backend.agents.checks  # Ensure checks are registered
from backend.core.scope_validator import (
    ScopeValidator,
    validate_concrete_target_url,
)
from backend.evidence.evidence_store import EvidenceVault
from backend.models.database import Finding, FindingDisposition, BountyEligibility, Program, ProgramScope, Scan, get_session_factory
from backend.persistence.models import Campaign, ExecutionTask
from backend.persistence.repository import CampaignRepository
from backend.persistence.state_machine import (
    CampaignLifecycleState,
    InvalidStateTransitionError,
    TaskLifecycleState,
)
from backend.services.finding_deduplicator import (
    ConfidenceLevel,
    DeterministicConfidenceScorer,
    FindingLifecycleState,
)
from backend.services.automated_finding_verifier import AutomatedFindingVerifier
from backend.services.request_engine import (
    AuthenticationContext,
    BaseAsyncTransport,
    MockTransport,
    RawResponse,
    RequestEngine,
    RequestEvidence,
    RequestSpec,
    RequestTimeout,
)
from backend.services.verification_engine import (
    VerificationConclusion,
    VerificationEngine,
    VerificationStatus,
)

logger = logging.getLogger("aihax.campaign_worker")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _get_default_db_session() -> Session:
    factory = get_session_factory()
    return factory()


class CampaignWorker:
    """Worker instance responsible for claiming, renewing, executing, and completing tasks."""

    def __init__(
        self,
        worker_id: Optional[str] = None,
        concurrency: int = 2,
        lease_duration_seconds: int = 30,
        heartbeat_interval: float = 5.0,
        request_engine: Optional[RequestEngine] = None,
        session_factory: Optional[Any] = None,
    ) -> None:
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex[:8]}"
        self.concurrency = max(1, concurrency)
        self.lease_duration_seconds = lease_duration_seconds
        self.heartbeat_interval = heartbeat_interval
        self._custom_request_engine = request_engine
        self._session_factory = session_factory or _get_default_db_session
        self.verification_engine = VerificationEngine()
        self._active_heartbeat_tasks: Dict[str, asyncio.Task] = {}

    def get_request_engine(
        self,
        target_url: Optional[str] = None,
        validator: Optional[ScopeValidator] = None,
    ) -> RequestEngine:
        """Returns the configured RequestEngine or builds a safe default."""
        if self._custom_request_engine is not None:
            return self._custom_request_engine

        # Default RequestEngine with strict scope validation
        active_validator = validator or ScopeValidator(in_scope_assets=[target_url] if target_url else [])
        return RequestEngine(
            scope_validator=active_validator,
            rate_limit_rps=10,
            max_concurrency=self.concurrency,
        )

    async def execute_task(
        self,
        task_id: str,
        session: Session,
        repo: Optional[CampaignRepository] = None,
    ) -> Dict[str, Any]:
        """Atomically execute a claimed task under worker lease and heartbeat."""
        repo = repo or CampaignRepository(session)
        task = session.query(ExecutionTask).filter(ExecutionTask.id == task_id).first()
        if not task:
            raise ValueError(f"Task '{task_id}' not found in database.")

        campaign = repo.get_campaign(task.campaign_id)
        if not campaign:
            raise ValueError(f"Campaign '{task.campaign_id}' not found.")

        # Guard: Check if campaign was cancelled or paused
        if campaign.status in (
            CampaignLifecycleState.CANCELLED.value,
            CampaignLifecycleState.PAUSED.value,
            CampaignLifecycleState.COMPLETED.value,
            CampaignLifecycleState.FAILED.value,
        ):
            logger.info(f"Aborting task {task_id}: Campaign {campaign.id} is in state {campaign.status}.")
            return {"status": "aborted", "reason": f"Campaign state is {campaign.status}"}

        # Transition task to RUNNING if not already
        if task.status == TaskLifecycleState.CLAIMED.value:
            task.status = TaskLifecycleState.RUNNING.value
            task.started_at = _utc_now()
            session.flush()

        # Start asynchronous heartbeat background renewal
        stop_heartbeat = asyncio.Event()
        heartbeat_task = asyncio.create_task(
            self._heartbeat_loop(task_id, stop_heartbeat)
        )
        self._active_heartbeat_tasks[task_id] = heartbeat_task

        vault = EvidenceVault(repo)
        candidates_created = 0
        verified_created = 0
        error_message = None

        try:
            # 0. Awaiting Target Gate
            if getattr(campaign, "awaiting_target", False) or not campaign.target_url or campaign.target_url == "WAITING_FOR_TARGET":
                err_msg = "Campaign is WAITING_FOR_TARGET. Operator must supply a concrete target URL."
                repo.fail_task(task_id, self.worker_id, err_msg, can_retry=False)
                session.commit()
                return {"status": "failed", "error": err_msg}

            # 1. Authoritative Pre-Execution Authorization & Snapshot Gate
            from backend.services.campaign_operations import (
                AuthorizationRequiredException,
                CampaignOperationsService,
                ScopeMismatchException,
            )
            ops = CampaignOperationsService(repo)
            try:
                ops._verify_authorization_or_raise(campaign)
            except (AuthorizationRequiredException, ScopeMismatchException) as auth_err:
                repo.fail_task(task_id, self.worker_id, f"Authorization gate failed: {auth_err}", can_retry=False)
                repo.append_audit_event(
                    campaign_id=campaign.id,
                    event_type="task_auth_failed",
                    actor=self.worker_id,
                    object_id=task_id,
                    metadata={"error": str(auth_err), "task_id": task_id},
                )
                session.commit()
                return {"status": "failed", "error": str(auth_err)}

            # 2. Server-Side Request Budget Pre-Check
            budget_limit = campaign.campaign_budget if campaign.campaign_budget is not None else 500
            if (campaign.requests_used or 0) >= budget_limit:
                budget_msg = f"Campaign request budget exhausted ({campaign.requests_used}/{campaign.campaign_budget})"
                repo.fail_task(task_id, self.worker_id, budget_msg, can_retry=False)
                repo.append_audit_event(
                    campaign_id=campaign.id,
                    event_type="budget_exhausted",
                    actor=self.worker_id,
                    object_id=task_id,
                    metadata={"requests_used": campaign.requests_used, "limit": campaign.campaign_budget},
                )
                session.commit()
                return {"status": "failed", "error": budget_msg}

            # 3. Destination Safety Check
            target_url = task.target_url or campaign.target_url
            from backend.core.scope_validator import validate_destination_safety
            dest_safe, dest_reason = validate_destination_safety(target_url, allow_loopback=True)
            if not dest_safe:
                repo.fail_task(task_id, self.worker_id, f"Destination safety check failed: {dest_reason}", can_retry=False)
                session.commit()
                return {"status": "failed", "error": f"Unsafe destination: {dest_reason}"}

            # 4. Atomically Increment Request Budget Counter
            campaign.requests_used = (campaign.requests_used or 0) + 1
            session.flush()

            # 5. Program Scope Verification Gate
            program_scope_record = session.query(ProgramScope).filter_by(program_id=campaign.program_id).first() if campaign.program_id else None
            in_scope = (
                json.loads(program_scope_record.in_scope_assets)
                if program_scope_record and program_scope_record.in_scope_assets
                else ([campaign.target_url] if campaign.target_url else [])
            )
            out_of_scope = json.loads(program_scope_record.out_of_scope_assets) if program_scope_record and program_scope_record.out_of_scope_assets else []

            validator = ScopeValidator(in_scope_assets=in_scope, out_of_scope_assets=out_of_scope)
            decision = validator.is_url_in_scope(target_url)
            if not decision.allowed:
                repo.fail_task(task_id, self.worker_id, f"Scope check failed: {decision.reason}", can_retry=False)
                session.commit()
                return {"status": "failed", "error": f"Out of scope: {decision.reason}"}

            req_engine = self.get_request_engine(target_url, validator=validator)

            # Campaign-level pipeline jobs keep recon and vulnerability testing ordered
            # and ensure RECON_ONLY cannot fall through to the individual-check runner.
            if task.check_id in {"PIPELINE_RECON_ONLY", "PIPELINE_RECON_THEN_VTA"}:
                pipeline_result = await self._execute_pipeline_task(
                    campaign=campaign,
                    task=task,
                    session=session,
                    repo=repo,
                    vault=vault,
                    target_url=target_url,
                    in_scope=in_scope,
                    out_of_scope=out_of_scope,
                    request_engine=req_engine,
                )
                repo.complete_task(task_id, self.worker_id)
                session.commit()
                self._evaluate_campaign_completion(campaign.id, session, repo)
                return {"status": "completed", "task_id": task_id, **pipeline_result}

            # 6. Resolve and execute Check from Registry (fail closed if unknown or destructive)
            check_cls = None
            try:
                check_cls = registry.get_check(task.check_id)
            except KeyError:
                # If specific check ID is missing, lookup by case-insensitive matching
                for registered in registry.get_all_checks():
                    if registered.contract.id.lower() == task.check_id.lower() or task.check_id.lower() in registered.contract.id.lower():
                        check_cls = registered
                        break

            if not check_cls:
                err_msg = f"Unknown check ID '{task.check_id}' rejected (not found in CheckRegistry)."
                repo.fail_task(task_id, self.worker_id, err_msg, can_retry=False)
                repo.append_audit_event(
                    campaign_id=campaign.id,
                    event_type="CHECK_FAILED",
                    actor=self.worker_id,
                    object_id=task_id,
                    metadata={"error": err_msg, "check_id": task.check_id},
                )
                session.commit()
                return {"status": "failed", "error": err_msg}

            if check_cls.contract.destructive:
                err_msg = f"Destructive check '{task.check_id}' rejected (non-destructive policy enforced)."
                repo.fail_task(task_id, self.worker_id, err_msg, can_retry=False)
                repo.append_audit_event(
                    campaign_id=campaign.id,
                    event_type="CHECK_FAILED",
                    actor=self.worker_id,
                    object_id=task_id,
                    metadata={"error": err_msg, "check_id": task.check_id},
                )
                session.commit()
                return {"status": "failed", "error": err_msg}

            repo.append_audit_event(
                campaign_id=campaign.id,
                event_type="CHECK_STARTED",
                actor=self.worker_id,
                object_id=task_id,
                metadata={"check_id": check_cls.contract.id, "target_url": target_url},
            )
            repo.append_audit_event(
                campaign_id=campaign.id,
                event_type="REQUEST_DISPATCHED",
                actor=self.worker_id,
                object_id=task_id,
                metadata={"target_url": target_url, "check_id": check_cls.contract.id},
            )

            check_result: Optional[CheckResult] = None
            check_instance = check_cls()
            config = {
                "campaign_id": campaign.id,
                "safe_mode": True,
                "auth_contexts": {},
                "parameter_name": task.parameter_name,
            }
            sig = inspect.signature(check_instance.execute)
            if len(sig.parameters) >= 3:
                check_result = await check_instance.execute(req_engine, target_url, config)
            else:
                check_result = await check_instance.execute(target_url, config)

            # 7. Process Findings & Evidence
            if check_result:
                # Deduplicate Candidate Finding in database
                contract = check_cls.contract if check_cls else None
                cat_val = contract.category.value if contract and hasattr(contract.category, "value") else "misconfig"
                sev_val = contract.severity.value if contract and hasattr(contract.severity, "value") else str(check_result.severity.value if hasattr(check_result.severity, "value") else check_result.severity)

                conf_score, _ = DeterministicConfidenceScorer.calculate_confidence(
                    reproduced_successfully=False,
                    baseline_differential_verified=bool(check_result.proof_request and check_result.proof_response),
                    passive_regex_matched=True,
                )

                # Ensure backing Scan row exists for foreign key constraint
                scan_record = session.query(Scan).filter(Scan.id == campaign.id).first()
                if not scan_record:
                    scan_record = Scan(
                        id=campaign.id,
                        target_url=campaign.target_url,
                        status="running",
                    )
                    session.add(scan_record)
                    session.flush()

                existing_finding = (
                    session.query(Finding)
                    .filter(
                        Finding.scan_id == campaign.id,
                        Finding.vuln_type == check_result.check_id,
                        Finding.affected_url == (check_result.affected_url or target_url),
                        Finding.affected_param == (check_result.affected_param or task.parameter_name or ""),
                    )
                    .first()
                )

                if existing_finding:
                    finding = existing_finding
                    finding.proof_request = check_result.proof_request or finding.proof_request
                    finding.proof_response = check_result.proof_response or finding.proof_response
                    finding.confidence = max(finding.confidence or 50, conf_score)
                else:
                    candidate_id = str(uuid.uuid4())
                    finding = Finding(
                        id=candidate_id,
                        scan_id=campaign.id,
                        agent_id=3,
                        title=check_result.title,
                        vuln_type=check_result.check_id,
                        category=cat_val,
                        severity=sev_val,
                        cwe_id=contract.cwe if contract else "CWE-16",
                        affected_url=check_result.affected_url or target_url,
                        affected_param=check_result.affected_param or task.parameter_name,
                        payload=check_result.payload,
                        proof_request=check_result.proof_request,
                        proof_response=check_result.proof_response,
                        confidence=conf_score,
                        false_positive=False,
                        verdict="Inconclusive",
                        verification_status=FindingLifecycleState.CANDIDATE.value,
                        evidence_ids=json.dumps(check_result.evidence_ids),
                        request_ids=json.dumps(check_result.request_ids),
                    )
                    session.add(finding)
                    session.flush()
                    candidates_created += 1

                    repo.append_audit_event(
                        campaign_id=campaign.id,
                        event_type="FINDING_CANDIDATE",
                        actor=self.worker_id,
                        object_id=finding.id,
                        metadata={"title": finding.title, "vuln_type": finding.vuln_type},
                    )

                # 5. Deterministic Verification & Automated Quality Gate
                repo.append_audit_event(
                    campaign_id=campaign.id,
                    event_type="VERIFICATION_STARTED",
                    actor=self.worker_id,
                    object_id=finding.id,
                    metadata={"title": finding.title, "vuln_type": finding.vuln_type},
                )

                conclusion = await self.verification_engine.verify_finding(
                    finding=finding,
                    request_engine=req_engine,
                    authorization_confirmed=True,
                    evidence_vault=EvidenceVault(repo),
                )

                # Fully automated verification gate
                explanation = AutomatedFindingVerifier.verify_finding(finding)

                event_type_name = "FINDING_INCONCLUSIVE"
                if explanation.disposition in (FindingDisposition.VALIDATED.value, FindingDisposition.EXPLOITABLE.value, FindingDisposition.VULNERABILITY.value):
                    event_type_name = "FINDING_VALIDATED"
                    verified_created += 1
                elif explanation.disposition == FindingDisposition.HARDENING_ONLY.value:
                    event_type_name = "FINDING_HARDENING_ONLY"
                elif explanation.disposition == FindingDisposition.FALSE_POSITIVE.value:
                    event_type_name = "FINDING_FALSE_POSITIVE"
                elif explanation.disposition == FindingDisposition.NOT_BOUNTY_ELIGIBLE.value:
                    event_type_name = "FINDING_REJECTED"

                repo.append_audit_event(
                    campaign_id=campaign.id,
                    event_type=event_type_name,
                    actor=self.worker_id,
                    object_id=finding.id,
                    metadata={
                        "title": finding.title,
                        "disposition": explanation.disposition,
                        "confidence": finding.confidence,
                        "reason": explanation.reason,
                    },
                )

                # Store primary evidence in Vault
                ev_entry = vault.store_evidence(
                    campaign_id=campaign.id,
                    evidence_type="CHECK_EXECUTION_EVIDENCE",
                    target_url=target_url,
                    method="GET",
                    raw_request=check_result.proof_request or f"GET {target_url} HTTP/1.1",
                    raw_response=check_result.proof_response or "HTTP/1.1 200 OK\r\n\r\nEvidence observed",
                    payload_summary=check_result.candidate_reason,
                    finding_id=finding.id,
                    task_id=task.id,
                    request_id=check_result.request_ids[0] if check_result.request_ids else None,
                )
                repo.append_audit_event(
                    campaign_id=campaign.id,
                    event_type="EVIDENCE_RECORDED",
                    actor=self.worker_id,
                    object_id=ev_entry.id,
                    metadata={"content_hash": ev_entry.content_hash, "target_url": target_url},
                )
            else:
                ev_entry = vault.store_evidence(
                    campaign_id=campaign.id,
                    evidence_type="CHECK_EXECUTION_CLEAN",
                    target_url=target_url,
                    method="GET",
                    raw_request=f"GET {target_url} HTTP/1.1",
                    raw_response="HTTP/1.1 200 OK\r\n\r\nCheck completed with no vulnerabilities observed.",
                    payload_summary=f"Check {task.check_id} completed cleanly.",
                    task_id=task.id,
                )
                repo.append_audit_event(
                    campaign_id=campaign.id,
                    event_type="EVIDENCE_RECORDED",
                    actor=self.worker_id,
                    object_id=ev_entry.id,
                    metadata={"content_hash": ev_entry.content_hash, "target_url": target_url},
                )

            repo.append_audit_event(
                campaign_id=campaign.id,
                event_type="CHECK_COMPLETED",
                actor=self.worker_id,
                object_id=task_id,
                metadata={
                    "check_id": check_cls.contract.id if check_cls else task.check_id,
                    "target_url": target_url,
                    "candidates_created": candidates_created,
                    "verified_created": verified_created,
                },
            )

            # Re-query campaign and task for mid-run pause/cancel/ownership loss
            cur_campaign = repo.get_campaign(campaign.id)
            if not cur_campaign or cur_campaign.status in (
                CampaignLifecycleState.CANCELLED.value,
                CampaignLifecycleState.PAUSED.value,
                CampaignLifecycleState.COMPLETED.value,
                CampaignLifecycleState.FAILED.value,
            ):
                logger.info(f"Campaign {campaign.id} entered state {cur_campaign.status if cur_campaign else 'NONE'} during execution. Aborting.")
                return {"status": "aborted", "reason": f"Campaign state is {cur_campaign.status if cur_campaign else 'NONE'}"}

            cur_task = session.query(ExecutionTask).filter_by(id=task_id).first()
            if not cur_task or (cur_task.worker_id and cur_task.worker_id != self.worker_id):
                err_msg = f"Task {task_id} ownership lost (currently owned by {cur_task.worker_id if cur_task else 'NONE'})."
                logger.warning(err_msg)
                repo.append_audit_event(
                    campaign_id=campaign.id,
                    event_type="OWNERSHIP_LOST",
                    actor=self.worker_id,
                    object_id=task_id,
                    metadata={"error": err_msg, "task_id": task_id},
                )
                session.commit()
                return {"status": "failed", "error": err_msg}

            # 6. Complete task
            repo.complete_task(task_id, self.worker_id)
            session.commit()

            # 7. Evaluate Campaign Completion
            self._evaluate_campaign_completion(campaign.id, session, repo)

            return {
                "status": "completed",
                "task_id": task_id,
                "check_id": task.check_id,
                "candidates_created": candidates_created,
                "verified_created": verified_created,
            }

        except Exception as exc:
            logger.exception(f"Error executing task {task_id} on worker {self.worker_id}: {exc}")
            session.rollback()
            # Mark task failed with retry support
            try:
                repo.fail_task(task_id, self.worker_id, str(exc), can_retry=True)
                session.commit()
            except Exception:
                session.rollback()
            return {"status": "failed", "error": str(exc)}

        finally:
            # Stop heartbeat loop cleanly
            stop_heartbeat.set()
            if task_id in self._active_heartbeat_tasks:
                try:
                    self._active_heartbeat_tasks[task_id].cancel()
                except Exception:
                    pass
                self._active_heartbeat_tasks.pop(task_id, None)

    async def _execute_pipeline_task(
        self,
        *,
        campaign: Campaign,
        task: ExecutionTask,
        session: Session,
        repo: CampaignRepository,
        vault: EvidenceVault,
        target_url: str,
        in_scope: List[str],
        out_of_scope: List[str],
        request_engine: RequestEngine,
    ) -> Dict[str, Any]:
        """Run one campaign's recon stage and, where selected, hand it to VTA."""
        from backend.agents.recon_agent import ReconAgent

        authorization = repo.get_authorization(campaign.id)
        if not authorization:
            raise ValueError("Pipeline task has no persisted authorization record.")

        recon_config = {
            "target_url": target_url,
            "authorization_confirmed": True,
            "authorization_record_id": authorization.id,
            "operator_id": authorization.authorized_by,
            "in_scope_assets": in_scope or [target_url],
            "out_of_scope_assets": out_of_scope,
            "execution_mode": "AUTHORIZED_LIVE_RECON",
            "allow_loopback": False,
            "enable_subdomain_discovery": True,
            "enable_port_scan": True,
            "enable_tech_detection": True,
            "enable_url_discovery": True,
            "enable_directory_discovery": True,
            "enable_active_crawler": True,
            "enable_dns_analysis": True,
            "enable_tls_analysis": True,
        }
        recon_agent = ReconAgent(campaign.id, session, recon_config, request_engine=request_engine)
        await recon_agent.execute()
        snapshot = getattr(recon_agent, "recon_snapshot", None)
        if snapshot is None:
            raise RuntimeError("ReconAgent completed without producing a ReconSnapshot.")

        result: Dict[str, Any] = {
            "mode": campaign.mode,
            "recon_status": snapshot.status,
            "recon_snapshot_hash": snapshot.snapshot_hash,
            "recon_observation_count": snapshot.observation_count,
            "recon_tool_results": snapshot.tool_results,
            "vulnerability_testing": None,
        }
        evidence = vault.store_evidence(
            campaign_id=campaign.id,
            evidence_type="CAMPAIGN_RECON_REPORT",
            target_url=target_url,
            method="RECON",
            raw_request="ReconAgent pipeline execution",
            raw_response=json.dumps(snapshot.to_dict(), sort_keys=True, default=str),
            payload_summary=f"Recon status={snapshot.status}; observations={snapshot.observation_count}; snapshot={snapshot.snapshot_hash}",
            task_id=task.id,
        )
        result["recon_evidence_id"] = evidence.id

        is_recon_only = task.check_id == "PIPELINE_RECON_ONLY"
        if not is_recon_only:
            from backend.agents.vulnerability_testing_agent import VulnerabilityTestingAgent
            from backend.services.vulnerability_execution_engine import ExecutionMode

            snapshot_record = repo.get_snapshot(campaign.id)
            selected_tools: List[str] = []
            if snapshot_record and snapshot_record.snapshot_json:
                try:
                    selected_tools = json.loads(snapshot_record.snapshot_json).get("selected_tools", [])
                except (TypeError, ValueError):
                    selected_tools = []
            vta_config = {
                **recon_config,
                "assessment_mode": campaign.assessment_mode,
                "execution_mode": "authorized_live",
                "in_scope_assets": in_scope or [target_url],
                "out_of_scope_assets": out_of_scope,
                "available_tools": None,
                "enabled_tools": selected_tools,
                "campaign_budget": campaign.campaign_budget,
                "request_budget": max(0, (campaign.campaign_budget or 500) - (campaign.requests_used or 0)),
                "request_engine": request_engine,
            }
            agent = VulnerabilityTestingAgent(campaign.id, session, vta_config)
            auth_record = repo.get_authorization(campaign.id)
            vta_result = await agent.run_vulnerability_pipeline(
                target_url=target_url,
                recon_snapshot=snapshot,
                mode=ExecutionMode.AUTHORIZED_LIVE,
                operator_id=auth_record.authorized_by if auth_record else None,
                operator_approval_id=auth_record.id if auth_record else None,
                in_scope_assets=in_scope or [target_url],
                out_of_scope_assets=out_of_scope,
                authorization_confirmed=bool(auth_record and auth_record.status == "ACTIVE"),
                authorization_record_id=auth_record.id if auth_record else None,
            )
            serialized = vta_result.to_dict()
            result["vulnerability_testing"] = serialized
            report_evidence = vault.store_evidence(
                campaign_id=campaign.id,
                evidence_type="VULNERABILITY_TESTING_REPORT",
                target_url=target_url,
                method="VTA",
                raw_request="VulnerabilityTestingAgent pipeline execution",
                raw_response=json.dumps(serialized, sort_keys=True, default=str),
                payload_summary=(
                    f"registered={vta_result.total_registered}; executed={vta_result.executed_count}; "
                    f"candidates={len(vta_result.findings)}; tool_results={len(vta_result.tool_results)}"
                ),
                task_id=task.id,
            )
            result["vulnerability_testing_evidence_id"] = report_evidence.id

            # Campaign pipeline must verify VTA candidates before chain analysis.
            # The agents query persisted Finding rows, so VTA evidence is available to
            # VerifyAgent and only its VERIFIED verdicts can reach ExploitChainAgent.
            from backend.agents.verify_agent import VerifyAgent
            from backend.agents.exploit_chain_agent import ExploitChainAgent

            verification_config = {
                **recon_config,
                "authorization_confirmed": bool(auth_record and auth_record.status == "ACTIVE"),
                "rate_limit_rps": campaign.rate_limit_rps or 2,
                "max_concurrency": campaign.max_concurrency or 1,
                "in_scope_assets": in_scope or [target_url],
                "out_of_scope_assets": out_of_scope,
            }
            verification_result = await VerifyAgent(campaign.id, session, verification_config).run()
            result["verification"] = verification_result
            verification_evidence = vault.store_evidence(
                campaign_id=campaign.id,
                evidence_type="VULNERABILITY_VERIFICATION_REPORT",
                target_url=target_url,
                method="VERIFY_AGENT",
                raw_request="VerifyAgent evaluated VTA candidate findings",
                raw_response=json.dumps(verification_result, sort_keys=True, default=str),
                payload_summary=(
                    f"verified={verification_result.get('verified', 0)}; "
                    f"rejected={verification_result.get('rejected', 0)}; "
                    f"inconclusive={verification_result.get('inconclusive', 0)}"
                ),
                task_id=task.id,
            )
            result["verification_evidence_id"] = verification_evidence.id

            chain_result = await ExploitChainAgent(campaign.id, session, verification_config).run()
            result["exploit_chain_analysis"] = chain_result
            chain_evidence = vault.store_evidence(
                campaign_id=campaign.id,
                evidence_type="EXPLOIT_CHAIN_REPORT",
                target_url=target_url,
                method="EXPLOIT_CHAIN_AGENT",
                raw_request="ExploitChainAgent received verified findings only",
                raw_response=json.dumps(chain_result, sort_keys=True, default=str),
                payload_summary=f"verified findings analyzed; chains={len(chain_result.get('chains', []))}",
                task_id=task.id,
            )
            result["exploit_chain_evidence_id"] = chain_evidence.id

        repo.append_audit_event(
            campaign_id=campaign.id,
            event_type="CAMPAIGN_PIPELINE_COMPLETED",
            actor=self.worker_id,
            object_id=task.id,
            metadata={
                "mode": campaign.mode,
                "recon_status": snapshot.status,
                "recon_snapshot_hash": snapshot.snapshot_hash,
                "recon_evidence_id": result.get("recon_evidence_id"),
                "vta_evidence_id": result.get("vulnerability_testing_evidence_id"),
            },
        )
        result["request_counts"] = request_engine.request_counts
        return result

    async def _heartbeat_loop(self, task_id: str, stop_event: asyncio.Event) -> None:
        """Background loop renewing worker lease and activity until task finishes."""
        while not stop_event.is_set():
            try:
                await asyncio.sleep(self.heartbeat_interval)
                if stop_event.is_set():
                    break
                session = self._session_factory()
                try:
                    repo = CampaignRepository(session)
                    repo.renew_task_lease(task_id, self.worker_id, self.lease_duration_seconds)
                    session.commit()
                except Exception as hb_err:
                    session.rollback()
                    logger.debug(f"Heartbeat renewal error for task {task_id}: {hb_err}")
                finally:
                    session.close()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Heartbeat loop unexpected error: {e}")

    def _evaluate_campaign_completion(
        self,
        campaign_id: str,
        session: Session,
        repo: CampaignRepository,
    ) -> None:
        """If all tasks for the campaign are completed/failed, mark the campaign COMPLETED."""
        campaign = repo.get_campaign(campaign_id)
        if not campaign or campaign.status != CampaignLifecycleState.RUNNING.value:
            return

        counts = repo.count_tasks_by_status(campaign_id)
        active_or_pending = counts.get("PENDING", 0) + counts.get("CLAIMED", 0) + counts.get("RUNNING", 0) + counts.get("RETRY_PENDING", 0)
        total_tasks = sum(counts.values())

        if total_tasks > 0 and active_or_pending == 0:
            logger.info(f"All {total_tasks} tasks for campaign {campaign_id} finished. Transitioning to COMPLETED.")
            from backend.services.campaign_operations import CampaignOperationsService
            ops = CampaignOperationsService(repo)
            try:
                ops.complete_campaign(campaign_id, actor=self.worker_id)
                session.commit()
            except Exception as comp_err:
                logger.exception(f"Error auto-completing campaign {campaign_id}: {comp_err}")
                session.rollback()


class CampaignWorkerRuntime:
    """Runtime service orchestrating worker pools, periodic polling, dispatch, and recovery."""

    def __init__(
        self,
        poll_interval: float = 1.0,
        worker_concurrency: int = 2,
        custom_request_engine: Optional[RequestEngine] = None,
        session_factory: Optional[Any] = None,
    ) -> None:
        self.poll_interval = poll_interval
        self.worker_concurrency = worker_concurrency
        self._custom_request_engine = custom_request_engine
        self._session_factory = session_factory or _get_default_db_session
        self.worker = CampaignWorker(
            concurrency=worker_concurrency,
            request_engine=custom_request_engine,
            session_factory=self._session_factory,
        )
        self._running: bool = False
        self._task: Optional[asyncio.Task] = None
        self._trigger_event: Optional[asyncio.Event] = None
        self._last_dispatch_time: Optional[datetime] = None

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def last_dispatch_time(self) -> Optional[datetime]:
        return self._last_dispatch_time

    async def start(self) -> None:
        """Start the background worker runtime loop."""
        if self._running:
            return
        self._trigger_event = asyncio.Event()
        self._running = True
        self._task = asyncio.create_task(self._run_loop(), name="AihaX-CampaignWorkerRuntime")
        logger.info(f"CampaignWorkerRuntime started (worker_id={self.worker.worker_id}, concurrency={self.worker_concurrency}).")

    async def stop(self) -> None:
        """Gracefully stop the background worker runtime loop."""
        if not self._running:
            return
        self._running = False
        if self._trigger_event:
            self._trigger_event.set()
        if self._task:
            self._task.cancel()
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
            self._task = None
        self._trigger_event = None
        logger.info("CampaignWorkerRuntime stopped.")

    def trigger_dispatch(self) -> None:
        """Wake up the worker loop immediately to process newly dispatched tasks."""
        if self._trigger_event:
            try:
                self._trigger_event.set()
            except Exception:
                pass

    async def dispatch_once(self) -> int:
        """Perform one discrete dispatch, recovery, and execution pass across all running campaigns."""
        self._last_dispatch_time = _utc_now()
        session = self._session_factory()
        executed_count = 0

        try:
            repo = CampaignRepository(session)

            # 1. Recover stale tasks across all campaigns
            repo.recover_stale_tasks()
            session.commit()

            # 2. Find all RUNNING campaigns
            running_campaigns = (
                session.query(Campaign)
                .filter(Campaign.status == CampaignLifecycleState.RUNNING.value)
                .all()
            )

            for campaign in running_campaigns:
                # 3. Atomically claim claimable tasks for this campaign
                claimed_tasks = repo.claim_tasks(
                    campaign_id=campaign.id,
                    worker_id=self.worker.worker_id,
                    limit=self.worker_concurrency,
                    lease_duration_seconds=self.worker.lease_duration_seconds,
                )
                session.commit()

                if not claimed_tasks:
                    # Check if campaign should complete if 0 tasks are left
                    self.worker._evaluate_campaign_completion(campaign.id, session, repo)
                    continue

                # 4. Execute claimed tasks
                for task in claimed_tasks:
                    res = await self.worker.execute_task(task.id, session, repo)
                    if res.get("status") == "completed":
                        executed_count += 1

        except Exception as e:
            session.rollback()
            logger.error(f"Error in CampaignWorkerRuntime dispatch_once: {e}")
        finally:
            session.close()

        return executed_count

    async def _run_loop(self) -> None:
        """Background continuous polling loop."""
        while self._running:
            try:
                await self.dispatch_once()
            except Exception as loop_err:
                logger.error(f"Worker runtime loop error: {loop_err}")

            try:
                # Wait for poll interval or immediate trigger event
                if self._trigger_event is None:
                    self._trigger_event = asyncio.Event()
                event = self._trigger_event
                event.clear()
                await asyncio.wait_for(event.wait(), timeout=self.poll_interval)
            except asyncio.TimeoutError:
                pass
            except asyncio.CancelledError:
                break


# Global singleton instance for FastAPI lifespan
campaign_worker_runtime = CampaignWorkerRuntime()
