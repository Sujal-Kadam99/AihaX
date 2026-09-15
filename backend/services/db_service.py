"""Data access repository service layer with thread-safe session handling."""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.models.database import (
    AgentLog,
    AuditLog,
    EntitlementCache,
    ExploitChain,
    Finding,
    Scan,
    ScanConfig,
    WatchSchedule,
    get_session_factory,
    with_db_retry,
)

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Pagination Helper
# -----------------------------------------------------------------------------

class PaginatedResult:
    """Generic paginated query result container."""

    def __init__(self, items: list, total: int, page: int, per_page: int):
        self.items = items
        self.total = total
        self.page = page
        self.per_page = per_page
        self.pages = max(1, (total + per_page - 1) // per_page)
        self.has_next = page < self.pages
        self.has_prev = page > 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "page": self.page,
            "per_page": self.per_page,
            "pages": self.pages,
            "has_next": self.has_next,
            "has_prev": self.has_prev,
        }


# -----------------------------------------------------------------------------
# Scan Repository
# -----------------------------------------------------------------------------

class ScanRepository:
    """Repository for managing Scan entity lifecycle and query operations."""

    @staticmethod
    @with_db_retry()
    def create_scan(
        db: Session,
        target_url: str,
        scan_depth: str = "normal",
        scan_mode: str = "standard",
        threads: int = 5,
        admin_mode: bool = False,
        user_id: Optional[str] = None,
        user_email: Optional[str] = None,
        industry: Optional[str] = None,
    ) -> Scan:
        scan = Scan(
            target_url=target_url,
            scan_depth=scan_depth,
            scan_mode=scan_mode,
            threads=threads,
            admin_mode=admin_mode,
            user_id=user_id,
            user_email=user_email,
            industry=industry,
            created_at=datetime.now(timezone.utc),
            status="pending",
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan

    @staticmethod
    @with_db_retry()
    def update_status(
        db: Session,
        scan_id: str,
        status: str,
        risk_score: Optional[int] = None,
    ) -> Optional[Scan]:
        scan = db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            return None
        old_status = scan.status
        scan.status = status
        if risk_score is not None:
            scan.risk_score = risk_score
        if status in ("completed", "complete", "failed", "cancelled"):
            scan.completed_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(scan)

        # Record audit trail
        AuditLogRepository.log_event(
            db,
            entity_type="scan",
            entity_id=scan_id,
            action="status_change",
            old_value=old_status,
            new_value=status,
            user_id=scan.user_id,
        )
        return scan

    @staticmethod
    def get_by_id(db: Session, scan_id: str) -> Optional[Scan]:
        return db.query(Scan).filter_by(id=scan_id).first()

    @staticmethod
    def list_scans(
        db: Session,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
        user_id: Optional[str] = None,
        user_email: Optional[str] = None,
    ) -> List[Scan]:
        query = db.query(Scan)
        if status:
            query = query.filter(Scan.status == status)
        if user_id:
            query = query.filter(Scan.user_id == user_id)
        if user_email:
            query = query.filter(Scan.user_email == user_email)
        return query.order_by(Scan.created_at.desc()).offset(offset).limit(limit).all()

    @staticmethod
    def list_scans_paginated(
        db: Session,
        page: int = 1,
        per_page: int = 20,
        status: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> PaginatedResult:
        query = db.query(Scan)
        if status:
            query = query.filter(Scan.status == status)
        if user_id:
            query = query.filter(Scan.user_id == user_id)
        total = query.count()
        items = query.order_by(Scan.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
        return PaginatedResult(items=items, total=total, page=page, per_page=per_page)

    @staticmethod
    def count_monthly_scans(db: Session, user_email: str) -> int:
        now = datetime.now(timezone.utc)
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        return db.query(Scan).filter(
            Scan.user_email == user_email,
            Scan.created_at >= month_start,
            Scan.status != "cancelled",
        ).count()

    @staticmethod
    @with_db_retry()
    def delete_scan(db: Session, scan_id: str) -> bool:
        scan = db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            return False
        db.delete(scan)
        db.commit()
        return True


# -----------------------------------------------------------------------------
# Finding Repository
# -----------------------------------------------------------------------------

class FindingRepository:
    """Repository for managing security Findings."""

    @staticmethod
    @with_db_retry()
    def add_finding(
        db: Session,
        scan_id: str,
        agent_id: int,
        title: str,
        vuln_type: str,
        category: str,
        severity: str,
        affected_url: str,
        **kwargs,
    ) -> Finding:
        finding = Finding(
            scan_id=scan_id,
            agent_id=agent_id,
            title=title,
            vuln_type=vuln_type,
            category=category,
            severity=severity,
            affected_url=affected_url,
            created_at=datetime.now(timezone.utc),
            **kwargs,
        )
        db.add(finding)
        db.commit()
        db.refresh(finding)

        # Increment total findings count on parent scan
        scan = db.query(Scan).filter_by(id=scan_id).first()
        if scan:
            scan.total_findings = (scan.total_findings or 0) + 1
            db.commit()

        return finding

    @staticmethod
    def get_by_scan(
        db: Session,
        scan_id: str,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        vuln_type: Optional[str] = None,
        min_confidence: Optional[int] = None,
        false_positive: Optional[bool] = None,
    ) -> List[Finding]:
        query = db.query(Finding).filter_by(scan_id=scan_id)
        if severity:
            query = query.filter(Finding.severity == severity)
        if category:
            query = query.filter(Finding.category == category)
        if vuln_type:
            query = query.filter(Finding.vuln_type == vuln_type)
        if min_confidence is not None:
            query = query.filter(Finding.confidence >= min_confidence)
        if false_positive is not None:
            query = query.filter(Finding.false_positive == false_positive)
        return query.order_by(Finding.created_at.desc()).all()

    @staticmethod
    def get_by_id(db: Session, finding_id: str) -> Optional[Finding]:
        return db.query(Finding).filter_by(id=finding_id).first()

    @staticmethod
    @with_db_retry()
    def mark_false_positive(db: Session, finding_id: str, is_fp: bool = True) -> Optional[Finding]:
        finding = db.query(Finding).filter_by(id=finding_id).first()
        if not finding:
            return None
        finding.false_positive = is_fp
        db.commit()
        db.refresh(finding)
        return finding

    @staticmethod
    @with_db_retry()
    def update_remediation(db: Session, finding_id: str, remediation: str) -> Optional[Finding]:
        finding = db.query(Finding).filter_by(id=finding_id).first()
        if not finding:
            return None
        finding.remediation = remediation
        db.commit()
        db.refresh(finding)
        return finding

    @staticmethod
    def get_severity_counts(db: Session, scan_id: str) -> dict[str, int]:
        rows = (
            db.query(Finding.severity, func.count(Finding.id))
            .filter_by(scan_id=scan_id, false_positive=False)
            .group_by(Finding.severity)
            .all()
        )
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for severity, count in rows:
            if severity in counts:
                counts[severity] = count
        return counts

    @staticmethod
    def list_paginated(
        db: Session,
        scan_id: str,
        page: int = 1,
        per_page: int = 50,
        severity: Optional[str] = None,
    ) -> PaginatedResult:
        query = db.query(Finding).filter_by(scan_id=scan_id)
        if severity:
            query = query.filter(Finding.severity == severity)
        total = query.count()
        items = query.order_by(Finding.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
        return PaginatedResult(items=items, total=total, page=page, per_page=per_page)


# -----------------------------------------------------------------------------
# AgentLog Repository
# -----------------------------------------------------------------------------

class AgentLogRepository:
    """Repository for logging agent activity during scans."""

    @staticmethod
    @with_db_retry()
    def log(
        db: Session,
        scan_id: str,
        agent_id: int,
        level: str,
        message: str,
        raw_output: Optional[str] = None,
    ) -> AgentLog:
        agent_log = AgentLog(
            scan_id=scan_id,
            agent_id=agent_id,
            level=level,
            message=message,
            raw_output=raw_output,
            created_at=datetime.now(timezone.utc),
        )
        db.add(agent_log)
        db.commit()
        db.refresh(agent_log)
        return agent_log

    @staticmethod
    def get_logs_for_scan(
        db: Session,
        scan_id: str,
        agent_id: Optional[int] = None,
        level: Optional[str] = None,
        limit: int = 100,
    ) -> List[AgentLog]:
        query = db.query(AgentLog).filter_by(scan_id=scan_id)
        if agent_id is not None:
            query = query.filter(AgentLog.agent_id == agent_id)
        if level:
            query = query.filter(AgentLog.level == level)
        return query.order_by(AgentLog.id.asc()).limit(limit).all()


# -----------------------------------------------------------------------------
# ExploitChain Repository
# -----------------------------------------------------------------------------

class ExploitChainRepository:
    """Repository for exploit chain analysis results."""

    @staticmethod
    @with_db_retry()
    def create(
        db: Session,
        scan_id: str,
        chain_name: str,
        severity_final: str,
        steps: str,
        impact_summary: Optional[str] = None,
    ) -> ExploitChain:
        chain = ExploitChain(
            scan_id=scan_id,
            chain_name=chain_name,
            severity_final=severity_final,
            steps=steps,
            impact_summary=impact_summary,
            created_at=datetime.now(timezone.utc),
        )
        db.add(chain)
        db.commit()
        db.refresh(chain)
        return chain

    @staticmethod
    def get_by_scan(db: Session, scan_id: str) -> List[ExploitChain]:
        return db.query(ExploitChain).filter_by(scan_id=scan_id).all()


# -----------------------------------------------------------------------------
# WatchSchedule Repository
# -----------------------------------------------------------------------------

class WatchScheduleRepository:
    """Repository for Watch Mode recurring schedule management."""

    @staticmethod
    @with_db_retry()
    def create(
        db: Session,
        target_url: str,
        schedule_type: str,
        watch_name: Optional[str] = None,
        scan_payload: Optional[str] = None,
        scope_notes: Optional[str] = None,
        alert_webhook: Optional[str] = None,
        alert_email: Optional[str] = None,
        next_run: Optional[datetime] = None,
    ) -> WatchSchedule:
        schedule = WatchSchedule(
            target_url=target_url,
            schedule_type=schedule_type,
            watch_name=watch_name or target_url,
            scan_payload=scan_payload,
            scope_notes=scope_notes,
            alert_webhook=alert_webhook,
            alert_email=alert_email,
            next_run=next_run or datetime.now(timezone.utc),
            active=True,
            created_at=datetime.now(timezone.utc),
        )
        db.add(schedule)
        db.commit()
        db.refresh(schedule)
        return schedule

    @staticmethod
    def get_due_schedules(db: Session) -> List[WatchSchedule]:
        now_utc = datetime.now(timezone.utc)
        return db.query(WatchSchedule).filter(
            WatchSchedule.active.is_(True),
            WatchSchedule.next_run <= now_utc,
        ).all()

    @staticmethod
    def get_all(db: Session, active_only: bool = True) -> List[WatchSchedule]:
        query = db.query(WatchSchedule)
        if active_only:
            query = query.filter(WatchSchedule.active.is_(True))
        return query.order_by(WatchSchedule.created_at.desc()).all()

    @staticmethod
    @with_db_retry()
    def deactivate(db: Session, schedule_id: str) -> bool:
        schedule = db.query(WatchSchedule).filter_by(id=schedule_id).first()
        if not schedule:
            return False
        schedule.active = False
        db.commit()
        return True


# -----------------------------------------------------------------------------
# AuditLog Repository
# -----------------------------------------------------------------------------

class AuditLogRepository:
    """Repository for system audit trail events."""

    @staticmethod
    @with_db_retry()
    def log_event(
        db: Session,
        entity_type: str,
        entity_id: str,
        action: str,
        old_value: Optional[str] = None,
        new_value: Optional[str] = None,
        user_id: Optional[str] = None,
        metadata: Optional[str] = None,
    ) -> AuditLog:
        entry = AuditLog(
            entity_type=entity_type,
            entity_id=entity_id,
            action=action,
            old_value=old_value,
            new_value=new_value,
            user_id=user_id,
            metadata_json=metadata,
            created_at=datetime.now(timezone.utc),
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)
        return entry

    @staticmethod
    def get_by_entity(
        db: Session,
        entity_type: str,
        entity_id: str,
        limit: int = 100,
    ) -> List[AuditLog]:
        return (
            db.query(AuditLog)
            .filter_by(entity_type=entity_type, entity_id=entity_id)
            .order_by(AuditLog.created_at.desc())
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_recent(db: Session, limit: int = 50) -> List[AuditLog]:
        return db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()


# -----------------------------------------------------------------------------
# EntitlementCache Repository
# -----------------------------------------------------------------------------

class EntitlementCacheRepository:
    """Repository for offline entitlement JWT cache management."""

    @staticmethod
    @with_db_retry()
    def upsert(
        db: Session,
        user_id: str,
        plan_name: str,
        entitlement_jwt: str,
        expires_at: datetime,
        features_json: Optional[str] = None,
    ) -> EntitlementCache:
        existing = db.query(EntitlementCache).filter_by(user_id=user_id).first()
        if existing:
            existing.plan_name = plan_name
            existing.entitlement_jwt = entitlement_jwt
            existing.expires_at = expires_at
            existing.features_json = features_json
            existing.synced_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(existing)
            return existing
        cache = EntitlementCache(
            user_id=user_id,
            plan_name=plan_name,
            entitlement_jwt=entitlement_jwt,
            expires_at=expires_at,
            features_json=features_json,
            synced_at=datetime.now(timezone.utc),
        )
        db.add(cache)
        db.commit()
        db.refresh(cache)
        return cache

    @staticmethod
    def get_for_user(db: Session, user_id: str) -> Optional[EntitlementCache]:
        return db.query(EntitlementCache).filter_by(user_id=user_id).first()
