"""Watch scheduler service for recurring scans and regression detection."""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import requests
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy.orm import Session

from backend.core.config import get_settings
from backend.models.database import (
    Finding,
    Scan,
    WatchSchedule,
    get_session_factory,
)
from backend.services.orchestrator import run_scan_pipeline, save_scan_config

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()


def _interval_seconds(schedule_type: str) -> int:
    return {
        "daily": 86400,
        "weekly": 604800,
        "after_deploy": 3600,
    }.get(schedule_type, 86400)


def load_watch_schedules() -> None:
    factory = get_session_factory()
    db = factory()
    try:
        schedules = db.query(WatchSchedule).filter_by(active=True).all()
        for schedule in schedules:
            schedule_watch_job(schedule)
    finally:
        db.close()


def schedule_watch_job(schedule: WatchSchedule) -> None:
    job_id = f"watch_{schedule.id}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)

    schedule_date = schedule.next_run or datetime.utcnow() + timedelta(seconds=5)
    scheduler.add_job(
        _run_watch_schedule,
        trigger="interval",
        seconds=_interval_seconds(schedule.schedule_type),
        id=job_id,
        next_run_time=schedule_date,
        kwargs={"schedule_id": schedule.id},
    )
    logger.info("Scheduled watch job %s for %s", job_id, schedule.target_url)


def cancel_watch_job(schedule_id: str) -> None:
    job_id = f"watch_{schedule_id}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)


async def _run_watch_schedule(schedule_id: str) -> None:
    factory = get_session_factory()
    db = factory()
    try:
        schedule = db.query(WatchSchedule).filter_by(id=schedule_id, active=True).first()
        if not schedule:
            return

        settings = get_settings()
        config = json.loads(schedule.scan_payload or "{}")
        config["scan_mode"] = "watch"
        config["schedule_id"] = schedule.id

        scan_id = str(uuid.uuid4())
        scan = Scan(
            id=scan_id,
            target_url=schedule.target_url,
            status="pending",
            scan_depth=config.get("scan_depth", "normal"),
            scan_mode="watch",
            threads=config.get("threads", 5),
            waf_bypass=config.get("waf_bypass", False),
            stealth_mode=config.get("stealth_mode", False),
            industry=config.get("industry"),
            schedule_id=schedule.id,
        )
        db.add(scan)
        db.commit()

        save_scan_config(db, scan_id, config)
        db.close()

        await run_scan_pipeline(scan_id, config)
        await _finish_watch_run(schedule.id, scan_id)
    finally:
        if db:
            db.close()


async def _finish_watch_run(schedule_id: str, scan_id: str) -> None:
    factory = get_session_factory()
    db = factory()
    try:
        schedule = db.query(WatchSchedule).filter_by(id=schedule_id).first()
        if not schedule:
            return

        current_findings = db.query(Finding).filter_by(scan_id=scan_id, false_positive=False).all()
        previous_findings = []
        if schedule.last_scan_id:
            previous_findings = db.query(Finding).filter_by(scan_id=schedule.last_scan_id, false_positive=False).all()

        added, fixed = _compare_findings(previous_findings, current_findings)
        summary = (
            f"New: {len(added)}, Fixed: {len(fixed)}, "
            f"New critical: {sum(1 for f in added if f.severity == 'critical')}"
        )
        schedule.delta_summary = summary
        schedule.last_scan_id = scan_id
        schedule.last_run = datetime.now(timezone.utc)
        schedule.next_run = datetime.now(timezone.utc) + timedelta(seconds=_interval_seconds(schedule.schedule_type))
        db.commit()

        if schedule.alert_webhook and added:
            _send_webhook_alert(schedule, added, fixed)
    finally:
        db.close()


def _compare_findings(previous: list[Finding], current: list[Finding]) -> tuple[list[Finding], list[Finding]]:
    prev_set = {(f.vuln_type, f.affected_url, f.affected_param) for f in previous}
    curr_set = {(f.vuln_type, f.affected_url, f.affected_param) for f in current}
    added = [f for f in current if (f.vuln_type, f.affected_url, f.affected_param) not in prev_set]
    fixed = [f for f in previous if (f.vuln_type, f.affected_url, f.affected_param) not in curr_set]
    return added, fixed


def _send_webhook_alert(schedule: WatchSchedule, added: list[Finding], fixed: list[Finding]) -> None:
    payload = {
        "watch_name": schedule.watch_name,
        "target_url": schedule.target_url,
        "new_findings": [f.title for f in added],
        "fixed_findings": [f.title for f in fixed],
        "new_critical": sum(1 for f in added if f.severity == 'critical'),
        "delta_summary": schedule.delta_summary,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    try:
        requests.post(schedule.alert_webhook, json=payload, timeout=10)
    except Exception as exc:
        logger.warning("Failed to send watch webhook alert: %s", exc)
