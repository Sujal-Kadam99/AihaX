"""Watch schedule API routes."""

import json
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.models.database import WatchSchedule, get_db
from backend.models.schemas import WatchScheduleItem, WatchSchedulePayload
from backend.services.watch_scheduler import schedule_watch_job, cancel_watch_job

router = APIRouter(prefix="/api/watch", tags=["watch"])


@router.post("")
async def create_watch_schedule(
    payload: WatchSchedulePayload,
    db: Session = Depends(get_db),
):
    schedule = WatchSchedule(
        target_url=payload.target_url,
        schedule_type=payload.schedule_type,
        watch_name=payload.watch_name or f"Watch {payload.target_url}",
        scan_payload=json.dumps(payload.scan_config),
        scope_notes=payload.scope_notes,
        alert_webhook=payload.alert_webhook or "",
        alert_email=payload.alert_email or "",
        next_run=datetime.utcnow() + payload.interval_delta,
        active=True,
    )
    db.add(schedule)
    db.commit()
    schedule_watch_job(schedule)

    return WatchScheduleItem(
        id=schedule.id,
        target_url=schedule.target_url,
        watch_name=schedule.watch_name,
        schedule_type=schedule.schedule_type,
        last_run=schedule.last_run,
        next_run=schedule.next_run,
        active=schedule.active,
        alert_webhook=schedule.alert_webhook,
        alert_email=schedule.alert_email,
        delta_summary=schedule.delta_summary,
    )


@router.get("/list")
async def list_watch_schedules(db: Session = Depends(get_db)):
    schedules = db.query(WatchSchedule).filter_by(active=True).order_by(WatchSchedule.created_at.desc()).all()
    return [
        WatchScheduleItem(
            id=s.id,
            target_url=s.target_url,
            watch_name=s.watch_name,
            schedule_type=s.schedule_type,
            last_run=s.last_run,
            next_run=s.next_run,
            active=s.active,
            alert_webhook=s.alert_webhook,
            alert_email=s.alert_email,
            delta_summary=s.delta_summary,
        )
        for s in schedules
    ]


@router.delete("/{schedule_id}")
async def delete_watch_schedule(schedule_id: str, db: Session = Depends(get_db)):
    schedule = db.query(WatchSchedule).filter_by(id=schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Watch schedule not found")
    schedule.active = False
    db.commit()
    cancel_watch_job(schedule.id)
    return {"schedule_id": schedule.id, "active": schedule.active}
