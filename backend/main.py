"""AihaX FastAPI application entry point."""

import asyncio
import json
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from backend.core.auth import require_auth
from backend.core.config import ensure_directories, get_settings
from backend.core.errors import APIException
from backend.core.logger import setup_logger
from backend.core.redis_client import close_redis, get_redis, subscribe_updates
from backend.models.database import get_db, init_db
from backend.models.schemas import HealthResponse
from backend.routers import auth, billing, campaigns, checks, findings, organizations, programs, reports, scan, settings, watch, ws
from backend.services.campaign_worker import campaign_worker_runtime
from backend.services.watch_scheduler import load_watch_schedules, scheduler

logger = setup_logger("aihax.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    ensure_directories(settings)
    init_db()
    if not scheduler.running:
        scheduler.start()
    load_watch_schedules()
    await campaign_worker_runtime.start()
    yield
    await campaign_worker_runtime.stop()
    await close_redis()


app = FastAPI(
    title="AihaX",
    description="AI-Powered Automated Penetration Testing Platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "X-AihaX-Token", "Content-Type"],
    max_age=3600,
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "::1", "testserver"],
)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "interest-cohort=()")
    return response


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    # Allow CORS preflight requests through so CORSMiddleware can handle them
    if request.method == "OPTIONS":
        return await call_next(request)
    try:
        from backend.core.auth import _is_public_path
        from backend.core.rate_limit import check_rate_limit

        if _is_public_path(request.url.path):
            check_rate_limit(request, "public")
        else:
            check_rate_limit(request, "authenticated")

        require_auth(request)
    except HTTPException as exc:
        return JSONResponse(
            status_code=exc.status_code,
            content={"success": False, "error": {"code": "HTTP_ERROR", "message": exc.detail}}
        )
    return await call_next(request)


@app.exception_handler(APIException)
async def api_exception_handler(request: Request, exc: APIException):
    logger.warning({
        "event": "api_exception",
        "code": exc.error_code,
        "message": exc.message,
        "path": request.url.path
    })
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": {"code": exc.error_code, "message": exc.message, "details": exc.details}
        }
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error({
        "event": "unhandled_exception",
        "error": str(exc),
        "path": request.url.path
    }, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred."
            }
        }
    )


app.include_router(auth.router)
app.include_router(programs.router)
app.include_router(scan.router)
app.include_router(settings.router, prefix="/api/settings", tags=["Settings"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])
app.include_router(findings.router)
app.include_router(watch.router)
app.include_router(billing.router)
app.include_router(organizations.router)
app.include_router(checks.router)
app.include_router(campaigns.router)
app.include_router(ws.router)

# Direct /campaigns compatibility routes
campaigns_compat_router = APIRouter(
    prefix="/campaigns",
    tags=["Campaigns Compatibility"],
    include_in_schema=False,
    dependencies=[Depends(campaigns.enforce_campaign_access)],
)

@campaigns_compat_router.get("/{campaign_id}/execution-summary")
def compat_execution_summary(campaign_id: str, db: Session = Depends(get_db)):
    from backend.routers.campaigns import get_campaign_execution_summary
    return get_campaign_execution_summary(campaign_id=campaign_id, db=db)

@campaigns_compat_router.get("/{campaign_id}/timeline")
def compat_timeline(
    campaign_id: str,
    limit: int = 100,
    offset: int = 0,
    event_type: Optional[str] = None,
    db: Session = Depends(get_db),
):
    from backend.routers.campaigns import get_campaign_timeline
    return get_campaign_timeline(campaign_id=campaign_id, limit=limit, offset=offset, event_type=event_type, db=db)

@campaigns_compat_router.get("/{campaign_id}/evidence")
def compat_evidence(
    campaign_id: str,
    limit: int = 50,
    offset: int = 0,
    evidence_type: Optional[str] = None,
    db: Session = Depends(get_db),
):
    from backend.routers.campaigns import get_campaign_evidence
    return get_campaign_evidence(campaign_id=campaign_id, limit=limit, offset=offset, evidence_type=evidence_type, db=db)

@campaigns_compat_router.get("/{campaign_id}/evidence/{evidence_id}")
def compat_evidence_detail(campaign_id: str, evidence_id: str, db: Session = Depends(get_db)):
    from backend.routers.campaigns import get_campaign_evidence_detail
    return get_campaign_evidence_detail(campaign_id=campaign_id, evidence_id=evidence_id, db=db)

app.include_router(campaigns_compat_router)


@app.get("/api/health", response_model=HealthResponse)
async def health_check():
    settings = get_settings()
    redis_status = "ok"
    db_status = "ok"

    try:
        r = await get_redis()
        if r:
            await r.ping()
        else:
            redis_status = "error"
    except Exception:
        redis_status = "error"

    return HealthResponse(
        status="ok",
        version=settings.app_version,
        redis=redis_status,
        database=db_status,
    )


@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    try:
        # First message must be auth token — avoids token in URL/logs
        auth_msg = await websocket.receive_text()
        auth_data = json.loads(auth_msg)
        token = auth_data.get("token")

        from backend.core.auth import require_ws_auth_token
        if not token or not await require_ws_auth_token(token, scan_id):
            await websocket.close(code=1008, reason="Unauthorized")
            return

        async for message in subscribe_updates(scan_id):
            await websocket.send_text(json.dumps(message))
    except WebSocketDisconnect:
        pass
    except Exception:
        await websocket.close()
