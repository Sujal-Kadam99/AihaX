import json
import logging
import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from backend.core.redis_client import subscribe_updates

router = APIRouter(prefix="/ws", tags=["websocket"])
logger = logging.getLogger(__name__)

@router.websocket("/scan/{scan_id}")
async def websocket_scan_endpoint(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    
    # We will run a background task to push Redis PubSub messages to the WebSocket
    async def push_updates():
        try:
            async for update in subscribe_updates(scan_id):
                await websocket.send_text(json.dumps(update))
        except Exception as e:
            logger.error(f"WebSocket push error: {e}")

    task = asyncio.create_task(push_updates())
    
    try:
        while True:
            # Keep connection alive, listen for client disconnects
            _ = await websocket.receive_text()
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for scan: {scan_id}")
    finally:
        task.cancel()
