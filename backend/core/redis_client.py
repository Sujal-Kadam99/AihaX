"""Redis client for agent communication and short-term memory."""

import json
import logging
from typing import Any, AsyncGenerator, Optional

import redis.asyncio as aioredis

from backend.core.config import get_settings

logger = logging.getLogger(__name__)

_redis_client: Optional[aioredis.Redis] = None
_redis_available: Optional[bool] = None


async def get_redis() -> Optional[aioredis.Redis]:
    global _redis_client, _redis_available
    if _redis_available is False:
        return None
    try:
        if _redis_client is None:
            settings = get_settings()
            _redis_client = aioredis.from_url(
                settings.redis_url,
                encoding="utf-8",
                decode_responses=True,
            )
        await _redis_client.ping()
        _redis_available = True
        return _redis_client
    except Exception as e:
        logger.warning("Redis unavailable: %s", e)
        _redis_available = False
        return None


async def close_redis() -> None:
    global _redis_client, _redis_available
    if _redis_client is not None:
        await _redis_client.close()
        _redis_client = None
    _redis_available = None


def scan_key(scan_id: str, suffix: str) -> str:
    return f"aihax:scan:{scan_id}:{suffix}"


async def set_scan_status(scan_id: str, status: str) -> None:
    r = await get_redis()
    if r:
        await r.set(scan_key(scan_id, "status"), status)


async def get_scan_status(scan_id: str) -> Optional[str]:
    r = await get_redis()
    if not r:
        return None
    return await r.get(scan_key(scan_id, "status"))


async def set_agent_state(
    scan_id: str,
    agent_id: int,
    status: str,
    progress: int,
    message: str,
) -> None:
    r = await get_redis()
    if not r:
        return
    key = scan_key(scan_id, f"agent:{agent_id}")
    await r.hset(
        key,
        mapping={
            "status": status,
            "progress": str(progress),
            "message": message,
            "last_updated": str(__import__("time").time()),
        },
    )


async def get_agent_state(scan_id: str, agent_id: int) -> dict[str, str]:
    r = await get_redis()
    if not r:
        return {}
    key = scan_key(scan_id, f"agent:{agent_id}")
    return await r.hgetall(key) or {}


async def publish_update(scan_id: str, message: dict[str, Any]) -> None:
    r = await get_redis()
    if not r:
        return
    channel = scan_key(scan_id, "updates")
    await r.publish(channel, json.dumps(message))


async def subscribe_updates(scan_id: str) -> AsyncGenerator[dict[str, Any], None]:
    r = await get_redis()
    if not r:
        return
    pubsub = r.pubsub()
    channel = scan_key(scan_id, "updates")
    await pubsub.subscribe(channel)
    try:
        async for msg in pubsub.listen():
            if msg["type"] == "message":
                yield json.loads(msg["data"])
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.close()


async def set_attack_surface(scan_id: str, data: dict[str, Any]) -> None:
    r = await get_redis()
    if r:
        await r.set(scan_key(scan_id, "attack_surface"), json.dumps(data))


async def get_attack_surface(scan_id: str) -> Optional[dict[str, Any]]:
    r = await get_redis()
    if not r:
        return None
    raw = await r.get(scan_key(scan_id, "attack_surface"))
    return json.loads(raw) if raw else None


async def set_sessions(scan_id: str, data: dict[str, Any]) -> None:
    r = await get_redis()
    if r:
        await r.set(scan_key(scan_id, "sessions"), json.dumps(data))


async def get_sessions(scan_id: str) -> Optional[dict[str, Any]]:
    r = await get_redis()
    if not r:
        return None
    raw = await r.get(scan_key(scan_id, "sessions"))
    return json.loads(raw) if raw else None
