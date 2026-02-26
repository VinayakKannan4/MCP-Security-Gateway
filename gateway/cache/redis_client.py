"""Async Redis client and typed helpers.

Security invariant: set_json() always requires a TTL — callers cannot
store data without an expiry. This ensures approval tokens and other
time-sensitive data cannot accumulate indefinitely.
"""

import json
import logging
from collections.abc import AsyncGenerator
from typing import Any

from redis.asyncio import Redis

from gateway.config import settings

logger = logging.getLogger(__name__)


async def get_redis() -> AsyncGenerator[Redis[str], None]:
    """FastAPI dependency that yields a connected async Redis client."""
    client: Redis[str] = Redis.from_url(settings.redis_url, decode_responses=True)
    try:
        yield client
    finally:
        await client.aclose()


async def set_json(client: Redis[str], key: str, value: dict[str, Any], ttl: int) -> None:
    """Serialize value as JSON and store it with a mandatory TTL (seconds).

    The ttl parameter is required — never store without expiry.
    """
    if ttl <= 0:
        raise ValueError(f"ttl must be positive, got {ttl}")
    await client.set(key, json.dumps(value), ex=ttl)
    logger.debug("redis set key=%s ttl=%ds", key, ttl)


async def get_json(client: Redis[str], key: str) -> dict[str, Any] | None:
    """Retrieve and deserialize a JSON value. Returns None if key is missing."""
    raw = await client.get(key)
    if raw is None:
        return None
    result: dict[str, Any] = json.loads(raw)
    return result


async def delete(client: Redis[str], key: str) -> None:
    """Delete a key from Redis."""
    await client.delete(key)
    logger.debug("redis delete key=%s", key)
