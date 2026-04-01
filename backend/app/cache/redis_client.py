# =============================================================================
# SVT System — Redis Client
# =============================================================================

from __future__ import annotations

from redis.asyncio import Redis, from_url

from app.core.config import get_settings

settings = get_settings()

_redis_client: Redis | None = None


async def get_redis() -> Redis:
    """Get or create async Redis client."""
    global _redis_client
    if _redis_client is None:
        _redis_client = from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
            max_connections=50,
        )
    return _redis_client


async def get_redis_bytes() -> Redis:
    """Get Redis client that returns bytes (for binary data)."""
    return from_url(
        settings.redis_url,
        decode_responses=False,
        max_connections=20,
    )


async def close_redis() -> None:
    """Close Redis connection on shutdown."""
    global _redis_client
    if _redis_client:
        await _redis_client.close()
        _redis_client = None
