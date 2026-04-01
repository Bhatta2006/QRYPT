# =============================================================================
# SVT System — Rate Limiter (Redis Sliding Window)
# =============================================================================

from __future__ import annotations

import time

from fastapi import HTTPException, status
from redis.asyncio import Redis


async def sliding_window_rate_limit(
    redis: Redis,
    key: str,
    limit: int,
    window_seconds: int,
) -> None:
    """
    Redis-backed sliding window rate limiter.

    Uses Sorted Set with timestamp-as-score for precise window tracking.

    Args:
        redis: Async Redis client
        key: Rate limit key (e.g., "rate:login:ip:1.2.3.4")
        limit: Maximum number of requests in the window
        window_seconds: Window duration in seconds

    Raises:
        HTTPException(429) with Retry-After header when limit exceeded.
    """
    now = time.time()
    window_start = now - window_seconds

    pipe = redis.pipeline()

    # Remove entries outside the window
    pipe.zremrangebyscore(key, 0, window_start)
    # Count current entries in window
    pipe.zcard(key)
    # Add current request
    pipe.zadd(key, {f"{now}:{id(key)}": now})
    # Set expiry on the key itself
    pipe.expire(key, window_seconds + 1)

    results = await pipe.execute()
    current_count = results[1]

    if current_count >= limit:
        # Find the oldest entry to calculate Retry-After
        oldest = await redis.zrange(key, 0, 0, withscores=True)
        retry_after = int(window_seconds - (now - oldest[0][1])) + 1 if oldest else window_seconds

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(max(1, retry_after))},
        )
