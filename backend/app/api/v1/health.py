# =============================================================================
# Health Endpoints — Liveness & Readiness Probes
# =============================================================================

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.cache.redis_client import get_redis
from app.db.session import get_db

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/ready")
async def readiness(
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
):
    """
    Readiness probe — validates DB and Redis connectivity.
    Returns 503 if either dependency is unreachable.
    Used by Kubernetes readiness probe to gate traffic.
    """
    try:
        await db.execute(text("SELECT 1"))
        await redis.ping()
        return {"status": "ready"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"not_ready: {str(e)}")
