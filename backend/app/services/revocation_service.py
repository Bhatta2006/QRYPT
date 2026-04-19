import uuid
from datetime import datetime
from uuid import UUID

from fastapi import HTTPException
from redis.asyncio import Redis
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.models.token import SVTToken
from app.models.revocation_event import RevocationEvent
from app.core.metrics import svt_revocations_total

logger = structlog.get_logger(__name__)

async def revoke(trace_id: str, reason: str, revoked_by_user_id: UUID, db: AsyncSession, redis: Redis) -> RevocationEvent:
    # 1. Update token status
    result = await db.execute(
        update(SVTToken)
        .where(SVTToken.trace_id == trace_id)
        .values(status="BLOCKED", revoked_at=datetime.utcnow(), revocation_reason=reason)
        .returning(SVTToken.id, SVTToken.issuer_id)
    )
    row = result.first()
    if row is None:
        raise HTTPException(status_code=404, detail="token_not_found")

    # 2. Insert RevocationEvent
    rev_event = RevocationEvent(
        trace_id=trace_id, 
        reason=reason, 
        revoked_by=revoked_by_user_id,
        created_at=datetime.utcnow()
    )
    db.add(rev_event)
    await db.commit()
    svt_revocations_total.inc()
    await db.refresh(rev_event)  # get generated id (BIGSERIAL)

    # 3. Redis: set BLOCKED with no TTL (permanent until unrevoked)
    await redis.set(f"svt:{trace_id}", "BLOCKED")

    # 4. Publish to Redis Stream for SSE propagation
    await redis.xadd(
        "revocation_events",
        {
            "id": str(rev_event.id), 
            "trace_id": trace_id,
            "action": "revoke", 
            "timestamp_ms": str(int(datetime.utcnow().timestamp() * 1000))
        },
        maxlen=10000, 
        approximate=True
    )
    
    logger.info("token_revoked", trace_id=trace_id, reason=reason, user_id=str(revoked_by_user_id))
    return rev_event

async def unrevoke(trace_id: str, admin_user_id: UUID, db: AsyncSession, redis: Redis) -> None:
    result = await db.execute(
        update(SVTToken)
        .where(SVTToken.trace_id == trace_id)
        .values(status="ACTIVE", revoked_at=None, revocation_reason=None)
        .returning(SVTToken.id)
    )
    if result.first() is None:
        raise HTTPException(status_code=404, detail="token_not_found")
        
    await db.commit()
    
    # Fully delete so it falls back to DB and caches fresh state
    await redis.delete(f"svt:{trace_id}")
    
    await redis.xadd(
        "revocation_events",
        {
            "id": f"unrevoke-{uuid.uuid4()}", 
            "trace_id": trace_id,
            "action": "unrevoke", 
            "timestamp_ms": str(int(datetime.utcnow().timestamp() * 1000))
        },
        maxlen=10000, 
        approximate=True
    )
    logger.info("token_unrevoked", trace_id=trace_id, user_id=str(admin_user_id))
