# =============================================================================
# SVT System — Tokens API Endpoints
# =============================================================================

from __future__ import annotations

from typing import Annotated, Any

import json

from fastapi import APIRouter, Depends, Query, status, Header
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.cache.redis_client import get_redis
from app.core.security import UserContext, rbac
from app.db.session import get_db
from app.models.token import SVTToken
from app.schemas.token import TokenCreateRequest, TokenDetailsResponse, TokenResponse
from app.services.token_service import generate_svt_token

router = APIRouter(prefix="/tokens", tags=["tokens"])


@router.post("", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def create_token(
    request: TokenCreateRequest,
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
    current_user: UserContext = Depends(rbac(["issuer", "admin"])),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
):
    """
    Generate an unbreakable cryptographically wrapped SVT representing a destination endpoint.
    Enforces strict idempotency per issuer.
    """
    cache_key = f"idempotency:{current_user.id}:{idempotency_key}"
    cached_val = await redis.get(cache_key)
    if cached_val:
        return json.loads(cached_val)

    # Generate SVT
    token_response = await generate_svt_token(db, current_user.id, request)

    # Convert Pydantic Response to string using model_dump for cache
    response_json = json.dumps(token_response.model_dump(mode="json"))
    await redis.set(cache_key, response_json, ex=86400)
    
    return token_response


@router.get("", response_model=list[TokenDetailsResponse])
async def list_tokens(
    current_user: UserContext = Depends(rbac(["issuer", "admin"])),
    db: AsyncSession = Depends(get_db),
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    """
    Fetch tokens owned strictly by the authenticated issuer context.
    Provides limit/offset pagination mechanism.
    """
    result = await db.execute(
        select(SVTToken)
        .where(SVTToken.issuer_id == current_user.id)
        .order_by(SVTToken.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return result.scalars().all()
