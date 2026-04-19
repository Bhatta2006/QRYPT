# =============================================================================
# SVT System — Scanner Device Auth Strategy
# =============================================================================

from __future__ import annotations

import hmac
import uuid
import hashlib
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis

from app.cache.redis_client import get_redis
from app.core.kms.provider import get_kms_client
from app.db.session import get_db
from app.models.scanner_device import ScannerDevice


async def get_current_scanner(
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
) -> ScannerDevice:
    """ Authenticaticate via robust HMAC signatures ensuring deterministic integrity. """
    device_id_str = request.headers.get("X-Device-Id")
    timestamp_str = request.headers.get("X-Timestamp")
    provided_signature = request.headers.get("X-Signature-SHA256")

    if not all([device_id_str, timestamp_str, provided_signature]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required authentication headers (X-Device-Id, X-Timestamp, X-Signature-SHA256)",
        )

    # 1. Validate timestamp
    try:
        timestamp = float(timestamp_str or "0")
        device_id = uuid.UUID(device_id_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid header formatting",
        )

    now = datetime.now(timezone.utc).timestamp()
    if abs(now - timestamp) > 30:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Request timestamp drift exceeded (±30s)",
        )

    # 4. Replay Protection (Immediate Redis SET NX)
    replay_key = f"hmac_replay:{device_id_str}:{timestamp_str}:{provided_signature}"
    set_success = await redis.set(replay_key, "1", nx=True, ex=30)
    if not set_success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Replay attack detected",
        )

    # Database Lookup
    result = await db.execute(
        select(ScannerDevice).where(ScannerDevice.id == device_id)
    )
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid scanner credentials",
        )
        
    if device.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Scanner device has been revoked",
        )

    # 2. Decrypt hmac_secret via KMS
    kms = get_kms_client()
    try:
        hmac_secret = await kms.decrypt(device.encrypted_hmac_secret)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to decrypt secure cryptographic material.",
        )

    # 3. Compute expected signature
    raw_body_bytes = await request.body()
    
    msg = (device_id_str or "").encode("utf-8") + (timestamp_str or "0").encode("utf-8") + raw_body_bytes
    expected_hmac = hmac.new(hmac_secret, msg, digestmod=hashlib.sha256).hexdigest()

    # 4. Timing-safe compare
    if not hmac.compare_digest(expected_hmac.encode("utf-8"), (provided_signature or "").encode("utf-8")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="HMAC signature verification failed",
        )

    return device
