# =============================================================================
# SVT System — Scan Verification Router
# =============================================================================

from fastapi import APIRouter, Depends, Request
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.cache.redis_client import get_redis
from app.core.rate_limit import sliding_window_rate_limit
from app.core.scanner_auth import get_current_scanner
from app.db.session import get_db
from app.models.scanner_device import ScannerDevice
from app.schemas.scan import ScanVerifyRequest, ScanVerifyResponse
from app.services.scan_service import verify_svt_token

router = APIRouter(prefix="/scan", tags=["scan"])


@router.post("/verify", response_model=ScanVerifyResponse)
async def verify_svt(
    body: ScanVerifyRequest,
    fastapi_req: Request,
    scanner: ScannerDevice = Depends(get_current_scanner),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
):
    """
    High-velocity SVT verification endpoint.
    Rate limited: 30 req/min per scanner_device_id.
    Authenticated via HMAC-SHA256 scanner credentials.
    """
    # Rate limit: 30 req/min per scanner device (NOT per IP)
    await sliding_window_rate_limit(
        redis, f"rate:scan:{scanner.id}", limit=30, window_seconds=60
    )

    client_ip = fastapi_req.client.host if fastapi_req.client else None
    user_agent = fastapi_req.headers.get("User-Agent")
    device_id = fastapi_req.headers.get("X-Device-Id", str(scanner.id))

    return await verify_svt_token(db, redis, body, scanner, client_ip, user_agent, device_id)
