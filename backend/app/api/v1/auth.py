# =============================================================================
# SVT System — Auth API Endpoints
# =============================================================================

from __future__ import annotations

import hashlib
import os
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from jose import jwt
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.cache.redis_client import get_redis
from app.core.config import get_settings
from app.core.crypto import generate_keypair
from app.core.rate_limit import sliding_window_rate_limit
from app.core.security.device import generate_device_fingerprint
from app.core.security import (
    UserContext,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    hash_password,
    rbac,
    verify_password,
)
from app.db.session import get_db
from app.models.scanner_device import ScannerDevice
from app.models.user import User
from app.models.issuer_key import IssuerKey
from app.schemas.user import (
    ScannerDeviceCreateRequest,
    ScannerDeviceCreateResponse,
    UserLoginRequest,
    UserLoginResponse,
    UserRegisterRequest,
    UserRegisterResponse,
    TokenRefreshResponse,
)

router = APIRouter(prefix="/auth", tags=["auth"])
settings = get_settings()


@router.post("/register", response_model=UserRegisterResponse, status_code=201)
async def register(
    body: UserRegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
):
    """Register a new issuer account."""
    # Rate limit: 10/hour per IP
    client_ip = request.client.host if request.client else "unknown"
    await sliding_window_rate_limit(redis, f"rate:register:ip:{client_ip}", 10, 3600)

    # Check existing email
    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    # Generate Ed25519 keypair
    public_key, encrypted_private_key = await generate_keypair()

    # The user creation and key creation are atomically managed by the session yield context
    user = User(
        email=body.email,
        hashed_password=hash_password(body.password),
        role="issuer",
    )
    db.add(user)
    await db.flush()

    issuer_key = IssuerKey(
        issuer_id=user.id,
        version=1,
        public_key=public_key,
        encrypted_private_key=encrypted_private_key,
    )
    db.add(issuer_key)
    await db.flush()

    return UserRegisterResponse(
        user_id=user.id,
        email=user.email,
        role=user.role,
    )


@router.post("/login", response_model=UserLoginResponse)
async def login(
    body: UserLoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
):
    """Login and receive JWT tokens with device binding."""
    client_ip = request.client.host if request.client else "unknown"

    # Rate limit: 5/min per IP AND 10/hour per email
    await sliding_window_rate_limit(redis, f"rate:login:ip:{client_ip}", 5, 60)
    await sliding_window_rate_limit(redis, f"rate:login:email:{body.email}", 10, 3600)

    # Authenticate
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account disabled",
        )

    # Device binding
    dfp = generate_device_fingerprint(request)

    # Create tokens
    access_token = create_access_token(user.id, user.role, user.email, dfp)
    refresh_token, jti = create_refresh_token(user.id)

    # Set refresh token as httpOnly cookie
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=settings.is_production,
        samesite="strict",
        max_age=settings.jwt_refresh_token_expire_days * 86400,
        path="/api/v1/auth",
    )

    return UserLoginResponse(access_token=access_token)


@router.post("/refresh", response_model=TokenRefreshResponse)
async def refresh(
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
):
    """Refresh access token using refresh_token cookie."""
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found",
        )

    payload = decode_token(refresh_token, expected_type="refresh")
    jti = payload.get("jti")

    # Check if jti is revoked
    if jti:
        is_revoked = await redis.exists(f"jti_revoked:{jti}")
        if is_revoked:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has been revoked",
            )

    # Fetch user to get current role
    user_id = uuid.UUID(payload["sub"])
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    dfp = generate_device_fingerprint(request)
    access_token = create_access_token(user.id, user.role, user.email, dfp)
    return TokenRefreshResponse(access_token=access_token)


@router.post("/logout", status_code=204)
async def logout(
    request: Request,
    response: Response,
    redis: Redis = Depends(get_redis),
):
    """Logout: revoke refresh token by adding its jti to Redis."""
    refresh_token = request.cookies.get("refresh_token")
    if refresh_token:
        try:
            # Decode without full verification to get jti for revocation
            payload = jwt.decode(
                refresh_token,
                settings.jwt_secret_key,
                algorithms=[settings.jwt_algorithm],
                options={"verify_exp": False},
            )
            jti = payload.get("jti")
            if jti:
                # Revoke for the full refresh token lifetime
                await redis.set(
                    f"jti_revoked:{jti}",
                    "1",
                    ex=settings.jwt_refresh_token_expire_days * 86400,
                )
        except Exception:
            pass  # Best effort — still clear the cookie

    response.delete_cookie(
        "refresh_token", path="/api/v1/auth", httponly=True, samesite="strict"
    )


@router.post("/scanner/create", response_model=ScannerDeviceCreateResponse)
async def create_scanner_device(
    body: ScannerDeviceCreateRequest,
    current_user: UserContext = Depends(rbac(["issuer", "admin"])),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a scanner device (ISSUER or ADMIN only).
    Returns the API key once — it cannot be retrieved again.
    """
    import base64
    from app.core.kms.provider import get_kms_client

    # Generate API key: 32 random bytes, base64url encoded
    api_key_bytes = os.urandom(32)
    api_key = base64.urlsafe_b64encode(api_key_bytes).decode('ascii').rstrip('=')

    # Store SHA-256 hash of the API key
    hashed_api_key = hashlib.sha256(api_key.encode()).hexdigest()

    hmac_secret_b = os.urandom(32)
    kms = get_kms_client()
    encrypted_hmac = await kms.encrypt(hmac_secret_b)

    device = ScannerDevice(
        issuer_id=current_user.id,
        name=body.name,
        hashed_api_key=hashed_api_key,
        encrypted_hmac_secret=encrypted_hmac,
        scopes=body.scopes,
    )
    db.add(device)
    await db.flush()

    return ScannerDeviceCreateResponse(
        device_id=device.id,
        api_key=api_key,
        hmac_secret=base64.urlsafe_b64encode(hmac_secret_b).decode('ascii').rstrip('='),
        name=device.name,
        scopes=device.scopes,
    )
