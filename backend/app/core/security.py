# =============================================================================
# SVT System — Security: JWT + RBAC
# =============================================================================

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import get_settings

settings = get_settings()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


@dataclass
class UserContext:
    """Authenticated user context extracted from JWT."""

    id: uuid.UUID
    role: str
    email: str


def hash_password(password: str) -> str:
    """Hash a password using bcrypt with 12 rounds."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(
    user_id: uuid.UUID, role: str, email: str
) -> str:
    """Create a short-lived access token (15 min default)."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "role": role,
        "email": email,
        "jti": str(uuid.uuid4()),
        "iss": "svt",
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_access_token_expire_minutes),
        "type": "access",
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def create_refresh_token(user_id: uuid.UUID) -> tuple[str, str]:
    """
    Create a long-lived refresh token (7 days default).

    Returns:
        (encoded_jwt, jti) — the jti is needed for revocation tracking
    """
    now = datetime.now(timezone.utc)
    jti = str(uuid.uuid4())
    payload = {
        "sub": str(user_id),
        "jti": jti,
        "iss": "svt",
        "iat": now,
        "exp": now + timedelta(days=settings.jwt_refresh_token_expire_days),
        "type": "refresh",
    }
    token = jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return token, jti


def decode_token(token: str, expected_type: str = "access") -> dict:
    """
    Decode and validate a JWT token.

    Raises HTTPException on invalid token.
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            options={"require_exp": True, "require_iat": True},
        )
        if payload.get("type") != expected_type:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token type: expected {expected_type}",
            )
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {e!s}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e


async def get_current_user(
    token: str = Depends(oauth2_scheme),
) -> UserContext:
    """
    FastAPI dependency: extract and validate user from access token.
    """
    payload = decode_token(token, expected_type="access")
    try:
        user_id = uuid.UUID(payload["sub"])
        role = payload["role"]
        email = payload["email"]
    except (KeyError, ValueError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token claims",
        ) from e
    return UserContext(id=user_id, role=role, email=email)


def rbac(roles: list[str]):
    """
    FastAPI dependency factory: enforce RBAC on routes.

    Usage: `Depends(rbac(["admin", "issuer"]))`
    """

    async def _rbac_check(
        current_user: UserContext = Depends(get_current_user),
    ) -> UserContext:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {roles}",
            )
        return current_user

    return _rbac_check
