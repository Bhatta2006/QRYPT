# =============================================================================
# SVT System — Auth Schemas (Pydantic)
# =============================================================================

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class UserRegisterRequest(BaseModel):
    """Registration request schema."""

    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class UserRegisterResponse(BaseModel):
    """Registration response schema."""

    user_id: uuid.UUID
    email: str
    role: str


class UserLoginRequest(BaseModel):
    """Login request schema."""

    email: EmailStr
    password: str


class UserLoginResponse(BaseModel):
    """Login response schema (access token in body)."""

    access_token: str
    token_type: str = "bearer"


class TokenRefreshResponse(BaseModel):
    """Token refresh response."""

    access_token: str
    token_type: str = "bearer"


class ScannerDeviceCreateRequest(BaseModel):
    """Scanner device creation request."""

    name: str = Field(min_length=1, max_length=255)
    scopes: list[str] = Field(default=["scan:verify"])


class ScannerDeviceCreateResponse(BaseModel):
    """Scanner device creation response (API key returned once)."""

    device_id: uuid.UUID
    api_key: str  # One-time display only
    hmac_secret: str # Base64url encoded
    name: str
    scopes: list[str]
