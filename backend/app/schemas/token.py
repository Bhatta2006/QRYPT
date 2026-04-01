# =============================================================================
# SVT System — Token Schemas
# =============================================================================

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class TokenCreateRequest(BaseModel):
    """Payload details for generating a new SVT."""

    payload_url: str = Field(
        ...,
        max_length=2048,
        description="The target URL or URI the QR code will direct to after verification.",
    )
    expires_in_hours: int | None = Field(
        None,
        ge=1,
        le=8760,
        description="Optional expiration limit in hours from creation.",
    )


class TokenResponse(BaseModel):
    """Response containing SVT generation details and the raw QR image."""

    trace_id: str
    status: str
    expires_at: datetime | None = None
    qr_code_base64: str = Field(
        ...,
        description="Base64-encoded PNG image of the standard QR Code containing the SVT.",
    )
    svt_raw: str = Field(
        ...,
        description="The raw CBOR + Base64url encoded envelope for manual testing/transport.",
    )


class TokenDetailsResponse(BaseModel):
    """Detailed view of an existing token."""

    id: uuid.UUID
    trace_id: str
    payload_url: str
    status: str
    created_at: datetime
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    revocation_reason: str | None = None
