# =============================================================================
# SVT System — Scan Verification Data Classes
# =============================================================================

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ScanVerifyRequest(BaseModel):
    """Encapsulates the payload received from physically scanning the SVT."""

    svt_raw: str = Field(
        ...,
        description="The raw CBOR + Base64url envelope string parsed from the SVT."
    )
    # Optional device telemetry attached sequentially by the physical scanner software
    device_fingerprint_override: str | None = None
    telemetry_lat: float | None = None
    telemetry_lng: float | None = None


class ScanVerifyResponse(BaseModel):
    """The normalized verdict routing directive transmitted back to the scanner."""

    result: Literal["ALLOW", "DENY", "WARN", "CANNOT_VERIFY"]
    payload_url: str | None = Field(
        default=None,
        description="The authorized payload destination. Suppressed strictly on DENY.",
    )
    reason: str | None = Field(
        default=None,
        description="Contextual diagnostic string regarding the verdict.",
    )
