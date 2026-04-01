# =============================================================================
# SVT System — Token Generation Service
# =============================================================================

from __future__ import annotations

import base64
import hashlib
import io
import os
import uuid
from datetime import datetime, timedelta, timezone

import cbor2
import qrcode
from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import get_private_key, sign_payload
from app.models.issuer_key import IssuerKey
from app.models.token import SVTToken
from app.schemas.token import TokenCreateRequest, TokenResponse


def base64url_no_padding(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


async def generate_svt_token(
    db: AsyncSession, issuer_id: uuid.UUID, request: TokenCreateRequest
) -> TokenResponse:
    """
    Generate an SVT token following STRICT DETACHED CBOR deterministic formats.
    """
    # 1. Fetch the latest active key for the issuer
    result = await db.execute(
        select(IssuerKey)
        .where(IssuerKey.issuer_id == issuer_id)
        .order_by(IssuerKey.version.desc())
        .limit(1)
    )
    active_key = result.scalar_one_or_none()

    if not active_key:
        raise HTTPException(
            status_code=500, detail="Issuer has no active cryptographic keys."
        )

    # 2. Construct deterministic D_dict payload EXACTLY as mandated
    now = datetime.now(timezone.utc)
    current_ms = int(now.timestamp() * 1000)
    
    expires_at = None
    exp_ms = 0
    if request.expires_in_hours:
        expires_at = now + timedelta(hours=request.expires_in_hours)
        exp_ms = int(expires_at.timestamp() * 1000)

    # Schema must strictly follow Blueprint types
    D_dict = {
        "issuer_id": issuer_id.bytes,
        "timestamp_ms": current_ms,
        "nonce": os.urandom(32),
        "payload_url": request.payload_url,
        "expires_at_ms": exp_ms
    }

    # 3. Canonical CBOR serialization -> Base64url trace_id
    D = cbor2.dumps(D_dict, canonical=True)
    trace_id_bytes = hashlib.sha256(D).digest()
    trace_id = base64url_no_padding(trace_id_bytes)

    # 4. Asymmetric Deterministic Ed25519 Signature
    private_key_bytes = await get_private_key(active_key.encrypted_private_key)
    # ONLY sign canonical byte mapping of D
    signature = await sign_payload(
        {"d": D, "trace_id": trace_id},
        private_key_bytes
    )
    # MUST zero private_key_bytes from memory (crypto.py already zeroes it!)
    from app.core.crypto import _zero_bytes
    _zero_bytes(private_key_bytes)

    # 5. Build strict QR CBOR payload
    qr_payload_dict = {
        "v": 1,
        "d": D,
        "trace_id": trace_id,
        "sig": signature
    }
    
    qr_payload_bytes = cbor2.dumps(qr_payload_dict, canonical=True)
    svt_raw = base64url_no_padding(qr_payload_bytes)

    # 6. Database storage
    token_record = SVTToken(
        trace_id=trace_id,
        issuer_id=issuer_id,
        payload_url=request.payload_url,
        status="ACTIVE",
        nonce=base64url_no_padding(D_dict["nonce"]),
        signature=signature,
        expires_at=expires_at,
    )
    db.add(token_record)

    # 7. Rendering QR code Image
    qr_data = f"svt://{svt_raw}"
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    qr_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

    return TokenResponse(
        trace_id=trace_id,
        status="ACTIVE",
        expires_at=expires_at,
        qr_code_base64=qr_base64,
        svt_raw=svt_raw,
    )
