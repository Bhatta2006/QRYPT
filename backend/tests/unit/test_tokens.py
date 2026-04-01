# =============================================================================
# SVT System — Token Generation Tests (Updated for blueprint wire format)
# =============================================================================

from __future__ import annotations

import base64
import hashlib
import uuid
from unittest.mock import AsyncMock, MagicMock

import cbor2
import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException

from app.core.crypto import generate_keypair
from app.models.issuer_key import IssuerKey
from app.schemas.token import TokenCreateRequest
from app.services.token_service import generate_svt_token, base64url_no_padding


@pytest.fixture(autouse=True)
def setup_mock_kms():
    from app.core.kms.mock_kms import MockKMSClient
    import app.core.kms.provider as kms_provider
    kms_provider._kms_client = MockKMSClient()
    yield
    kms_provider._kms_client = None


@pytest.mark.asyncio
async def test_generate_svt_token_success():
    """Verify SVT token builds blueprint-compliant CBOR envelope."""
    mock_db = AsyncMock(spec=AsyncSession)

    public_key, encrypted_private_key = await generate_keypair()
    issuer_id = uuid.uuid4()

    mock_scalar = MagicMock(return_value=IssuerKey(
        issuer_id=issuer_id,
        version=1,
        public_key=public_key,
        encrypted_private_key=encrypted_private_key
    ))
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = mock_scalar
    mock_db.execute.return_value = mock_result
    mock_db.add = MagicMock()

    request = TokenCreateRequest(payload_url="https://secure.example.com/pay/123", expires_in_hours=24)
    response = await generate_svt_token(mock_db, issuer_id, request)

    assert response.status == "ACTIVE"
    assert response.trace_id is not None
    assert response.expires_at is not None
    assert response.qr_code_base64.startswith("iVBORw0KGgo")  # PNG magic bytes in b64
    assert response.svt_raw is not None

    # Validate DB addition
    mock_db.add.assert_called_once()
    token_record = mock_db.add.call_args[0][0]
    assert token_record.trace_id == response.trace_id
    assert token_record.payload_url == "https://secure.example.com/pay/123"

    # Decode the SVT Raw envelope and verify blueprint structure
    padding = 4 - len(response.svt_raw) % 4
    cbor_bytes = base64.urlsafe_b64decode(response.svt_raw + ("=" * padding if padding != 4 else ""))
    envelope = cbor2.loads(cbor_bytes)

    # Blueprint format: {v:1, d:bytes, trace_id:str, sig:str}
    assert envelope["v"] == 1
    assert isinstance(envelope["d"], bytes)
    assert isinstance(envelope["trace_id"], str)
    assert isinstance(envelope["sig"], str)

    # trace_id = base64url(SHA256(D))
    D = envelope["d"]
    expected_trace_id = base64url_no_padding(hashlib.sha256(D).digest())
    assert envelope["trace_id"] == expected_trace_id
    assert response.trace_id == expected_trace_id

    # D must contain required blueprint fields, no JWT-style fields
    D_dict = cbor2.loads(D)
    assert D_dict["issuer_id"] == issuer_id.bytes
    assert D_dict["payload_url"] == "https://secure.example.com/pay/123"
    assert "iat" not in D_dict
    assert "exp" not in D_dict
    assert "jti" not in D_dict


@pytest.mark.asyncio
async def test_generate_svt_token_no_active_keys():
    """Verify missing keys cause HTTP 500 error instead of failing silently."""
    mock_db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = mock_result

    request = TokenCreateRequest(payload_url="https://x.com")

    with pytest.raises(HTTPException) as exc:
        await generate_svt_token(mock_db, uuid.uuid4(), request)

    assert exc.value.status_code == 500
    assert "no active cryptographic keys" in exc.value.detail
