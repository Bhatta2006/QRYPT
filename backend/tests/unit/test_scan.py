# =============================================================================
# SVT System — test_scan.py (Updated for blueprint wire format)
# =============================================================================
# Old format tests replaced — blueprint compliance tested in test_stage4_5_compliance.py
# This file retains basic backward-compat smoke tests using the real wire format.
# =============================================================================

from __future__ import annotations

import base64
import hashlib
import os
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import cbor2
import pytest
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import generate_keypair, get_private_key, sign_payload
from app.models.issuer_key import IssuerKey
from app.models.scanner_device import ScannerDevice
from app.models.token import SVTToken
from app.schemas.scan import ScanVerifyRequest
from app.services.scan_service import verify_svt_token, _base64url_no_padding


@pytest.fixture(autouse=True)
def setup_mock_kms():
    from app.core.kms.mock_kms import MockKMSClient
    import app.core.kms.provider as kms_provider
    kms_provider._kms_client = MockKMSClient()
    yield
    kms_provider._kms_client = None


@pytest.fixture
def mock_scanner():
    return ScannerDevice(
        id=uuid.uuid4(),
        issuer_id=uuid.uuid4(),
        name="Test Scanner 1",
        hashed_api_key="x" * 64,
        encrypted_hmac_secret=b"\x00" * 48,
        scopes=["scan:verify"],
    )


async def build_valid_svt_raw(issuer_id, key_version, payload_url, private_key_b, public_key_b, expired=False):
    """Build a blueprint-compliant SVT."""
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    exp_ms = (now_ms - 60_000) if expired else (now_ms + 3_600_000)

    D_dict = {
        "issuer_id": issuer_id.bytes,
        "timestamp_ms": now_ms,
        "nonce": os.urandom(32),
        "payload_url": payload_url,
        "expires_at_ms": exp_ms,
    }
    D = cbor2.dumps(D_dict, canonical=True)
    trace_id = _base64url_no_padding(hashlib.sha256(D).digest())
    sig = await sign_payload({"d": D, "trace_id": trace_id}, private_key_b)

    envelope = cbor2.dumps({"v": 1, "d": D, "trace_id": trace_id, "sig": sig}, canonical=True)
    return _base64url_no_padding(envelope)


@pytest.mark.asyncio
async def test_verify_svt_token_allow(mock_scanner):
    mock_db = AsyncMock(spec=AsyncSession)
    mock_redis = AsyncMock(spec=Redis)

    pub_k, enc_priv_k = await generate_keypair()
    priv_k = await get_private_key(enc_priv_k)

    issuer_id = uuid.uuid4()
    svt_raw = await build_valid_svt_raw(issuer_id, 1, "https://secure.example.com", priv_k, pub_k)

    mock_token = SVTToken(trace_id="any", status="ACTIVE")
    mock_key = IssuerKey(issuer_id=issuer_id, version=1, public_key=pub_k)

    call_count = [0]
    mock_token_result = MagicMock(); mock_token_result.scalar_one_or_none.return_value = mock_token
    mock_key_result = MagicMock(); mock_key_result.scalar_one_or_none.return_value = mock_key

    async def execute_side_effect(query):
        call_count[0] += 1
        return mock_token_result if call_count[0] == 1 else mock_key_result

    mock_db.execute = execute_side_effect
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.set = AsyncMock()
    mock_redis.xadd = AsyncMock()

    req = ScanVerifyRequest(svt_raw=svt_raw)
    res = await verify_svt_token(mock_db, mock_redis, req, mock_scanner, "127.0.0.1", "curl/7.68.0", str(mock_scanner.id))

    assert res.result == "ALLOW"
    assert res.payload_url == "https://secure.example.com"
    assert mock_redis.xadd.call_count == 2
    stream_names = [call[0][0] for call in mock_redis.xadd.call_args_list]
    assert "scan_events" in stream_names
    assert "anomaly_events" in stream_names


@pytest.mark.asyncio
async def test_verify_svt_token_expired(mock_scanner):
    mock_db = AsyncMock(spec=AsyncSession)
    mock_redis = AsyncMock(spec=Redis)

    pub_k, enc_priv_k = await generate_keypair()
    priv_k = await get_private_key(enc_priv_k)

    issuer_id = uuid.uuid4()
    svt_raw = await build_valid_svt_raw(issuer_id, 1, "https://expired.example.com", priv_k, pub_k, expired=True)

    mock_token = SVTToken(trace_id="any", status="ACTIVE")
    mock_key = IssuerKey(issuer_id=issuer_id, version=1, public_key=pub_k)

    call_count = [0]
    mock_token_result = MagicMock(); mock_token_result.scalar_one_or_none.return_value = mock_token
    mock_key_result = MagicMock(); mock_key_result.scalar_one_or_none.return_value = mock_key

    async def execute_side_effect(query):
        call_count[0] += 1
        return mock_token_result if call_count[0] == 1 else mock_key_result

    mock_db.execute = execute_side_effect
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.set = AsyncMock()
    mock_redis.xadd = AsyncMock()

    req = ScanVerifyRequest(svt_raw=svt_raw)
    res = await verify_svt_token(mock_db, mock_redis, req, mock_scanner, "127.0.0.1", "curl", str(mock_scanner.id))

    assert res.result == "DENY"
    assert "expired" in res.reason.lower()


@pytest.mark.asyncio
async def test_verify_svt_token_revoked(mock_scanner):
    """Token with REVOKED status in Redis cache → DENY."""
    mock_db = AsyncMock(spec=AsyncSession)
    mock_redis = AsyncMock(spec=Redis)

    pub_k, enc_priv_k = await generate_keypair()
    priv_k = await get_private_key(enc_priv_k)

    issuer_id = uuid.uuid4()
    svt_raw = await build_valid_svt_raw(issuer_id, 1, "https://x.com", priv_k, pub_k)

    # Simulate cache returning REVOKED status
    mock_redis.get = AsyncMock(return_value=b"REVOKED")
    mock_redis.set = AsyncMock()
    mock_redis.xadd = AsyncMock()

    req = ScanVerifyRequest(svt_raw=svt_raw)
    res = await verify_svt_token(mock_db, mock_redis, req, mock_scanner, "10.0.0.1", "safari", str(mock_scanner.id))

    assert res.result == "DENY"
    assert "revoked" in res.reason.lower()


@pytest.mark.asyncio
async def test_verify_svt_token_invalid_format(mock_scanner):
    mock_db = AsyncMock(spec=AsyncSession)
    mock_redis = AsyncMock(spec=Redis)
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.set = AsyncMock()

    req = ScanVerifyRequest(svt_raw="not_a_valid_b64url_cbor_string")
    res = await verify_svt_token(mock_db, mock_redis, req, mock_scanner, "127.0.0.1", None, None)

    assert res.result == "CANNOT_VERIFY"
    assert "Malformed" in res.reason
