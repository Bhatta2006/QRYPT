# =============================================================================
# SVT System — Stage 4 & 5 Compliance Tests (Blueprint-Strict)
# =============================================================================

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import cbor2
import pytest
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import generate_keypair, get_private_key, sign_payload, verify_payload
from app.models.issuer_key import IssuerKey
from app.models.scanner_device import ScannerDevice
from app.schemas.scan import ScanVerifyRequest
from app.schemas.token import TokenCreateRequest
from app.services.scan_service import verify_svt_token, _base64url_no_padding, _base64url_decode
from app.services.token_service import generate_svt_token


# ─── Helpers ──────────────────────────────────────────────────────────────────

def base64url_decode_pad(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


async def _build_valid_svt(issuer_id: uuid.UUID, pub_k: bytes, priv_k: bytes,
                            payload_url: str = "https://test.example.com",
                            expired: bool = False) -> tuple[str, str]:
    """Build a valid blueprint-compliant SVT. Returns (svt_raw, trace_id)."""
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    exp_ms = now_ms - 1000 if expired else now_ms + 3_600_000

    D_dict = {
        "issuer_id": issuer_id.bytes,
        "timestamp_ms": now_ms,
        "nonce": os.urandom(32),
        "payload_url": payload_url,
        "expires_at_ms": exp_ms,
    }
    D = cbor2.dumps(D_dict, canonical=True)
    trace_id = _base64url_no_padding(hashlib.sha256(D).digest())
    sig = await sign_payload({"d": D, "trace_id": trace_id}, priv_k)

    envelope = cbor2.dumps({"v": 1, "d": D, "trace_id": trace_id, "sig": sig}, canonical=True)
    svt_raw = _base64url_no_padding(envelope)
    return svt_raw, trace_id


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
        name="Test Scanner",
        hashed_api_key="x" * 64,
        encrypted_hmac_secret=b"\x00" * 48,  # placeholder encrypted bytes
        scopes=["scan:verify"],
    )


# ─── Task 1: Token Wire Format ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_token_wire_format_exactly():
    """
    Token generation must produce strict blueprint CBOR structure:
    {v:1, d:D_bytes, trace_id:str, sig:str}
    where trace_id = base64url(SHA256(D_bytes))
    """
    mock_db = AsyncMock(spec=AsyncSession)
    pub_k, enc_priv_k = await generate_keypair()
    priv_k = await get_private_key(enc_priv_k)
    issuer_id = uuid.uuid4()

    mock_key = IssuerKey(issuer_id=issuer_id, version=1, public_key=pub_k, encrypted_private_key=enc_priv_k)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_key
    mock_db.execute.return_value = mock_result
    mock_db.add = MagicMock()

    req = TokenCreateRequest(payload_url="https://example.com/pay/42", expires_in_hours=1)
    response = await generate_svt_token(mock_db, issuer_id, req)

    # Decode SVT
    raw_bytes = base64url_decode_pad(response.svt_raw)
    envelope = cbor2.loads(raw_bytes)

    # STRICT field check
    assert envelope["v"] == 1
    assert isinstance(envelope["d"], bytes)
    assert isinstance(envelope["trace_id"], str)
    assert isinstance(envelope["sig"], str)

    D = envelope["d"]
    trace_id = envelope["trace_id"]

    # trace_id must equal base64url(SHA256(D))
    expected_trace_id = _base64url_no_padding(hashlib.sha256(D).digest())
    assert trace_id == expected_trace_id
    assert trace_id == response.trace_id

    # D must decode to correct fields
    D_dict = cbor2.loads(D)
    assert D_dict["issuer_id"] == issuer_id.bytes
    assert D_dict["payload_url"] == "https://example.com/pay/42"
    assert isinstance(D_dict["timestamp_ms"], int)
    assert D_dict["expires_at_ms"] > 0
    assert len(D_dict["nonce"]) == 32

    # No JSON-style fields allowed
    assert "iat" not in D_dict
    assert "exp" not in D_dict
    assert "jti" not in D_dict
    assert "iss" not in D_dict


@pytest.mark.asyncio
async def test_signature_round_trip():
    """Signature over {d: D_bytes, trace_id} must be verifiable."""
    pub_k, enc_priv_k = await generate_keypair()
    priv_k = await get_private_key(enc_priv_k)
    issuer_id = uuid.uuid4()

    D_dict = {
        "issuer_id": issuer_id.bytes,
        "timestamp_ms": int(datetime.now(timezone.utc).timestamp() * 1000),
        "nonce": os.urandom(32),
        "payload_url": "https://test.com",
        "expires_at_ms": 0,
    }
    D = cbor2.dumps(D_dict, canonical=True)
    trace_id = _base64url_no_padding(hashlib.sha256(D).digest())

    sig = await sign_payload({"d": D, "trace_id": trace_id}, priv_k)
    assert verify_payload({"d": D, "trace_id": trace_id}, sig, pub_k) is True


@pytest.mark.asyncio
async def test_deterministic_cbor_same_d_same_trace_id():
    """Same D_dict (same nonce) must produce same trace_id."""
    issuer_id = uuid.uuid4()
    nonce = os.urandom(32)
    ts = int(datetime.now(timezone.utc).timestamp() * 1000)

    D_dict = {
        "issuer_id": issuer_id.bytes,
        "timestamp_ms": ts,
        "nonce": nonce,
        "payload_url": "https://determinism.test",
        "expires_at_ms": 0,
    }
    D1 = cbor2.dumps(D_dict, canonical=True)
    D2 = cbor2.dumps(D_dict, canonical=True)
    assert D1 == D2

    trace_id_1 = _base64url_no_padding(hashlib.sha256(D1).digest())
    trace_id_2 = _base64url_no_padding(hashlib.sha256(D2).digest())
    assert trace_id_1 == trace_id_2


# ─── Task 2: Idempotency ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_idempotency_redis_hit_returns_cached():
    """If idempotency key exists in Redis, return cached response without DB call."""
    from app.api.v1.tokens import create_token
    from app.core.security import UserContext

    cached_response = {
        "trace_id": "test-trace-id",
        "status": "ACTIVE",
        "expires_at": None,
        "qr_code_base64": "abc",
        "svt_raw": "def"
    }
    mock_redis = AsyncMock(spec=Redis)
    mock_redis.get = AsyncMock(return_value=json.dumps(cached_response).encode())
    mock_db = AsyncMock(spec=AsyncSession)

    user_ctx = UserContext(id=uuid.uuid4(), role="issuer", email="t@t.com")
    req = TokenCreateRequest(payload_url="https://x.com")

    result = await create_token(req, "idem-key-123", user_ctx, mock_db, mock_redis)

    # Should return from cache without calling DB
    assert result["trace_id"] == "test-trace-id"
    mock_db.execute.assert_not_called()
    # Verify redis.get was called with correct key
    mock_redis.get.assert_called_once_with(f"idempotency:{user_ctx.id}:idem-key-123")


@pytest.mark.asyncio
async def test_idempotency_redis_miss_generates_and_caches():
    """On Redis miss, generate token and cache it for 24h."""
    from app.api.v1.tokens import create_token
    from app.core.security import UserContext

    pub_k, enc_priv_k = await generate_keypair()
    issuer_id = uuid.uuid4()

    mock_key = IssuerKey(issuer_id=issuer_id, version=1, public_key=pub_k, encrypted_private_key=enc_priv_k)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_key

    mock_redis = AsyncMock(spec=Redis)
    mock_redis.get = AsyncMock(return_value=None)  # Cache miss
    mock_redis.set = AsyncMock()

    mock_db = AsyncMock(spec=AsyncSession)
    mock_db.execute.return_value = mock_result
    mock_db.add = MagicMock()

    user_ctx = UserContext(id=issuer_id, role="issuer", email="t@t.com")
    req = TokenCreateRequest(payload_url="https://idempotent.test", expires_in_hours=1)
    result = await create_token(req, "new-idem-key", user_ctx, mock_db, mock_redis)

    # Verify cache was set with 86400s TTL
    mock_redis.set.assert_called_once()
    call_args = mock_redis.set.call_args
    assert call_args[1]["ex"] == 86400
    assert f"idempotency:{issuer_id}:new-idem-key" == call_args[0][0]


# ─── Stage 5: Scanner Auth & HMAC ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_hmac_valid_signature_passes(mock_scanner):
    """Valid HMAC-SHA256 signature must result in successful auth."""
    from app.core.scanner_auth import get_current_scanner

    hmac_secret = os.urandom(32)
    from app.core.kms.provider import get_kms_client
    kms = get_kms_client()
    encrypted_secret = await kms.encrypt(hmac_secret)
    mock_scanner.encrypted_hmac_secret = encrypted_secret

    device_id = str(mock_scanner.id)
    timestamp = str(time.time())
    body = b'{"svt_raw":"test"}'

    msg = device_id.encode() + timestamp.encode() + body
    expected_sig = hmac.new(hmac_secret, msg, digestmod=hashlib.sha256).hexdigest()

    class MockRequest:
        headers = {
            "X-Device-Id": device_id,
            "X-Timestamp": timestamp,
            "X-Signature-SHA256": expected_sig,
        }
        client = type("C", (), {"host": "127.0.0.1"})()

        async def body(self):
            return body

    mock_db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_scanner
    mock_db.execute.return_value = mock_result

    mock_redis = AsyncMock(spec=Redis)
    mock_redis.set = AsyncMock(return_value=True)  # Replay key not set yet

    req = MockRequest()
    device = await get_current_scanner(req, mock_db, mock_redis)
    assert device.id == mock_scanner.id


@pytest.mark.asyncio
async def test_hmac_invalid_signature_rejected(mock_scanner):
    """Wrong HMAC signature must be rejected."""
    from app.core.scanner_auth import get_current_scanner
    from fastapi import HTTPException

    hmac_secret = os.urandom(32)
    from app.core.kms.provider import get_kms_client
    kms = get_kms_client()
    encrypted_secret = await kms.encrypt(hmac_secret)
    mock_scanner.encrypted_hmac_secret = encrypted_secret

    device_id = str(mock_scanner.id)
    timestamp = str(time.time())
    body = b'{"svt_raw":"test"}'

    class MockRequest:
        headers = {
            "X-Device-Id": device_id,
            "X-Timestamp": timestamp,
            "X-Signature-SHA256": "deadbeef" * 8,  # Wrong sig
        }
        client = type("C", (), {"host": "127.0.0.1"})()

        async def body(self):
            return body

    mock_db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_scanner
    mock_db.execute.return_value = mock_result

    mock_redis = AsyncMock(spec=Redis)
    mock_redis.set = AsyncMock(return_value=True)

    with pytest.raises(HTTPException) as exc:
        await get_current_scanner(MockRequest(), mock_db, mock_redis)
    assert exc.value.status_code == 401
    assert "HMAC" in exc.value.detail


@pytest.mark.asyncio
async def test_hmac_timestamp_drift_rejected():
    """Timestamps > 30s in the past must be rejected."""
    from app.core.scanner_auth import get_current_scanner
    from fastapi import HTTPException

    old_timestamp = str(time.time() - 60)  # 60s ago

    class MockRequest:
        headers = {
            "X-Device-Id": str(uuid.uuid4()),
            "X-Timestamp": old_timestamp,
            "X-Signature-SHA256": "abc",
        }
        client = type("C", (), {"host": "127.0.0.1"})()

        async def body(self):
            return b""

    mock_db = AsyncMock(spec=AsyncSession)
    mock_redis = AsyncMock(spec=Redis)

    with pytest.raises(HTTPException) as exc:
        await get_current_scanner(MockRequest(), mock_db, mock_redis)
    assert exc.value.status_code == 401
    assert "drift" in exc.value.detail


@pytest.mark.asyncio
async def test_replay_attack_rejected(mock_scanner):
    """Duplicate request (same sig + timestamp) must be rejected."""
    from app.core.scanner_auth import get_current_scanner
    from fastapi import HTTPException

    hmac_secret = os.urandom(32)
    from app.core.kms.provider import get_kms_client
    kms = get_kms_client()
    encrypted_secret = await kms.encrypt(hmac_secret)
    mock_scanner.encrypted_hmac_secret = encrypted_secret

    device_id = str(mock_scanner.id)
    timestamp = str(time.time())
    body = b'{}'

    msg = device_id.encode() + timestamp.encode() + body
    sig = hmac.new(hmac_secret, msg, digestmod=hashlib.sha256).hexdigest()

    class MockRequest:
        headers = {
            "X-Device-Id": device_id,
            "X-Timestamp": timestamp,
            "X-Signature-SHA256": sig,
        }
        client = type("C", (), {"host": "127.0.0.1"})()

        async def body(self):
            return body

    mock_db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_scanner
    mock_db.execute.return_value = mock_result

    mock_redis = AsyncMock(spec=Redis)
    # Simulate: first call succeeds (returns True), replay call fails (returns False/None)
    mock_redis.set = AsyncMock(return_value=None)  # NX set fails = already exists = replay

    with pytest.raises(HTTPException) as exc:
        await get_current_scanner(MockRequest(), mock_db, mock_redis)
    assert exc.value.status_code == 401
    assert "Replay" in exc.value.detail


# ─── Stage 5: SVT Verification Service ────────────────────────────────────────

@pytest.mark.asyncio
async def test_verify_svt_allow(mock_scanner):
    """Valid unrevoked SVT → ALLOW with correct URL."""
    pub_k, enc_priv_k = await generate_keypair()
    priv_k = await get_private_key(enc_priv_k)
    issuer_id = uuid.uuid4()

    svt_raw, trace_id = await _build_valid_svt(issuer_id, pub_k, priv_k)

    mock_db = AsyncMock(spec=AsyncSession)
    mock_key = IssuerKey(issuer_id=issuer_id, version=1, public_key=pub_k)
    mock_key_result = MagicMock()
    mock_key_result.scalar_one_or_none.return_value = mock_key

    # SVTToken for cache fallback
    from app.models.token import SVTToken
    mock_token = SVTToken(trace_id=trace_id, status="ACTIVE")
    mock_token_result = MagicMock()
    mock_token_result.scalar_one_or_none.return_value = mock_token

    call_count = [0]
    async def execute_side_effect(query):
        call_count[0] += 1
        # First call: SVTToken lookup; second call: IssuerKey lookup
        return mock_token_result if call_count[0] == 1 else mock_key_result

    mock_db.execute = execute_side_effect

    mock_redis = AsyncMock(spec=Redis)
    mock_redis.get = AsyncMock(return_value=None)  # cache miss
    mock_redis.set = AsyncMock()
    mock_redis.xadd = AsyncMock()

    with patch("app.services.scan_service._resolve_geoip", return_value=("US", "New York")):
        result = await verify_svt_token(mock_db, mock_redis, ScanVerifyRequest(svt_raw=svt_raw),
                                         mock_scanner, "2.2.2.2", "Mozilla/5.0", str(mock_scanner.id))

    assert result.result == "ALLOW"
    assert result.payload_url == "https://test.example.com"
    assert mock_redis.xadd.call_count == 2
    stream_names = [call[0][0] for call in mock_redis.xadd.call_args_list]
    assert "scan_events" in stream_names
    assert "anomaly_events" in stream_names

    # Check event schema
    event_data = json.loads(mock_redis.xadd.call_args[0][1]["event"])
    assert "device_fingerprint_hash" in event_data
    assert "country_code" in event_data
    assert "city_name" in event_data
    assert event_data["country_code"] == "US"


@pytest.mark.asyncio
async def test_verify_svt_cache_hit_no_db_query(mock_scanner):
    """Redis cache hit should avoid DB svt_token lookup."""
    pub_k, enc_priv_k = await generate_keypair()
    priv_k = await get_private_key(enc_priv_k)
    issuer_id = uuid.uuid4()

    svt_raw, trace_id = await _build_valid_svt(issuer_id, pub_k, priv_k)

    mock_db = AsyncMock(spec=AsyncSession)
    mock_key_result = MagicMock()
    mock_key_result.scalar_one_or_none.return_value = IssuerKey(
        issuer_id=issuer_id, version=1, public_key=pub_k
    )
    call_count = [0]
    async def execute_side_effect(query):
        call_count[0] += 1
        return mock_key_result

    mock_db.execute = execute_side_effect

    mock_redis = AsyncMock(spec=Redis)
    # svt cache HIT for token status
    mock_redis.get = AsyncMock(side_effect=[b"ACTIVE", None])  # 1st=svt cache, 2nd=pubkey cache
    mock_redis.set = AsyncMock()
    mock_redis.xadd = AsyncMock()

    with patch("app.services.scan_service._resolve_geoip", return_value=(None, None)):
        result = await verify_svt_token(mock_db, mock_redis, ScanVerifyRequest(svt_raw=svt_raw),
                                         mock_scanner, "1.1.1.1", "curl", str(mock_scanner.id))

    # DB was only called once (for pubkey), NOT for token status
    assert call_count[0] == 1
    assert result.result == "ALLOW"


@pytest.mark.asyncio
async def test_verify_svt_expired_returns_deny(mock_scanner):
    """Expired token → DENY."""
    pub_k, enc_priv_k = await generate_keypair()
    priv_k = await get_private_key(enc_priv_k)
    issuer_id = uuid.uuid4()

    svt_raw, trace_id = await _build_valid_svt(issuer_id, pub_k, priv_k, expired=True)

    mock_db = AsyncMock(spec=AsyncSession)
    mock_key_result = MagicMock()
    mock_key_result.scalar_one_or_none.return_value = IssuerKey(
        issuer_id=issuer_id, version=1, public_key=pub_k
    )
    mock_token_result = MagicMock()
    from app.models.token import SVTToken
    mock_token_result.scalar_one_or_none.return_value = SVTToken(trace_id=trace_id, status="ACTIVE")

    call_count = [0]
    async def execute_side_effect(query):
        call_count[0] += 1
        return mock_token_result if call_count[0] == 1 else mock_key_result

    mock_db.execute = execute_side_effect

    mock_redis = AsyncMock(spec=Redis)
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.set = AsyncMock()
    mock_redis.xadd = AsyncMock()

    with patch("app.services.scan_service._resolve_geoip", return_value=(None, None)):
        result = await verify_svt_token(mock_db, mock_redis, ScanVerifyRequest(svt_raw=svt_raw),
                                         mock_scanner, None, None, None)

    assert result.result == "DENY"
    assert "expired" in result.reason.lower()


@pytest.mark.asyncio
async def test_verify_svt_tampered_trace_denied(mock_scanner):
    """Tampered trace_id must fail integrity check before sig verification."""
    pub_k, enc_priv_k = await generate_keypair()
    priv_k = await get_private_key(enc_priv_k)
    issuer_id = uuid.uuid4()

    svt_raw, real_trace_id = await _build_valid_svt(issuer_id, pub_k, priv_k)

    # Decode SVT, tamper trace_id
    raw_bytes = base64url_decode_pad(svt_raw)
    envelope = cbor2.loads(raw_bytes)
    envelope["trace_id"] = "tampered-trace-id"
    tampered_raw = _base64url_no_padding(cbor2.dumps(envelope, canonical=True))

    mock_db = AsyncMock(spec=AsyncSession)
    mock_redis = AsyncMock(spec=Redis)
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.set = AsyncMock()
    mock_redis.xadd = AsyncMock()

    result = await verify_svt_token(mock_db, mock_redis, ScanVerifyRequest(svt_raw=tampered_raw),
                                     mock_scanner, None, None, None)
    assert result.result == "DENY"
    assert "integrity" in result.reason.lower()


@pytest.mark.asyncio
async def test_verify_svt_wrong_version_denied(mock_scanner):
    """v != 1 must be rejected."""
    pub_k, enc_priv_k = await generate_keypair()
    priv_k = await get_private_key(enc_priv_k)
    issuer_id = uuid.uuid4()

    svt_raw, _ = await _build_valid_svt(issuer_id, pub_k, priv_k)
    raw_bytes = base64url_decode_pad(svt_raw)
    envelope = cbor2.loads(raw_bytes)
    envelope["v"] = 2
    bad_raw = _base64url_no_padding(cbor2.dumps(envelope, canonical=True))

    mock_db = AsyncMock(spec=AsyncSession)
    mock_redis = AsyncMock(spec=Redis)
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.set = AsyncMock()

    result = await verify_svt_token(mock_db, mock_redis, ScanVerifyRequest(svt_raw=bad_raw),
                                     mock_scanner, None, None, None)
    assert result.result == "DENY"
    assert "version" in result.reason.lower()


# ─── GeoIP Tests ──────────────────────────────────────────────────────────────

def test_geoip_invalid_ip_graceful():
    """Invalid IP must return (None, None) without raising."""
    from app.services.scan_service import _resolve_geoip
    result = _resolve_geoip("999.999.999.999")
    assert result == (None, None)


def test_geoip_none_ip_graceful():
    from app.services.scan_service import _resolve_geoip
    assert _resolve_geoip(None) == (None, None)


# ─── Stream Schema Tests ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_telemetry_stream_name_and_schema(mock_scanner):
    """Telemetry must publish to 'scan_events' with correct schema."""
    from app.services.scan_service import _emit_telemetry

    mock_redis = AsyncMock(spec=Redis)
    mock_redis.xadd = AsyncMock()

    await _emit_telemetry(
        redis=mock_redis,
        trace_id="abc123",
        result="ALLOW",
        scanner=mock_scanner,
        client_ip="8.8.8.8",
        user_agent="TestAgent/1.0",
        device_id="device-uuid",
    )

    assert mock_redis.xadd.call_count == 2

    # Verify both stream names were used
    stream_names = [call[0][0] for call in mock_redis.xadd.call_args_list]
    assert "scan_events" in stream_names
    assert "anomaly_events" in stream_names

    # Get the payload from the first call
    stream_name, payload = mock_redis.xadd.call_args_list[0][0]

    event = json.loads(payload["event"])
    required_fields = {"trace_id", "result", "ip_hash", "country_code", "city_name",
                        "user_agent", "device_id", "device_fingerprint_hash",
                        "scanner_device_id", "timestamp"}
    assert required_fields.issubset(event.keys())

    # Device fingerprint correctness
    expected_dfp = hashlib.sha256(("TestAgent/1.0" + "device-uuid").encode()).hexdigest()
    assert event["device_fingerprint_hash"] == expected_dfp
