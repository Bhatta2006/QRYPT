# =============================================================================
# SVT System — Crypto and Security Unit Tests
# =============================================================================

from __future__ import annotations

import copy
import os
import uuid
import pytest

from app.core.crypto import (
    CryptoError,
    _base64url_decode,
    _base64url_encode,
    canonical_encode,
    compute_trace_id,
    generate_keypair,
    get_private_key,
    sign_payload,
    verify_payload,
)

from app.core.kms.interface import KMSClient
from app.core.kms.mock_kms import MockKMSClient
import app.core.kms.provider as kms_provider

from fastapi import Request

@pytest.fixture(autouse=True)
def setup_mock_kms():
    """Ensure KMS interface relies on the mock KMS implementation."""
    kms_provider._kms_client = MockKMSClient()
    yield
    kms_provider._kms_client = None

class TestBase64URL:
    """Test base64url encoding/decoding."""

    def test_round_trip(self) -> None:
        data = os.urandom(32)
        encoded = _base64url_encode(data)
        decoded = _base64url_decode(encoded)
        assert decoded == data

    def test_no_padding(self) -> None:
        encoded = _base64url_encode(b"hello")
        assert "=" not in encoded

    def test_url_safe_chars(self) -> None:
        data = bytes(range(256))
        encoded = _base64url_encode(data)
        assert "+" not in encoded
        assert "/" not in encoded


class TestCanonicalEncode:
    """Test CBOR canonical encoding determinism."""

    def test_deterministic_across_calls(self) -> None:
        payload = {"z": 1, "a": 2, "m": "hello"}
        results = [canonical_encode(payload) for _ in range(1000)]
        assert all(r == results[0] for r in results)

    def test_key_order_independent(self) -> None:
        payload_a = {"b": 2, "a": 1}
        payload_b = {"a": 1, "b": 2}
        assert canonical_encode(payload_a) == canonical_encode(payload_b)

    def test_nested_dict(self) -> None:
        payload = {"outer": {"z": 1, "a": 2}}
        result = canonical_encode(payload)
        assert isinstance(result, bytes)
        assert len(result) > 0


@pytest.mark.asyncio
class TestKeyGeneration:
    """Test Ed25519 keypair generation with KMS interface."""

    async def test_generate_keypair(self) -> None:
        public_key, encrypted_private_key = await generate_keypair()
        assert len(public_key) == 32
        assert len(encrypted_private_key) > 32  # encrypted = nonce + ciphertext

    async def test_different_keypairs(self) -> None:
        pk1, _ = await generate_keypair()
        pk2, _ = await generate_keypair()
        assert pk1 != pk2

    async def test_private_key_recovery(self) -> None:
        _, encrypted_pk = await generate_keypair()
        recovered = await get_private_key(encrypted_pk)
        assert len(recovered) == 32


@pytest.mark.asyncio
class TestSignVerify:
    """Test Ed25519 sign and verify operations."""

    async def test_sign_verify_round_trip_10(self) -> None:
        for _ in range(10):
            public_key, encrypted_pk = await generate_keypair()
            payload = {
                "id": str(uuid.uuid4()),
                "data": os.urandom(16).hex(),
                "number": int.from_bytes(os.urandom(4), "big"),
                "kid": 1,
            }
            private_key = await get_private_key(encrypted_pk)
            signature = await sign_payload(payload, private_key)
            assert verify_payload(payload, signature, public_key) is True

    async def test_tampered_payload_fails(self) -> None:
        public_key, encrypted_pk = await generate_keypair()
        payload = {"message": "original"}
        private_key = await get_private_key(encrypted_pk)
        signature = await sign_payload(payload, private_key)

        tampered = {"message": "tampered"}
        assert verify_payload(tampered, signature, public_key) is False

    async def test_wrong_public_key_fails(self) -> None:
        pk_a, enc_pk_a = await generate_keypair()
        pk_b, _ = await generate_keypair()

        payload = {"test": "cross-key"}
        private_key = await get_private_key(enc_pk_a)
        signature = await sign_payload(payload, private_key)

        assert verify_payload(payload, signature, pk_a) is True
        assert verify_payload(payload, signature, pk_b) is False

    async def test_empty_payload(self) -> None:
        public_key, encrypted_pk = await generate_keypair()
        payload: dict = {}
        private_key = await get_private_key(encrypted_pk)
        signature = await sign_payload(payload, private_key)
        assert verify_payload(payload, signature, public_key) is True


class TestComputeTraceId:
    def test_deterministic(self) -> None:
        data = b"test data"
        t1 = compute_trace_id(data)
        t2 = compute_trace_id(data)
        assert t1 == t2

    def test_different_input_different_id(self) -> None:
        t1 = compute_trace_id(b"data1")
        t2 = compute_trace_id(b"data2")
        assert t1 != t2

# =============================================================================
# Device Fingerprint Tests
# =============================================================================
from app.core.security.device import generate_device_fingerprint

class DummyRequest:
    def __init__(self, headers: dict, host: str):
        self.headers = headers
        self.client = type("Client", (), {"host": host})()

def test_device_fingerprint_generation():
    req1 = DummyRequest({"User-Agent": "Mozilla", "Accept-Language": "en-US"}, "1.2.3.4")
    req2 = DummyRequest({"User-Agent": "Mozilla", "Accept-Language": "en-US"}, "1.2.3.4")
    req3 = DummyRequest({"User-Agent": "Chrome", "Accept-Language": "en-US"}, "1.2.3.4")
    req4 = DummyRequest({"User-Agent": "Mozilla", "Accept-Language": "fr-FR"}, "1.2.3.4")
    
    fp1 = generate_device_fingerprint(req1)
    fp2 = generate_device_fingerprint(req2)
    fp3 = generate_device_fingerprint(req3)
    fp4 = generate_device_fingerprint(req4)
    
    assert fp1 == fp2  # Identical requests
    assert fp1 != fp3  # User-Agent modification
    assert fp1 != fp4  # Accept-Language modification
