# =============================================================================
# SVT System — Cryptographic Engine
# =============================================================================
# Ed25519 signing/verification with KMS-backed envelope encryption.
# sign_payload accepts a dict; when a value is bytes (e.g. "d": D),
# it is preserved as-is in CBOR — CBOR natively represents bytes.
# =============================================================================

from __future__ import annotations

import base64
import ctypes
import hashlib
from typing import TYPE_CHECKING

import cbor2
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from app.core.kms.provider import get_kms_client

if TYPE_CHECKING:
    pass


class CryptoError(Exception):
    """Raised on any cryptographic operation failure."""

    def __init__(self, message: str, cause: Exception | None = None) -> None:
        super().__init__(message)
        self.cause = cause


def _zero_bytes(data: bytes | bytearray) -> None:
    """Zero out sensitive bytes in memory using ctypes.memset."""
    if isinstance(data, bytes):
        buf = ctypes.create_string_buffer(data)
        ctypes.memset(buf, 0, len(data))
    elif isinstance(data, bytearray):
        ctypes.memset((ctypes.c_char * len(data)).from_buffer(data), 0, len(data))


def _base64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(data: str) -> bytes:
    """Base64url decode with missing padding restoration."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


# =============================================================================
# Core Cryptographic Functions
# =============================================================================

async def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate an Ed25519 keypair.

    Returns:
        (public_key_raw_bytes, kms_encrypted_private_key_bytes)

    The plaintext private key is zeroed from memory before return.
    """
    try:
        signing_key = SigningKey.generate()
        public_key_bytes = bytes(signing_key.verify_key)
        private_key_bytes = bytes(signing_key)  # 32-byte seed

        kms_client = get_kms_client()

        # Encrypt private key under KMS
        encrypted_private_key = await kms_client.encrypt(private_key_bytes)

        # Zero the plaintext private key
        _zero_bytes(private_key_bytes)

        return public_key_bytes, encrypted_private_key

    except Exception as e:
        raise CryptoError("Keypair generation failed", cause=e) from e


async def get_private_key(encrypted_private_key: bytes) -> bytes:
    """
    Decrypt the private key using KMS.

    Returns:
        Plaintext private key bytes. Caller is responsible for zeroing after use.
    """
    try:
        kms_client = get_kms_client()
        return await kms_client.decrypt(encrypted_private_key)
    except Exception as e:
        raise CryptoError("Private key decryption failed", cause=e) from e


def canonical_encode(payload: dict) -> bytes:
    """
    CBOR-encode the payload with deterministic ordering.

    When a value in payload is bytes (e.g. "d": D), CBOR preserves it
    as a byte string — which is exactly what we need for the SVT envelope.

    Deterministic: same input always produces same output.
    """
    try:
        return cbor2.dumps(payload, canonical=True)
    except Exception as e:
        raise CryptoError("Canonical encoding failed", cause=e) from e


async def sign_payload(payload: dict, private_key_bytes: bytes) -> str:
    """
    Sign a payload using Ed25519.

    The payload dict is CBOR-encoded canonically before signing.
    Bytes values in the dict (e.g. 'd': D_bytes) are preserved as CBOR
    byte strings — ensuring the signature covers the exact binary form of D.

    Args:
        payload: Dictionary to sign. Values may be bytes, str, int, etc.
        private_key_bytes: Raw 32-byte Ed25519 private key seed

    Returns:
        Base64url-encoded (no padding) 64-byte Ed25519 signature

    The private_key_bytes are zeroed after use.
    """
    try:
        message = canonical_encode(payload)
        signing_key = SigningKey(private_key_bytes)
        signed = signing_key.sign(message)
        signature_bytes = signed.signature  # 64 bytes

        # Zero private key
        _zero_bytes(private_key_bytes)

        return _base64url_encode(signature_bytes)

    except Exception as e:
        _zero_bytes(private_key_bytes)
        raise CryptoError("Signing failed", cause=e) from e


def verify_payload(
    payload: dict, signature_b64url: str, public_key_bytes: bytes
) -> bool:
    """
    Verify an Ed25519 signature over a payload.

    Args:
        payload: Dictionary that was signed (same structure as given to sign_payload)
        signature_b64url: Base64url-encoded signature
        public_key_bytes: Raw 32-byte Ed25519 public key

    Returns:
        True if signature is valid, False otherwise.
        Never raises on invalid signature.
    """
    try:
        message = canonical_encode(payload)
        signature_bytes = _base64url_decode(signature_b64url)
        verify_key = VerifyKey(public_key_bytes)
        verify_key.verify(message, signature_bytes)
        return True
    except BadSignatureError:
        return False
    except Exception:
        return False


def compute_trace_id(data_bytes: bytes) -> str:
    """Compute trace_id as base64url(SHA-256(data_bytes))."""
    digest = hashlib.sha256(data_bytes).digest()
    return _base64url_encode(digest)
