# =============================================================================
# SVT System — Mock KMS Client
# =============================================================================

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.kms.interface import KMSClient


class MockKMSClient(KMSClient):
    """
    Mock KMS for development.
    Uses AES-256-GCM with a random key strictly generated at runtime.
    WARNING: Dev data encrypted here is non-recoverable after process restart.
    """

    def __init__(self) -> None:
        """Generate a random 32-byte master key per process."""
        self._master_key = os.urandom(32)

    async def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt using AES-256-GCM."""
        nonce = os.urandom(12)
        aesgcm = AESGCM(self._master_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        # Prepend nonce to ciphertext
        return nonce + ciphertext

    async def decrypt(self, ciphertext_blob: bytes) -> bytes:
        """Decrypt using AES-256-GCM."""
        nonce = ciphertext_blob[:12]
        ciphertext = ciphertext_blob[12:]
        aesgcm = AESGCM(self._master_key)
        # Exceptions (e.g., InvalidTag) will propagate up
        return aesgcm.decrypt(nonce, ciphertext, None)
