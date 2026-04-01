# =============================================================================
# SVT System — KMS Interface
# =============================================================================

from abc import ABC, abstractmethod


class KMSClient(ABC):
    """Abstract interface for Key Management Service operations."""

    @abstractmethod
    async def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext securely using the KMS."""
        pass

    @abstractmethod
    async def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext securely using the KMS."""
        pass
