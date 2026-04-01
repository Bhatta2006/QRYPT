# =============================================================================
# SVT System — GCP KMS Client
# =============================================================================

from google.cloud import kms  # type: ignore

from app.core.kms.interface import KMSClient


class GCPKMSClient(KMSClient):
    """Google Cloud KMS implementation for production."""

    def __init__(self, key_name: str) -> None:
        """
        Initialize GCP KMS Client.
        :param key_name: Full resource name of the crypto key.
        """
        self._client = kms.KeyManagementServiceAsyncClient()
        self._key_name = key_name

    async def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt using GCP KMS."""
        # Using the async client syntax
        request = {
            "name": self._key_name,
            "plaintext": plaintext,
        }
        response = await self._client.encrypt(request=request)
        return response.ciphertext

    async def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt using GCP KMS."""
        request = {
            "name": self._key_name,
            "ciphertext": ciphertext,
        }
        response = await self._client.decrypt(request=request)
        return response.plaintext
