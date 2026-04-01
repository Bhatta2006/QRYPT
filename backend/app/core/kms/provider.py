# =============================================================================
# SVT System — KMS Provider (Dependency Injection)
# =============================================================================

from app.core.config import get_settings
from app.core.kms.interface import KMSClient

# Cached singleton per process
_kms_client: KMSClient | None = None


def get_kms_client() -> KMSClient:
    """
    Dependency injection factory for KMSClient.
    This is the ONLY module where the environment is checked for KMS routing.
    """
    global _kms_client
    if _kms_client is not None:
        return _kms_client

    settings = get_settings()

    if settings.kms_provider == "gcp":
        from app.core.kms.gcp_kms import GCPKMSClient

        _kms_client = GCPKMSClient(settings.kms_key_name)
    else:
        from app.core.kms.mock_kms import MockKMSClient

        _kms_client = MockKMSClient()

    return _kms_client
