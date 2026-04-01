# =============================================================================
# SVT System — Device Fingerprinting
# =============================================================================

import hashlib

from fastapi import Request


def generate_device_fingerprint(request: Request) -> str:
    """
    Generate a replay-resistant SHA-256 device fingerprint.
    Combines User-Agent, Accept-Language, and client IP.
    """
    components = [
        request.headers.get("User-Agent", ""),
        request.headers.get("Accept-Language", ""),
        request.client.host if request.client else "",
    ]
    raw_fingerprint = "|".join(components).encode("utf-8")
    return hashlib.sha256(raw_fingerprint).hexdigest()
