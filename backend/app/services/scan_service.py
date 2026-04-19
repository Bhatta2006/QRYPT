# =============================================================================
# SVT System — High Velocity Verification Service (Blueprint Compliant)
# =============================================================================
# Wire format: CBOR({v:1, d:D_bytes, trace_id, sig})
# where D = CBOR({issuer_id_bytes, timestamp_ms, nonce, payload_url, expires_at_ms})
# trace_id = base64url(SHA256(D))
# =============================================================================

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone

import cbor2
import geoip2.database
import geoip2.errors
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import verify_payload
from app.core.metrics import scan_verify_duration_seconds, svt_scans_total
from app.models.issuer_key import IssuerKey
from app.models.scanner_device import ScannerDevice
from app.schemas.scan import ScanVerifyRequest, ScanVerifyResponse

# GeoIP database path — must be volume-mounted in production
GEOIP_DB_PATH = "/app/data/GeoLite2-City.mmdb"

# Lazy-loaded singleton GeoIP reader
_geoip_reader: geoip2.database.Reader | None = None


def _get_geoip_reader() -> geoip2.database.Reader | None:
    """Return cached GeoIP reader, or None if DB unavailable."""
    global _geoip_reader
    if _geoip_reader is None:
        try:
            _geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
        except Exception:
            return None
    return _geoip_reader


def _resolve_geoip(client_ip: str | None) -> tuple[str | None, str | None]:
    """Resolve IP to (country_code, city). Gracefully returns (None, None) on failure."""
    if not client_ip:
        return None, None
    reader = _get_geoip_reader()
    if not reader:
        return None, None
    try:
        response = reader.city(client_ip)
        country = response.country.iso_code
        city = response.city.name
        return country, city
    except (geoip2.errors.AddressNotFoundError, Exception):
        return None, None


def _base64url_no_padding(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _base64url_decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


async def verify_svt_token(
    db: AsyncSession,
    redis: Redis,
    request: ScanVerifyRequest,
    scanner: ScannerDevice,
    client_ip: str | None,
    user_agent: str | None,
    device_id: str | None = None,
) -> ScanVerifyResponse:
    """
    Decode and verify the SVT QR payload against the blueprint wire format.
    Implements: cache fallback, GeoIP, device fingerprinting, stream telemetry.
    """
    with scan_verify_duration_seconds.time():
        return await _verify_inner(db, redis, request, scanner, client_ip, user_agent, device_id)


async def _verify_inner(
    db: AsyncSession,
    redis: Redis,
    request: ScanVerifyRequest,
    scanner: ScannerDevice,
    client_ip: str | None,
    user_agent: str | None,
    device_id: str | None = None,
) -> ScanVerifyResponse:
    now = datetime.now(timezone.utc)

    # Strip svt:// prefix
    raw_payload = request.svt_raw
    if raw_payload.startswith("svt://"):
        raw_payload = raw_payload[6:]

    # 1. Decode CBOR envelope
    try:
        qr_bytes = _base64url_decode(raw_payload)
        envelope = cbor2.loads(qr_bytes)
    except Exception:
        svt_scans_total.labels(result="DENY").inc()
        return ScanVerifyResponse(result="CANNOT_VERIFY", reason="Malformed SVT: base64/CBOR decode failed")

    # 2. Strict field validation (Task 12)
    required = {"v", "d", "trace_id", "sig"}
    if not isinstance(envelope, dict) or set(envelope.keys()) != required:
        svt_scans_total.labels(result="DENY").inc()
        return ScanVerifyResponse(result="CANNOT_VERIFY", reason="Invalid or unexpected SVT fields")

    # 3. Version check (Task 10)
    if envelope.get("v") != 1:
        svt_scans_total.labels(result="DENY").inc()
        return ScanVerifyResponse(result="DENY", reason=f"Unsupported SVT version: {envelope.get('v')}")

    D: bytes = envelope["d"]
    trace_id: str = envelope["trace_id"]
    sig: str = envelope["sig"]

    if not isinstance(D, bytes) or not isinstance(trace_id, str) or not isinstance(sig, str):
        svt_scans_total.labels(result="DENY").inc()
        return ScanVerifyResponse(result="CANNOT_VERIFY", reason="Invalid field types in SVT")

    # 4. Verify trace_id deterministically
    computed_trace_id = _base64url_no_padding(hashlib.sha256(D).digest())
    if computed_trace_id != trace_id:
        svt_scans_total.labels(result="DENY").inc()
        return ScanVerifyResponse(result="DENY", reason="trace_id integrity check failed")

    # 5. Decode inner D dict
    try:
        D_dict = cbor2.loads(D)
        issuer_id_bytes: bytes = D_dict["issuer_id"]
        expires_at_ms: int = D_dict.get("expires_at_ms", 0)
        payload_url: str = D_dict["payload_url"]
        issuer_id = uuid.UUID(bytes=issuer_id_bytes)
    except Exception:
        svt_scans_total.labels(result="DENY").inc()
        return ScanVerifyResponse(result="CANNOT_VERIFY", reason="Malformed D payload")

    # 6. Cache fallback — check Redis first, then DB (Task 7)
    cache_key = f"svt:{trace_id}"
    cached_status = await redis.get(cache_key)
    if cached_status:
        token_status = cached_status.decode() if isinstance(cached_status, bytes) else cached_status
    else:
        # DB lookup (Task 7 — miss path)
        from app.models.token import SVTToken
        db_result = await db.execute(
            select(SVTToken).where(SVTToken.trace_id == trace_id)
        )
        token_record = db_result.scalar_one_or_none()
        token_status = token_record.status if token_record else "UNKNOWN"
        # Cache result for 60s
        await redis.set(cache_key, token_status, ex=60)

    if token_status == "REVOKED":
        svt_scans_total.labels(result="DENY").inc()
        await _emit_telemetry(redis, trace_id, "DENY", scanner, client_ip, user_agent, device_id)
        return ScanVerifyResponse(result="DENY", reason="Token has been revoked by issuer")

    # 7. Fetch public key — with Redis caching (Task 9)
    # We will try fetching the latest active key from DB to get the version,
    # or rely on a known cache. The blueprint specifies pubkey:{issuer_id}:{version}
    from sqlalchemy import func
    key_result = await db.execute(
        select(IssuerKey)
        .where(IssuerKey.issuer_id == issuer_id)
        .order_by(IssuerKey.version.desc())
        .limit(1)
    )
    issuer_key = key_result.scalar_one_or_none()
    if not issuer_key:
        svt_scans_total.labels(result="DENY").inc()
        return ScanVerifyResponse(result="DENY", reason="Issuer public key not found")
        
    pubkey_cache_key = f"pubkey:{issuer_id}:{issuer_key.version}"
    cached_pubkey = await redis.get(pubkey_cache_key)
    
    if cached_pubkey:
        public_key_bytes = cached_pubkey
    else:
        public_key_bytes = issuer_key.public_key
        await redis.set(pubkey_cache_key, public_key_bytes, ex=3600)

    # 8. Signature verification — sign({d: D_bytes, trace_id: str})
    is_valid = verify_payload({"d": D, "trace_id": trace_id}, sig, public_key_bytes)
    if not is_valid:
        svt_scans_total.labels(result="DENY").inc()
        await _emit_telemetry(redis, trace_id, "DENY", scanner, client_ip, user_agent, device_id)
        return ScanVerifyResponse(result="DENY", reason="Cryptographic signature mismatch")

    # 9. Expiration check
    if expires_at_ms and expires_at_ms > 0:
        if int(now.timestamp() * 1000) > expires_at_ms:
            svt_scans_total.labels(result="DENY").inc()
            await _emit_telemetry(redis, trace_id, "DENY", scanner, client_ip, user_agent, device_id)
            return ScanVerifyResponse(result="DENY", reason="Token is valid but expired")

    # 10. Success
    svt_scans_total.labels(result="ALLOW").inc()
    await _emit_telemetry(redis, trace_id, "ALLOW", scanner, client_ip, user_agent, device_id)
    return ScanVerifyResponse(result="ALLOW", payload_url=payload_url)


async def _emit_telemetry(
    redis: Redis,
    trace_id: str,
    result: str,
    scanner: ScannerDevice | None,
    client_ip: str | None,
    user_agent: str | None,
    device_id: str | None,
) -> None:
    """
    Publish scan event to 'scan_events' Redis stream (Blueprint name).
    Includes GeoIP resolution, device fingerprint hash.
    """
    # GeoIP resolution (Task 5)
    country_code, city_name = _resolve_geoip(client_ip)

    # Device fingerprint (Task 6): SHA256(user_agent + device_id)
    ua = user_agent or ""
    did = device_id or ""
    device_fingerprint_hash = hashlib.sha256((ua + did).encode("utf-8")).hexdigest()

    # IP hash for privacy
    ip_hash = hashlib.sha256(client_ip.encode()).hexdigest() if client_ip else ""

    event = {
        "trace_id": trace_id,
        "result": result,
        "ip_hash": ip_hash,
        "country_code": country_code or "",
        "city_name": city_name or "",
        "user_agent": ua,
        "device_id": did,
        "device_fingerprint_hash": device_fingerprint_hash,
        "scanner_device_id": str(scanner.id) if scanner else "",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # EXACT stream name per blueprint (Task 4)
    await redis.xadd("scan_events", {"event": json.dumps(event)})
    # ALWAYS PUSH TO BOTH STREAMS (Task 3.10)
    await redis.xadd("anomaly_events", {"event": json.dumps(event)})
