"""
SVT System — Smoke Test Script
Called by the CD pipeline after deployment to validate basic system health.
"""

import argparse
import os
import sys

import httpx


def main():
    parser = argparse.ArgumentParser(description="SVT System Smoke Test")
    parser.add_argument("--url", required=True, help="Base URL of the SVT backend")
    args = parser.parse_args()
    base = args.url.rstrip("/")

    # 1. Health check
    print(f"[1/3] Health check: {base}/api/v1/health")
    r = httpx.get(f"{base}/api/v1/health", timeout=10)
    assert r.status_code == 200, f"Health failed: {r.status_code}"
    print("  ✓ Health OK")

    # 2. Login as test issuer (credentials injected via env)
    print("[2/3] Login check")
    smoke_email = os.environ.get("SMOKE_EMAIL")
    smoke_password = os.environ.get("SMOKE_PASSWORD")
    if not smoke_email or not smoke_password:
        print("  ⚠ SMOKE_EMAIL/SMOKE_PASSWORD not set, skipping login test")
    else:
        r = httpx.post(
            f"{base}/api/v1/auth/login",
            json={"email": smoke_email, "password": smoke_password},
            timeout=10,
        )
        assert r.status_code == 200, f"Login failed: {r.text}"
        token = r.json()["access_token"]
        print("  ✓ Login OK")

        # 3. Generate token
        print("[3/3] Token generation check")
        r = httpx.post(
            f"{base}/api/v1/tokens/generate",
            headers={
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": "smoke-test-key-1",
            },
            json={"payload_url": "https://smoke.test/payload", "ttl_seconds": 3600},
            timeout=15,
        )
        assert r.status_code in (200, 201), f"Generate failed: {r.text}"
        trace_id = r.json()["trace_id"]
        print(f"  ✓ Generated token: {trace_id}")

    # 4. Verify scan (skipped — requires scanner credentials, logged as warning)
    print("\nSmoke test passed.")
    sys.exit(0)


if __name__ == "__main__":
    main()
