import asyncio
import httpx

async def test_flow():
    base_url = "http://localhost:8000/api/v1"
    async with httpx.AsyncClient(base_url=base_url) as client:
        print("1. Registering user...")
        res = await client.post("/auth/register", json={"email": "issuer123@example.com", "password": "securepassword99"})
        if res.status_code == 409:
            print("User already exists, proceeding to login...")
        else:
            res.raise_for_status()
            
        print("2. Logging in...")
        res = await client.post("/auth/login", json={"email": "issuer123@example.com", "password": "securepassword99"})
        res.raise_for_status()
        token = res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        print("3. Creating scanner device...")
        res = await client.post("/auth/scanner/create", json={"name": "Test Scanner"}, headers=headers)
        res.raise_for_status()
        scanner = res.json()
        
        print("4. Generating SVT token...")
        res = await client.post("/tokens", json={
            "payload_url": "https://example.com/verified",
            "expires_in_hours": 24
        }, headers={**headers, "Idempotency-Key": "req-1"})
        res.raise_for_status()
        svt_data = res.json()
        svt_raw = svt_data["svt_raw"]
        
        print("5. Verifying SVT scan...")
        import time
        import json
        import hashlib
        import hmac
        timestamp = str(time.time())
        device_id = scanner["device_id"]
        hmac_secret_b64 = scanner["hmac_secret"]
        import base64
        hmac_secret = base64.urlsafe_b64decode(hmac_secret_b64 + "==")
        body = json.dumps({"svt_raw": svt_raw}).encode("utf-8")
        msg = device_id.encode("utf-8") + timestamp.encode("utf-8") + body
        sig = hmac.new(hmac_secret, msg, digestmod=hashlib.sha256).hexdigest()
        
        scan_headers = {
            "X-Device-Id": device_id,
            "X-Timestamp": timestamp,
            "X-Signature-SHA256": sig,
            "Content-Type": "application/json"
        }
        res = await client.post("/scan/verify", content=body, headers=scan_headers)
        res.raise_for_status()
        print("Scan result:", res.json())
        print("ALL TESTS PASSED: TRUE")

if __name__ == "__main__":
    asyncio.run(test_flow())
