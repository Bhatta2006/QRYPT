# =============================================================================
# SVT System — JWT Binding Tests
# =============================================================================

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException, Request

from app.core.security import create_access_token, get_current_user
from app.core.security.device import generate_device_fingerprint


class MockRequest:
    def __init__(self, user_agent: str, ip: str, accept_language: str = ""):
        self.headers = {
            "User-Agent": user_agent,
            "Accept-Language": accept_language,
        }
        class ClientObj:
            host = ip
        self.client = ClientObj()


@pytest.mark.asyncio
async def test_jwt_binding_success():
    """Test valid device -> success."""
    req = MockRequest("Mozilla/5.0", "192.168.1.1")
    dfp = generate_device_fingerprint(req)
    
    user_id = uuid.uuid4()
    token = create_access_token(user_id, "issuer", "test@test.com", dfp)
    
    user_ctx = await get_current_user(req, token)
    assert user_ctx.id == user_id
    assert user_ctx.role == "issuer"


@pytest.mark.asyncio
async def test_jwt_binding_mismatch():
    """Test modified headers -> 401 Unauthorized."""
    # Token generated from valid device
    req_original = MockRequest("Mozilla/5.0", "192.168.1.1")
    dfp = generate_device_fingerprint(req_original)
    user_id = uuid.uuid4()
    token = create_access_token(user_id, "issuer", "test@test.com", dfp)
    
    # Attacker tries to reuse token on a different IP/Agent
    req_attacker = MockRequest("Chrome", "10.0.0.1")
    
    with pytest.raises(HTTPException) as exc:
        await get_current_user(req_attacker, token)
    
    assert exc.value.status_code == 401
    assert "Token device mismatch" in exc.value.detail
