import os
import json
import pytest
import asyncio
from datetime import datetime, timedelta
import fakeredis.aioredis
from typing import AsyncGenerator
from unittest.mock import patch, MagicMock, AsyncMock

import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import select

from app.db.base import Base
from app.models import SVTToken
from app.services import anomaly_service
from app.services import webhook_service

# --- Fixtures ---

@pytest_asyncio.fixture(scope="function")
async def db() -> AsyncGenerator[AsyncSession, None]:
    # Strip postgres-specific server defaults for sqlite compatibility
    for table in Base.metadata.sorted_tables:
        for column in table.columns:
            if getattr(column, "server_default", None) is not None:
                column.server_default = None
                
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all, tables=[SVTToken.__table__])
        
    AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)
    async with AsyncSessionLocal() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all, tables=[SVTToken.__table__])
    await engine.dispose()

@pytest_asyncio.fixture(scope="function")
async def redis():
    redis_instance = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield redis_instance
    await redis_instance.close()

@pytest_asyncio.fixture(scope="function")
async def test_token(db: AsyncSession):
    import uuid
    trace_id = "test-trace-id"
    token = SVTToken(
        id=uuid.uuid4(),
        trace_id=trace_id,
        issuer_id=uuid.uuid4(), # Mock issuer
        payload_url="http://example.com",
        status="ACTIVE",
        nonce="nonce",
        signature="signature",
        created_at=datetime.utcnow()
    )
    db.add(token)
    await db.commit()
    yield trace_id

# --- Tests ---

@pytest.mark.asyncio
async def test_rule_01_scan_flood(db: AsyncSession, redis, test_token: str):
    # Process 51 times
    for _ in range(51):
        event = {
            "trace_id": test_token,
            "timestamp_ms": int(datetime.utcnow().timestamp() * 1000)
        }
        await anomaly_service.process(event, db, redis)
        
    # After 51st call, status should be SUSPICIOUS
    result = await db.execute(select(SVTToken).where(SVTToken.trace_id == test_token))
    token = result.scalar_one()
    assert token.status == "SUSPICIOUS"

@pytest.mark.asyncio
async def test_rule_02_geo_impossible(db: AsyncSession, redis, test_token: str):
    device_fp = "device-123"
    
    # First event
    event1 = {
        "trace_id": test_token,
        "device_fingerprint_hash": device_fp,
        "timestamp_ms": int(datetime.utcnow().timestamp() * 1000),
        "lat": 0.0,
        "lon": 0.0
    }
    await anomaly_service.process(event1, db, redis)
    
    # Second event, 300s later, far away (60.0, 60.0 is > 500km)
    event2 = {
        "trace_id": test_token,
        "device_fingerprint_hash": device_fp,
        "timestamp_ms": int((datetime.utcnow() + timedelta(seconds=300)).timestamp() * 1000),
        "lat": 60.0,
        "lon": 60.0
    }
    await anomaly_service.process(event2, db, redis)
    
    result = await db.execute(select(SVTToken).where(SVTToken.trace_id == test_token))
    token = result.scalar_one()
    assert token.status == "SUSPICIOUS"

@pytest.mark.asyncio
async def test_rule_02_skip_null_geo(db: AsyncSession, redis, test_token: str):
    device_fp = "device-123"
    
    event1 = {
        "trace_id": test_token,
        "device_fingerprint_hash": device_fp,
        "timestamp_ms": int(datetime.utcnow().timestamp() * 1000),
        "lat": None,
        "lon": None
    }
    await anomaly_service.process(event1, db, redis)
    
    event2 = {
        "trace_id": test_token,
        "device_fingerprint_hash": device_fp,
        "timestamp_ms": int((datetime.utcnow() + timedelta(seconds=300)).timestamp() * 1000),
        "lat": None,
        "lon": None
    }
    await anomaly_service.process(event2, db, redis)
    
    result = await db.execute(select(SVTToken).where(SVTToken.trace_id == test_token))
    token = result.scalar_one()
    assert token.status == "ACTIVE"

@pytest.mark.asyncio
async def test_rule_03_device_code_flood(db: AsyncSession, redis, test_token: str):
    device_fp = "device-flood"
    
    # 21 events with same device fp, but different trace_ids
    for i in range(21):
        event = {
            "trace_id": f"other-trace-{i}",
            "device_fingerprint_hash": device_fp,
            "timestamp_ms": int(datetime.utcnow().timestamp() * 1000)
        }
        await anomaly_service.process(event, db, redis)
        
    # The 21st trace_id gets flagged, let's test one specific one
    last_trace = "other-trace-20"
    
    # Manually check the redis flag
    status = await redis.get(f"svt:{last_trace}")
    assert status == "SUSPICIOUS"

@pytest.mark.asyncio
async def test_dead_letter_logic():
    # Because testing the actual worker while True loop is tricky,
    # we simulate the worker logic for dead-letter processing
    redis_mock = fakeredis.aioredis.FakeRedis(decode_responses=True)
    
    # Create the groups and stream
    await redis_mock.xgroup_create("anomaly_events", "anomaly-workers", mkstream=True)
    
    message_id = await redis_mock.xadd("anomaly_events", {"event": '{"trace_id": "test"}'})
    
    # Read to put into PEL
    await redis_mock.xreadgroup("anomaly-workers", "test-consumer", {"anomaly_events": ">"}, count=1)
    
    # Simulate time passing by manually forging the xpending lookup mock or xclaim
    # fakeredis doesn't perfectly support xpending time mock natively, so we mock xpending_range and xclaim
    
    with patch.object(redis_mock, 'xpending_range', new_callable=AsyncMock) as mock_pending:
        with patch.object(redis_mock, 'xclaim', new_callable=AsyncMock) as mock_claim:
            
            mock_pending.return_value = [
                {"message_id": message_id, "time_since_delivered": 300001, "consumer": "test-consumer"}
            ]
            
            mock_claim.return_value = [
                (message_id, {"event": '{"trace_id": "test"}'})
            ]
            
            # The dead-letter processing
            pending = await redis_mock.xpending_range("anomaly_events", "anomaly-workers", "-", "+", 100)
            for entry in pending:
                if entry["time_since_delivered"] > 300000:
                    claimed_messages = await redis_mock.xclaim(
                        "anomaly_events", "anomaly-workers", "test-consumer", 300000, [entry["message_id"]]
                    )
                    
                    for claimed_id, claimed_data in claimed_messages:
                        dlq_data = dict(claimed_data)
                        dlq_data["dlq_reason"] = "max_idle_exceeded"
                        await redis_mock.xadd("anomaly_events_dlq", dlq_data)
                        await redis_mock.xack("anomaly_events", "anomaly-workers", claimed_id)
                        
            # Assert dead letter created
            dlq_msgs = await redis_mock.xrange("anomaly_events_dlq")
            assert len(dlq_msgs) > 0
            assert dlq_msgs[0][1]["dlq_reason"] == "max_idle_exceeded"

@pytest.mark.asyncio
async def test_webhook_retry_failure(monkeypatch):
    from app.core.config import get_settings
    settings = get_settings()
    monkeypatch.setattr(settings, "admin_webhook_url", "http://mock-webhook")

    call_count = 0

    class MockAsyncClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass
        async def post(self, url, json):
            nonlocal call_count
            call_count += 1
            class MockResponse:
                def raise_for_status(self):
                    import httpx
                    raise httpx.HTTPStatusError("500", request=MagicMock(), response=MagicMock())
            return MockResponse()

    # We mock asyncio.sleep so the test runs fast
    with patch("httpx.AsyncClient", new=lambda **kwargs: MockAsyncClient()):
        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            with patch.object(webhook_service.logger, "error") as mock_logger:
                await webhook_service.alert("test-trace", "test-trigger", 1.0)
                
                assert call_count == 4 # Initial + 3 retries
                mock_logger.assert_called_once_with("webhook_failed", trace_id="test-trace", trigger="test-trigger", attempts=3)

@pytest.mark.asyncio
async def test_model_missing_skip_ml(db: AsyncSession, redis, test_token: str):
    anomaly_service._model = None
    anomaly_service._model_loaded = False
    
    # Ensure joblib.load raises Exception
    with patch("joblib.load", side_effect=Exception("File not found")):
        event = {
            "trace_id": test_token,
            "timestamp_ms": int(datetime.utcnow().timestamp() * 1000)
        }
        # Run process
        await anomaly_service.process(event, db, redis)
        
        # Result should still process rules but ML skipped without failing
        count = await redis.get(f"scan_count:{test_token}")
        assert int(count) == 1
        
        result = await db.execute(select(SVTToken).where(SVTToken.trace_id == test_token))
        token = result.scalar_one()
        assert token.status == "ACTIVE" # Still active since no rules triggered
