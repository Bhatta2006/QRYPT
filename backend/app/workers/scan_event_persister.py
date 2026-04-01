# =============================================================================
# SVT System — Async Redis Stream Bulk Persister Worker (Blueprint Compliant)
# =============================================================================
# Reads from 'scan_events' stream (blueprint name).
# Persists events with GeoIP and device fingerprint fields.
# =============================================================================

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime

from redis.asyncio import Redis

from app.cache.redis_client import get_redis
from app.db.session import AsyncSessionLocal
from app.models.scan_event import ScanEvent

logger = logging.getLogger(__name__)

# EXACT stream names per blueprint
SCAN_EVENTS_STREAM = "scan_events"
ANOMALY_EVENTS_STREAM = "anomaly_events"


async def run_scan_event_persister(batch_size: int = 100, poll_timeout_ms: int = 5000):
    """
    Continuous background worker consuming from the 'scan_events' Redis stream.
    Batches inserts into TimescaleDB for high-velocity throughput.
    """
    redis: Redis = await get_redis()
    logger.info("Starting SVT Scan Event Stream Persister Worker...")

    group_name = "db_persisters"
    consumer_name = "persister-1"

    try:
        await redis.xgroup_create(SCAN_EVENTS_STREAM, group_name, mkstream=True)
    except Exception as e:
        if "BUSYGROUP" not in str(e):
            logger.error(f"Stream group setup failed: {e}")

    while True:
        try:
            messages = await redis.xreadgroup(
                groupname=group_name,
                consumername=consumer_name,
                streams={SCAN_EVENTS_STREAM: ">"},
                count=batch_size,
                block=poll_timeout_ms,
            )

            if not messages:
                continue

            scan_events_list = []
            message_ids = []

            for stream, msgs in messages:
                for msg_id, payload_mapping in msgs:
                    try:
                        raw_event = json.loads(payload_mapping[b"event"] if isinstance(payload_mapping, dict) and b"event" in payload_mapping else payload_mapping["event"])
                        scan_events_list.append(
                            ScanEvent(
                                trace_id=raw_event["trace_id"],
                                result=raw_event["result"],
                                ip_hash=raw_event.get("ip_hash") or None,
                                country_code=raw_event.get("country_code") or None,
                                city_name=raw_event.get("city_name") or None,
                                user_agent=raw_event.get("user_agent") or None,
                                device_id=raw_event.get("device_id") or None,
                                device_fingerprint_hash=raw_event.get("device_fingerprint_hash") or None,
                                scanner_device_id=raw_event.get("scanner_device_id") or None,
                                scanned_at=datetime.fromisoformat(raw_event["timestamp"]),
                            )
                        )
                        message_ids.append(msg_id)
                    except Exception as e:
                        logger.error(f"Failed to parse stream event: {e}")
                        await redis.xack(SCAN_EVENTS_STREAM, group_name, msg_id)

            if scan_events_list:
                async with AsyncSessionLocal() as db:
                    db.add_all(scan_events_list)
                    await db.commit()

                await redis.xack(SCAN_EVENTS_STREAM, group_name, *message_ids)
                logger.debug(f"Persisted {len(scan_events_list)} scan events.")

        except asyncio.CancelledError:
            logger.info("Stream Persister Worker terminated.")
            break
        except Exception as e:
            logger.error(f"Persister Worker error: {e}")
            await asyncio.sleep(5)
