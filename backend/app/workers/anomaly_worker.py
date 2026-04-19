import asyncio
import os
import json
import traceback
import structlog
from redis.exceptions import ResponseError

from app.cache.redis_client import get_redis
from app.db.session import SessionLocal
from app.services import anomaly_service

logger = structlog.get_logger(__name__)

async def main():
    consumer_name = f"{os.environ.get('POD_NAME', 'local')}-{os.getpid()}"
    redis = await get_redis()
    
    # Idempotent group creation
    try:
        await redis.xgroup_create("anomaly_events", "anomaly-workers", id="$", mkstream=True)
        logger.info("consumer_group_created", group="anomaly-workers")
    except ResponseError as e:
        if "BUSYGROUP" in str(e):
            logger.debug("consumer_group_exists", group="anomaly-workers")
        else:
            raise

    logger.info("anomaly_worker_started", consumer_name=consumer_name)

    while True:
        try:
            # 1. Read messages from stream
            result = await redis.xreadgroup(
                "anomaly-workers", 
                consumer_name, 
                {"anomaly_events": ">"}, 
                count=10, 
                block=1000
            )

            if result:
                for stream, messages in result:
                    for message_id, message_data in messages:
                        try:
                            # DB Session scoped per message for safety/isolation
                            async with SessionLocal() as db:
                                # Data could be directly in message_data or JSON string under 'event'
                                event = message_data.get("event")
                                if isinstance(event, str):
                                    event = json.loads(event)
                                elif not event:
                                    event = message_data
                                    
                                await anomaly_service.process(event, db, redis)
                                await redis.xack("anomaly_events", "anomaly-workers", message_id)
                        except Exception as e:
                            logger.error("anomaly_processing_failed", 
                                       message_id=message_id, 
                                       exc_info=True, 
                                       traceback=traceback.format_exc())

            # 2. Dead-letter processing
            pending = await redis.xpending_range("anomaly_events", "anomaly-workers", "-", "+", 100)
            for entry in pending:
                message_id = entry["message_id"]
                idle_time_ms = entry["time_since_delivered"]
                
                if idle_time_ms > 300000:  # 5 minutes
                    claimed_messages = await redis.xclaim(
                        "anomaly_events", 
                        "anomaly-workers", 
                        consumer_name, 
                        300000, 
                        [message_id]
                    )
                    
                    for claimed_id, claimed_data in claimed_messages:
                        dlq_data = dict(claimed_data)
                        dlq_data["dlq_reason"] = "max_idle_exceeded"
                        
                        await redis.xadd("anomaly_events_dlq", dlq_data)
                        await redis.xack("anomaly_events", "anomaly-workers", claimed_id)
                        logger.warning("message_dead_lettered", message_id=claimed_id)
                        
        except asyncio.CancelledError:
            logger.info("anomaly_worker_shutting_down")
            break
        except Exception as e:
            logger.error("anomaly_worker_error", exc_info=True)
            await asyncio.sleep(5)

if __name__ == "__main__":
    asyncio.run(main())
