import asyncio
import json
import os

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import StreamingResponse
from redis.asyncio import Redis

from app.cache.redis_client import get_redis
from app.core.security import UserContext, rbac

router = APIRouter(prefix="/events", tags=["events"])

@router.get("/stream")
async def sse_stream(
    last_event_id: str = Header("0-0", alias="Last-Event-Id"),
    current_user: UserContext = Depends(rbac(["issuer", "admin"])),
    redis: Redis = Depends(get_redis),
):
    pod_name = os.environ.get("POD_NAME", "local")
    conn_key = f"sse_connections:{pod_name}"
    
    count = await redis.incr(conn_key)
    if count > 500:
        await redis.decr(conn_key)
        raise HTTPException(status_code=503, detail="sse_capacity_exceeded")

    async def event_generator():
        cursor = last_event_id
        queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        heartbeat_interval = 15  # seconds

        async def stream_reader():
            nonlocal cursor
            while True:
                try:
                    entries = await redis.xread({"revocation_events": cursor}, count=100, block=15000)
                    if entries:
                        for stream_name, messages in entries:
                            for msg_id, fields in messages:
                                await queue.put((msg_id, fields))
                                cursor = msg_id
                except Exception:
                    await asyncio.sleep(1)

        reader_task = asyncio.create_task(stream_reader())
        last_heartbeat = asyncio.get_event_loop().time()

        try:
            while True:
                now = asyncio.get_event_loop().time()
                timeout = max(0, heartbeat_interval - (now - last_heartbeat))
                try:
                    msg_id, fields = await asyncio.wait_for(queue.get(), timeout=timeout)
                    payload = json.dumps({
                        k.decode() if isinstance(k, bytes) else k: v.decode() if isinstance(v, bytes) else v
                        for k, v in fields.items()
                    })
                    msg_id_str = msg_id.decode() if isinstance(msg_id, bytes) else msg_id
                    yield f"id: {msg_id_str}\ndata: {payload}\n\n"
                    last_heartbeat = asyncio.get_event_loop().time()
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
                    last_heartbeat = asyncio.get_event_loop().time()
        except GeneratorExit:
            pass
        finally:
            reader_task.cancel()
            await redis.decr(conn_key)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )
