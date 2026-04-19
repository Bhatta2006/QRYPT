import asyncio
import httpx
import structlog
from datetime import datetime

from app.core.config import get_settings

logger = structlog.get_logger(__name__)
settings = get_settings()

async def alert(trace_id: str, trigger: str, severity: float, timestamp_iso: str | None = None) -> None:
    if not settings.admin_webhook_url:
        return

    payload = {
        "trace_id": trace_id,
        "trigger": trigger,
        "severity": round(severity, 4),
        "timestamp_iso": timestamp_iso or datetime.utcnow().isoformat()
    }

    delays = [1, 4, 16]
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        for attempt in range(4):
            try:
                res = await client.post(settings.admin_webhook_url, json=payload)
                res.raise_for_status()
                return
            except Exception:
                if attempt < 3:
                    await asyncio.sleep(delays[attempt])
                else:
                    logger.error("webhook_failed", trace_id=trace_id, trigger=trigger, attempts=3)
