import json
import math
import structlog
import numpy as np
import joblib
from datetime import datetime
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis

from app.models import SVTToken
from app.core.metrics import svt_anomalies_total
from app.services import webhook_service

logger = structlog.get_logger(__name__)

_model = None
_model_loaded = False

def _get_model():
    global _model, _model_loaded
    if not _model_loaded:
        _model_loaded = True
        try:
            # model is an IsolationForest
            _model = joblib.load("/app/models/anomaly_model.joblib", mmap_mode="r")
        except Exception:
            logger.warning("anomaly_model_missing")
            _model = None
    return _model

def haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    # Earth radius in kilometers
    R = 6371.0
    
    lat1_rad = math.radians(lat1)
    lon1_rad = math.radians(lon1)
    lat2_rad = math.radians(lat2)
    lon2_rad = math.radians(lon2)
    
    dlon = lon2_rad - lon1_rad
    dlat = lat2_rad - lat1_rad
    
    a = math.sin(dlat / 2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2)**2
    c = 2 * math.asin(math.sqrt(a))
    
    return R * c

async def _flag(trace_id: str, reason: str, score: float, db: AsyncSession, redis: Redis) -> None:
    await db.execute(
        update(SVTToken)
        .where(SVTToken.trace_id == trace_id, SVTToken.status == "ACTIVE")
        .values(status="SUSPICIOUS")
    )
    await db.commit()
    svt_anomalies_total.labels(rule=reason).inc()
    await redis.set(f"svt:{trace_id}", "SUSPICIOUS", ex=86400)
    await webhook_service.alert(trace_id, reason, score)

async def process(event: dict, db: AsyncSession, redis: Redis) -> None:
    trace_id = event.get("trace_id")
    if not trace_id:
        return
        
    timestamp_ms = event.get("timestamp_ms") or int(datetime.utcnow().timestamp() * 1000)
    device_fingerprint_hash = event.get("device_fingerprint_hash")
    
    # RULE-01: Scan Flood
    count_key = f"scan_count:{trace_id}"
    count = await redis.incr(count_key)
    await redis.expire(count_key, 60)
    if count > 50:
        await _flag(trace_id, "scan_flood", 1.0, db, redis)

    # RULE-02: Geographic Impossibility
    curr_lat = event.get("lat")
    curr_lon = event.get("lon")
    if device_fingerprint_hash and curr_lat is not None and curr_lon is not None:
        key = f"last_geo:{device_fingerprint_hash}"
        last = await redis.get(key)
        if last:
            prev = json.loads(last)
            dist_km = haversine(prev["lat"], prev["lon"], curr_lat, curr_lon)
            delta_s = (int(timestamp_ms) - prev["timestamp_ms"]) / 1000
            # Prevent division by zero or negative time
            if delta_s < 0:
                delta_s = 0
            if dist_km > 500 and delta_s < 600:
                score = min(dist_km / 500.0, 1.0)
                await _flag(trace_id, "geo_impossible", score, db, redis)
        await redis.set(key, json.dumps({"lat": curr_lat, "lon": curr_lon, "timestamp_ms": int(timestamp_ms)}), ex=1800)

    # RULE-03: Device Code Flood
    if device_fingerprint_hash:
        device_codes_key = f"device_codes:{device_fingerprint_hash}"
        await redis.pfadd(device_codes_key, trace_id)
        await redis.expire(device_codes_key, 60)
        device_count = await redis.pfcount(device_codes_key)
        if device_count > 20: 
            await _flag(trace_id, "device_code_flood", min(device_count/20.0, 1.0), db, redis)

    # ML Scoring
    model = _get_model()
    if model:
        scan_velocity = await redis.get(f"scan_count:{trace_id}")
        scan_velocity = int(scan_velocity) if scan_velocity else 0
        device_diversity = await redis.pfcount(f"device_codes:{device_fingerprint_hash}") if device_fingerprint_hash else 0
        
        now = datetime.utcnow()
        hour_of_day = now.hour
        is_weekend = int(now.weekday() >= 5)
        
        features = np.array([[int(scan_velocity), int(device_diversity), 0.0, hour_of_day, is_weekend]])
        # invert: higher = more anomalous
        score = float(model.decision_function(features)[0]) * -1
        if score > 0.3:
            await _flag(trace_id, "ml_anomaly", score, db, redis)
