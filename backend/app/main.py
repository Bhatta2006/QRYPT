# =============================================================================
# SVT System — Application Entry Point
# =============================================================================
# Pure composition layer: instantiates FastAPI, registers routers,
# initializes infrastructure. Zero business logic.
#
# Run: uvicorn app.main:app --reload
# CWD: backend/
# =============================================================================

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import get_settings
from app.core.metrics import REGISTRY
from app.core.tracing import configure_tracing
from prometheus_client import make_asgi_app
from app.api.router import api_router

logger = logging.getLogger("svt.main")
settings = get_settings()


# =============================================================================
# Lifespan — Infrastructure Init / Teardown
# =============================================================================

@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncGenerator[None, None]:
    """
    Manages infrastructure lifecycle via async context manager.
    Startup: validate DB connectivity, initialize Redis client.
    Shutdown: close Redis connections gracefully.
    """
    # --- Startup ---
    logger.info("SVT System starting up (env=%s)...", settings.app_env)

    # Initialize Redis client (lazy singleton — first call creates connection)
    from app.cache.redis_client import get_redis, close_redis

    redis = await get_redis()
    try:
        await redis.ping()
        logger.info("Redis connection verified.")
    except Exception as exc:
        logger.warning("Redis not available at startup; continuing without cache features: %s", exc)

    # Validate DB engine connectivity
    from app.db.session import engine

    try:
        async with engine.connect() as conn:
            await conn.execute(
                __import__("sqlalchemy").text("SELECT 1")
            )
        logger.info("Database connection verified.")
    except Exception as exc:
        logger.error("Database not available at startup: %s", exc)
        raise RuntimeError(f"Startup halted: Database unavailable - {exc}")

    logger.info("SVT System ready — serving on %s:%s", settings.app_host, settings.app_port)

    yield

    # --- Shutdown ---
    logger.info("SVT System shutting down...")
    await close_redis()
    await engine.dispose()
    logger.info("SVT System shutdown complete.")


# =============================================================================
# Application Instance
# =============================================================================

app = FastAPI(
    title="SVT System",
    description="Secure Traceable Visual Token System — Production API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)


# =============================================================================
# Middleware — CORS only (auth + rate limiting already per-route)
# =============================================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-Id", "Retry-After"],
)


# =============================================================================
# Observability — OpenTelemetry Tracing & Prometheus Metrics
# =============================================================================

configure_tracing(app)

metrics_app = make_asgi_app(registry=REGISTRY)
app.mount("/metrics", metrics_app)


# =============================================================================
# Router Registration — Canonical API Router
# =============================================================================

app.include_router(api_router)


# =============================================================================
# Health Endpoints — Liveness & Readiness Probes
# =============================================================================

@app.get(
    "/api/v1/health",
    tags=["health"],
    summary="Liveness probe",
    status_code=status.HTTP_200_OK,
)
async def health_liveness():
    """
    Liveness probe — always returns OK if the process is running.
    Used by Kubernetes liveness probe.
    """
    return {"status": "ok", "service": "svt-backend"}


@app.get(
    "/api/v1/health/ready",
    tags=["health"],
    summary="Readiness probe",
)
async def health_readiness():
    """
    Readiness probe — validates DB and Redis connectivity.
    Returns 503 if either dependency is unreachable.
    Used by Kubernetes readiness probe to gate traffic.
    """
    checks = {"database": False, "redis": False}

    # Check database
    try:
        from app.db.session import engine

        async with engine.connect() as conn:
            await conn.execute(
                __import__("sqlalchemy").text("SELECT 1")
            )
        checks["database"] = True
    except Exception:
        pass

    # Check Redis
    try:
        from app.cache.redis_client import get_redis

        redis = await get_redis()
        await redis.ping()
        checks["redis"] = True
    except Exception:
        pass

    all_ready = all(checks.values())

    return JSONResponse(
        status_code=status.HTTP_200_OK if all_ready else status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "status": "ready" if all_ready else "not_ready",
            "checks": checks,
        },
    )


# =============================================================================
# Logging Configuration
# =============================================================================

logging.basicConfig(
    level=getattr(logging, settings.app_log_level.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
