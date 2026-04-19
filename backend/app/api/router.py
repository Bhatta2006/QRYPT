# =============================================================================
# API Router Aggregator
# =============================================================================

from fastapi import APIRouter

from app.api.v1.auth import router as auth_router
from app.api.v1.tokens import router as tokens_router
from app.api.v1.keys import router as keys_router
from app.api.v1.scan import router as scan_router
from app.api.v1.events import router as events_router

api_router = APIRouter()

api_router.include_router(auth_router, prefix="/api/v1")
api_router.include_router(tokens_router, prefix="/api/v1")
api_router.include_router(keys_router, prefix="/api/v1")
api_router.include_router(scan_router, prefix="/api/v1")
api_router.include_router(events_router, prefix="/api/v1")

from app.api.v1 import health
api_router.include_router(health.router, prefix="/api/v1")
