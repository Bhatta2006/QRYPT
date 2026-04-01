# =============================================================================
# SVT System — Keys API Endpoints
# =============================================================================

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import generate_keypair
from app.core.security import UserContext, rbac
from app.db.session import get_db
from app.models.issuer_key import IssuerKey

router = APIRouter(prefix="/keys", tags=["keys"])


@router.post("/rotate", status_code=status.HTTP_201_CREATED)
async def rotate_key(
    current_user: UserContext = Depends(rbac(["issuer"])),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """
    Rotate signing keys for the issuer.
    This creates a new KeyVersion for the issuer without invalidating old ones.
    Using FOR UPDATE lock to avoid race conditions.
    """
    # Lock keys to find max version safely
    result = await db.execute(
        select(func.max(IssuerKey.version))
        .where(IssuerKey.issuer_id == current_user.id)
        .with_for_update()
    )
    max_version = result.scalar() or 0
    new_version = max_version + 1

    # Generate new Ed25519 keypair
    public_key, encrypted_private_key = await generate_keypair()

    new_key = IssuerKey(
        issuer_id=current_user.id,
        version=new_version,
        public_key=public_key,
        encrypted_private_key=encrypted_private_key,
    )
    db.add(new_key)
    await db.flush()

    return {
        "message": "Key rotated successfully",
        "version": new_version,
    }
