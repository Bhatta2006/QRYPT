# =============================================================================
# SVT System — Scanner Device ORM Model
# =============================================================================

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, text, LargeBinary
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class ScannerDevice(Base):
    """Scanner device provisioned by an issuer."""

    __tablename__ = "scanner_devices"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    issuer_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    hashed_api_key: Mapped[str] = mapped_column(String(255), nullable=False)
    encrypted_hmac_secret: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    scopes: Mapped[list[str]] = mapped_column(
        ARRAY(String),
        nullable=False,
        server_default=text("ARRAY['scan:verify']::text[]"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("NOW()"), nullable=False
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    issuer: Mapped["User"] = relationship(back_populates="scanner_devices")  # noqa: F821

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    def __repr__(self) -> str:
        return f"<ScannerDevice(id={self.id}, name={self.name})>"
