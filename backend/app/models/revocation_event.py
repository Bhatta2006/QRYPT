# =============================================================================
# SVT System — Revocation Event ORM Model
# =============================================================================

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class RevocationEvent(Base):
    """Durable revocation event log. Used as SSE stream source."""

    __tablename__ = "revocation_events"

    id: Mapped[int] = mapped_column(
        primary_key=True, autoincrement=True  # BIGSERIAL
    )
    trace_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("svt_tokens.trace_id"),
        nullable=False,
        index=True,
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    revoked_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("NOW()"),
        nullable=False,
        index=True,
    )

    # Relationships
    token: Mapped["SVTToken"] = relationship(back_populates="revocation_events")  # noqa: F821

    def __repr__(self) -> str:
        return f"<RevocationEvent(id={self.id}, trace_id={self.trace_id})>"
