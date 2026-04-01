# =============================================================================
# SVT System — SVT Token ORM Model
# =============================================================================

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class SVTToken(Base):
    """Secure Visual Token record."""

    __tablename__ = "svt_tokens"
    __table_args__ = (
        CheckConstraint(
            "status IN ('ACTIVE', 'SUSPICIOUS', 'BLOCKED', 'EXPIRED')",
            name="ck_svt_tokens_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    trace_id: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    issuer_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )
    payload_url: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="ACTIVE", index=True
    )
    nonce: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("NOW()"), nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revocation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    issuer: Mapped["User"] = relationship(back_populates="tokens")  # noqa: F821
    scan_events: Mapped[list["ScanEvent"]] = relationship(  # noqa: F821
        back_populates="token", lazy="dynamic"
    )
    revocation_events: Mapped[list["RevocationEvent"]] = relationship(  # noqa: F821
        back_populates="token", lazy="dynamic"
    )

    def __repr__(self) -> str:
        return f"<SVTToken(trace_id={self.trace_id}, status={self.status})>"
