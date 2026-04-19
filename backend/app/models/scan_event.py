# =============================================================================
# SVT System — Scan Event ORM Model
# =============================================================================

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Text, text
from sqlalchemy.dialects.postgresql import UUID
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from app.models.token import SVTToken
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class ScanEvent(Base):
    """High-velocity scan event log (TimescaleDB hypertable)."""

    __tablename__ = "scan_events"
    __table_args__ = (
        CheckConstraint(
            "result IN ('ALLOW', 'WARN', 'DENY', 'CANNOT_VERIFY')",
            name="ck_scan_events_result",
        ),
        # Note: TimescaleDB hypertable is configured via Alembic migration 001,
        # not via ORM __table_args__. Composite PK (id, scanned_at) is required.
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        default=uuid.uuid4,
        nullable=False,
        primary_key=True,
    )
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
        primary_key=True,
    )
    trace_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("svt_tokens.trace_id"),
        nullable=False,
        index=True,
    )
    ip_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    country_code: Mapped[str | None] = mapped_column(String(2), nullable=True)
    city_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    device_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    device_fingerprint_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    result: Mapped[str] = mapped_column(String(20), nullable=False)
    scanner_device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scanner_devices.id"),
        nullable=True,
    )

    # Relationships
    token: Mapped["SVTToken"] = relationship(back_populates="scan_events")  # noqa: F821

    def __repr__(self) -> str:
        return f"<ScanEvent(trace_id={self.trace_id}, result={self.result})>"
