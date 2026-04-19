# =============================================================================
# SVT System — User ORM Model
# =============================================================================

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, String, text
from sqlalchemy.dialects.postgresql import UUID
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from app.models.token import SVTToken
    from app.models.scanner_device import ScannerDevice
    from app.models.issuer_key import IssuerKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class User(Base):
    """Issuer or Admin user."""

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("role IN ('issuer', 'admin')", name="ck_users_role"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    email: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True
    )
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="issuer"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("NOW()"), nullable=False
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, server_default="true", nullable=False
    )

    # Relationships
    keys: Mapped[list["IssuerKey"]] = relationship(  # noqa: F821
        back_populates="issuer", lazy="selectin", cascade="all, delete-orphan"
    )
    tokens: Mapped[list["SVTToken"]] = relationship(  # noqa: F821
        back_populates="issuer", lazy="selectin"
    )
    scanner_devices: Mapped[list["ScannerDevice"]] = relationship(  # noqa: F821
        back_populates="issuer", lazy="selectin"
    )

    def __repr__(self) -> str:
        return f"<User(id={self.id}, email={self.email}, role={self.role})>"
