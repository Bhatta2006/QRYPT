# =============================================================================
# SVT System — Issuer Key ORM Model
# =============================================================================

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class IssuerKey(Base):
    """Stores versioned Ed25519 signing keys per issuer."""

    __tablename__ = "issuer_keys"
    __table_args__ = (
        UniqueConstraint("issuer_id", "version", name="uq_issuer_keys_issuer_version"),
    )

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
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encrypted_private_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("NOW()"), nullable=False
    )

    # Relationships
    issuer: Mapped["User"] = relationship(back_populates="keys")  # noqa: F821

    def __repr__(self) -> str:
        return f"<IssuerKey(issuer_id={self.issuer_id}, version={self.version})>"
