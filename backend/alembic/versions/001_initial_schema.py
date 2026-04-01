"""Initial schema — all tables

Revision ID: 001
Revises: None
Create Date: 2026-04-01

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, ARRAY

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- Enable extensions ---
    op.execute("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE")
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    # --- Users ---
    op.create_table(
        "users",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("email", sa.String(255), unique=True, nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("role", sa.String(20), nullable=False, server_default="issuer"),
        sa.Column("public_key", sa.LargeBinary, nullable=False),
        sa.Column("encrypted_private_key", sa.LargeBinary, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("is_active", sa.Boolean, server_default="true", nullable=False),
        sa.CheckConstraint("role IN ('issuer', 'admin')", name="ck_users_role"),
    )
    op.create_index("idx_users_email", "users", ["email"])

    # --- Scanner Devices ---
    op.create_table(
        "scanner_devices",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("issuer_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("hashed_api_key", sa.String(255), nullable=False),
        sa.Column("scopes", ARRAY(sa.String), nullable=False, server_default=sa.text("ARRAY['scan:verify']::text[]")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("idx_scanner_devices_issuer_id", "scanner_devices", ["issuer_id"])

    # --- SVT Tokens ---
    op.create_table(
        "svt_tokens",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("trace_id", sa.String(64), unique=True, nullable=False),
        sa.Column("issuer_id", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("payload_url", sa.Text, nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="ACTIVE"),
        sa.Column("nonce", sa.String(64), nullable=False),
        sa.Column("signature", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.Text, nullable=True),
        sa.CheckConstraint("status IN ('ACTIVE', 'SUSPICIOUS', 'BLOCKED', 'EXPIRED')", name="ck_svt_tokens_status"),
    )
    op.create_index("idx_svt_tokens_trace_id", "svt_tokens", ["trace_id"])
    op.create_index("idx_svt_tokens_issuer_id", "svt_tokens", ["issuer_id"])
    op.create_index("idx_svt_tokens_expires_at", "svt_tokens", ["expires_at"])
    op.create_index("idx_svt_tokens_status", "svt_tokens", ["status"])

    # --- Scan Events (TimescaleDB hypertable) ---
    op.create_table(
        "scan_events",
        sa.Column("id", UUID(as_uuid=True), nullable=False),
        sa.Column("scanned_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("trace_id", sa.String(64), sa.ForeignKey("svt_tokens.trace_id"), nullable=False),
        sa.Column("ip_hash", sa.String(64), nullable=True),
        sa.Column("country_code", sa.String(2), nullable=True),
        sa.Column("city", sa.String(100), nullable=True),
        sa.Column("device_fingerprint_hash", sa.String(64), nullable=True),
        sa.Column("user_agent", sa.Text, nullable=True),
        sa.Column("result", sa.String(20), nullable=False),
        sa.Column("scanner_device_id", UUID(as_uuid=True), sa.ForeignKey("scanner_devices.id"), nullable=True),
        sa.PrimaryKeyConstraint("id", "scanned_at"),
        sa.CheckConstraint("result IN ('ALLOW', 'WARN', 'DENY', 'CANNOT_VERIFY')", name="ck_scan_events_result"),
    )

    # Convert to TimescaleDB hypertable
    op.execute("SELECT create_hypertable('scan_events', 'scanned_at', if_not_exists => TRUE)")
    op.execute("ALTER TABLE scan_events SET (timescaledb.compress, timescaledb.compress_orderby = 'scanned_at DESC')")
    op.execute("SELECT add_compression_policy('scan_events', INTERVAL '7 days')")
    op.execute("SELECT set_chunk_time_interval('scan_events', INTERVAL '6 hours')")

    op.create_index("idx_scan_events_trace_id", "scan_events", ["trace_id"])

    # --- Revocation Events ---
    op.create_table(
        "revocation_events",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("trace_id", sa.String(64), sa.ForeignKey("svt_tokens.trace_id"), nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("revoked_by", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
    )
    op.create_index("idx_revocation_events_trace_id", "revocation_events", ["trace_id"])
    op.create_index("idx_revocation_events_created_at", "revocation_events", ["created_at"], postgresql_ops={"created_at": "DESC"})


def downgrade() -> None:
    op.drop_table("revocation_events")
    op.drop_table("scan_events")
    op.drop_table("svt_tokens")
    op.drop_table("scanner_devices")
    op.drop_table("users")
