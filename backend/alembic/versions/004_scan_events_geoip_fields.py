"""Add GeoIP and device fields to scan_events, add encrypted_hmac_secret to scanner_devices

Revision ID: 004
Revises: 003
Create Date: 2026-04-01

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Rename 'city' to 'city_name' in scan_events
    op.alter_column("scan_events", "city", new_column_name="city_name")
    # Add device_id to scan_events
    op.add_column("scan_events", sa.Column("device_id", sa.String(64), nullable=True))


def downgrade() -> None:
    op.drop_column("scan_events", "device_id")
    op.alter_column("scan_events", "city_name", new_column_name="city")
