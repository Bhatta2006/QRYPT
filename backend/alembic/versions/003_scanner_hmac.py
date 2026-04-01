"""add encrypted_hmac_secret to scanner_devices

Revision ID: 003
Revises: 002
Create Date: 2026-04-01

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Since we have existing scanner_devices (potentially from test data),
    # we need to provide a default value to satisfy the NOT NULL constraint.
    # We will generate a dummy 32-byte secret.
    op.add_column("scanner_devices", sa.Column("encrypted_hmac_secret", sa.LargeBinary, nullable=True))
    op.execute("UPDATE scanner_devices SET encrypted_hmac_secret = '\\x0000000000000000000000000000000000000000000000000000000000000000'")
    op.alter_column("scanner_devices", "encrypted_hmac_secret", nullable=False)

def downgrade() -> None:
    op.drop_column("scanner_devices", "encrypted_hmac_secret")
