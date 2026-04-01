"""Remove keys from users, add issuer_keys table

Revision ID: 002
Revises: 001
Create Date: 2026-04-01

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

# revision identifiers, used by Alembic.
revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- Issuer Keys ---
    op.create_table(
        "issuer_keys",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("issuer_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("public_key", sa.LargeBinary, nullable=False),
        sa.Column("encrypted_private_key", sa.LargeBinary, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.UniqueConstraint("issuer_id", "version", name="uq_issuer_keys_issuer_version"),
    )
    op.create_index("idx_issuer_keys_issuer_id", "issuer_keys", ["issuer_id"])

    # Migrate data from users to issuer_keys safely using plain SQL
    op.execute(
        """
        INSERT INTO issuer_keys (issuer_id, version, public_key, encrypted_private_key)
        SELECT id, 1, public_key, encrypted_private_key FROM users;
        """
    )

    # Drop old columns from users
    op.drop_column("users", "public_key")
    op.drop_column("users", "encrypted_private_key")


def downgrade() -> None:
    # Re-add columns to users
    op.add_column("users", sa.Column("public_key", sa.LargeBinary, nullable=True))
    op.add_column("users", sa.Column("encrypted_private_key", sa.LargeBinary, nullable=True))

    # Move latest version back (Data loss on old keys accepted during downgrade)
    op.execute(
        """
        UPDATE users u
        SET public_key = k.public_key,
            encrypted_private_key = k.encrypted_private_key
        FROM (
            SELECT issuer_id, public_key, encrypted_private_key
            FROM (
                SELECT issuer_id, public_key, encrypted_private_key,
                       ROW_NUMBER() OVER(PARTITION BY issuer_id ORDER BY version DESC) as rn
                FROM issuer_keys
            ) latest WHERE rn = 1
        ) k
        WHERE u.id = k.issuer_id;
        """
    )
    
    # Enforce non-null again
    op.alter_column("users", "public_key", nullable=False)
    op.alter_column("users", "encrypted_private_key", nullable=False)

    op.drop_table("issuer_keys")
