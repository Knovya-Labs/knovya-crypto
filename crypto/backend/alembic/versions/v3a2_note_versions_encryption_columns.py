from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "v3a2"
down_revision: Union[str, None] = "v3a1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "note_versions",
        sa.Column(
            "is_encrypted",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "note_versions",
        sa.Column(
            "encryption_metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )

    op.execute(
        "ALTER TABLE note_versions "
        "ADD CONSTRAINT chk_nv_encrypted_has_metadata CHECK ("
        "is_encrypted = false OR encryption_metadata IS NOT NULL"
        ")"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE note_versions "
        "DROP CONSTRAINT IF EXISTS chk_nv_encrypted_has_metadata"
    )
    op.drop_column("note_versions", "encryption_metadata")
    op.drop_column("note_versions", "is_encrypted")
