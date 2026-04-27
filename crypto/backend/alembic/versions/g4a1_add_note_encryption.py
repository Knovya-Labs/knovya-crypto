from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "g4a1b2c3d4e5"
down_revision: Union[str, None] = "f3a1d5e6f7a8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "notes",
        sa.Column(
            "is_encrypted",
            sa.Boolean(),
            server_default="false",
            nullable=False,
        ),
    )
    op.add_column(
        "notes",
        sa.Column(
            "encryption_metadata",
            JSONB,
            nullable=True,
            comment="Client-side crypto params: {v, alg, kdf, iter, hash, salt, iv}",
        ),
    )

    op.create_index(
        "ix_notes_encrypted",
        "notes",
        ["is_encrypted"],
        postgresql_where=sa.text("is_encrypted = true"),
    )

    op.execute("""
        CREATE OR REPLACE FUNCTION prevent_encrypted_note_fts()
        RETURNS TRIGGER AS $$
        BEGIN
            IF NEW.is_encrypted = true THEN
                NEW.search_vector := NULL;
                NEW.content_text := '';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER trg_encrypted_note_guard
        BEFORE INSERT OR UPDATE ON notes
        FOR EACH ROW
        WHEN (NEW.is_encrypted = true)
        EXECUTE FUNCTION prevent_encrypted_note_fts();
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_encrypted_note_guard ON notes;")
    op.execute("DROP FUNCTION IF EXISTS prevent_encrypted_note_fts();")
    op.drop_index("ix_notes_encrypted", table_name="notes")
    op.drop_column("notes", "encryption_metadata")
    op.drop_column("notes", "is_encrypted")
