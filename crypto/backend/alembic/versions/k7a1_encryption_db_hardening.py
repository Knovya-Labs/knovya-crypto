from typing import Sequence, Union

from alembic import op

revision: str = "k7a1b2c3d4e5"
down_revision: Union[str, None] = "db3451ec0a68"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_encrypted_note_guard ON notes;")
    op.execute("DROP FUNCTION IF EXISTS prevent_encrypted_note_fts();")

    op.execute("""
        CREATE OR REPLACE FUNCTION prevent_encrypted_note_fts()
        RETURNS TRIGGER AS $$
        BEGIN
            IF NEW.is_encrypted = true THEN
                NEW.search_vector := NULL;
                NEW.content_text := '';
                NEW.content_json := '[]'::jsonb;
                NEW.embedding := NULL;
                NEW.content_hash := NULL;
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

    op.execute("""
        UPDATE notes SET encryption_metadata = NULL
        WHERE encryption_metadata IS NOT NULL AND jsonb_typeof(encryption_metadata) = 'null';
    """)

    op.execute("""
        ALTER TABLE notes ADD CONSTRAINT chk_encrypted_has_metadata
        CHECK (
            is_encrypted = false
            OR (is_encrypted = true AND encryption_metadata IS NOT NULL
                AND jsonb_typeof(encryption_metadata) = 'object')
        );
    """)

    op.execute("""
        ALTER TABLE notes ADD CONSTRAINT chk_encryption_metadata_valid
        CHECK (
            encryption_metadata IS NULL
            OR jsonb_typeof(encryption_metadata) != 'object'
            OR (
                encryption_metadata ? 'v'
                AND encryption_metadata ? 'alg'
                AND encryption_metadata ? 'kdf'
                AND encryption_metadata ? 'iter'
                AND encryption_metadata ? 'salt'
                AND encryption_metadata ? 'iv'
                AND encryption_metadata ? 'wrappedDek'
                AND encryption_metadata ? 'dekIv'
                AND (encryption_metadata->>'iter')::int >= 100000
                AND encryption_metadata->>'alg' = 'AES-256-GCM'
            )
        );
    """)

    op.execute("DROP VIEW IF EXISTS admin_notes_view;")
    op.execute("""
        CREATE VIEW admin_notes_view AS
        SELECT
            id, workspace_id, user_id, folder_id, status,
            '[REDACTED]' AS title,
            '[REDACTED]' AS content_md,
            '[REDACTED]' AS content_text,
            char_length(COALESCE(content_text, '')) AS content_length,
            is_pinned, is_favorited, is_locked, is_encrypted,
            created_at, updated_at, deleted_at,
            version, language, meta,
            checklist_total, checklist_done
        FROM notes;
    """)


def downgrade() -> None:
    op.execute("""
        CREATE OR REPLACE VIEW admin_notes_view AS
        SELECT
            id, workspace_id, user_id, folder_id, status,
            '[REDACTED]' AS title,
            '[REDACTED]' AS content_md,
            '[REDACTED]' AS content_text,
            char_length(COALESCE(content_text, '')) AS content_length,
            is_pinned, is_favorited, is_locked,
            created_at, updated_at, deleted_at,
            version, language, meta,
            checklist_total, checklist_done
        FROM notes;
    """)

    op.execute("ALTER TABLE notes DROP CONSTRAINT IF EXISTS chk_encryption_metadata_valid;")
    op.execute("ALTER TABLE notes DROP CONSTRAINT IF EXISTS chk_encrypted_has_metadata;")

    op.execute("DROP TRIGGER IF EXISTS trg_encrypted_note_guard ON notes;")
    op.execute("DROP FUNCTION IF EXISTS prevent_encrypted_note_fts();")

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
