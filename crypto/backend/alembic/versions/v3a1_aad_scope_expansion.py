from typing import Sequence, Union

from alembic import op


revision: str = "v3a1"
down_revision: Union[str, None] = "c4d1e8b2a7f9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE notes DROP CONSTRAINT IF EXISTS chk_encryption_metadata_valid;")
    op.execute("""
        ALTER TABLE notes ADD CONSTRAINT chk_encryption_metadata_valid CHECK (
            encryption_metadata IS NULL
            OR jsonb_typeof(encryption_metadata) != 'object'
            OR (
                encryption_metadata ? 'v'
                AND encryption_metadata ? 'alg'
                AND encryption_metadata ? 'kdf'
                AND encryption_metadata ? 'iter'
                AND encryption_metadata ? 'hash'
                AND encryption_metadata ? 'salt'
                AND encryption_metadata ? 'iv'
                AND encryption_metadata ? 'wrappedDek'
                AND encryption_metadata ? 'dekIv'
                AND (encryption_metadata->>'iter')::int >= 600000
                AND encryption_metadata->>'alg' = 'AES-256-GCM'
                AND encryption_metadata->>'kdf' = 'PBKDF2'
                AND encryption_metadata->>'hash' = 'SHA-256'
                AND (encryption_metadata->>'v')::int IN (1, 2, 3)
            )
        );
    """)

    op.execute("ALTER TABLE user_preferences DROP CONSTRAINT IF EXISTS chk_encryption_setup_valid;")
    op.execute("""
        ALTER TABLE user_preferences ADD CONSTRAINT chk_encryption_setup_valid CHECK (
            encryption_setup IS NULL
            OR (
                jsonb_typeof(encryption_setup) = 'object'
                AND encryption_setup ? 'salt'
                AND encryption_setup ? 'wrappedDek'
                AND encryption_setup ? 'dekIv'
            )
        );
    """)


def downgrade() -> None:
    op.execute("ALTER TABLE user_preferences DROP CONSTRAINT IF EXISTS chk_encryption_setup_valid;")

    op.execute("ALTER TABLE notes DROP CONSTRAINT IF EXISTS chk_encryption_metadata_valid;")
    op.execute("""
        ALTER TABLE notes ADD CONSTRAINT chk_encryption_metadata_valid CHECK (
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
