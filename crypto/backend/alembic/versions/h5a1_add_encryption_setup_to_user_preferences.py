from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision: str = 'h5a1e2f3g4h5'
down_revision: Union[str, None] = 'b7c26d8142f4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'user_preferences',
        sa.Column('encryption_setup', JSONB, nullable=True),
    )


def downgrade() -> None:
    op.drop_column('user_preferences', 'encryption_setup')
