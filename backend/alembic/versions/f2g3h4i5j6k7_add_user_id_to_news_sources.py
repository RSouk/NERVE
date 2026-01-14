"""add_user_id_to_news_sources

Revision ID: f2g3h4i5j6k7
Revises: e1f2a3b4c5d6
Create Date: 2026-01-13 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f2g3h4i5j6k7'
down_revision: Union[str, Sequence[str], None] = 'e1f2a3b4c5d6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add user_id column to news_sources for user-specific RSS feeds."""
    # Step 1: Add user_id column as nullable first
    op.add_column('news_sources', sa.Column('user_id', sa.Integer(), nullable=True))

    # Step 2: Set default user_id for existing sources (assign to first admin user)
    # This ensures existing feeds are assigned to someone
    op.execute("UPDATE news_sources SET user_id = COALESCE(created_by, 1) WHERE user_id IS NULL")

    # Step 3: Create index on user_id for performance
    op.create_index(op.f('ix_news_sources_user_id'), 'news_sources', ['user_id'], unique=False)

    # Note: SQLite doesn't support altering columns to be NOT NULL or adding foreign keys
    # The model enforces nullable=False and the relationship is handled at the application level


def downgrade() -> None:
    """Remove user_id from news_sources."""
    op.drop_index(op.f('ix_news_sources_user_id'), table_name='news_sources')
    op.drop_column('news_sources', 'user_id')
