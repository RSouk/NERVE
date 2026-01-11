"""Add image_url, read_time, and active fields to education_resources

Revision ID: a1b2c3d4e5f6
Revises: fb340ee8dabb
Create Date: 2026-01-11 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = 'fb340ee8dabb'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add new columns to education_resources table."""
    # Add image_url column (nullable)
    op.add_column('education_resources', sa.Column('image_url', sa.String(500), nullable=True))

    # Add read_time column (nullable)
    op.add_column('education_resources', sa.Column('read_time', sa.String(20), nullable=True))

    # Add active column (nullable first, then set defaults)
    op.add_column('education_resources', sa.Column('active', sa.Boolean(), nullable=True))

    # Set default values for existing rows
    op.execute("UPDATE education_resources SET active = 1 WHERE active IS NULL")
    op.execute("UPDATE education_resources SET read_time = '5 min read' WHERE read_time IS NULL")


def downgrade() -> None:
    """Remove new columns from education_resources table."""
    op.drop_column('education_resources', 'active')
    op.drop_column('education_resources', 'read_time')
    op.drop_column('education_resources', 'image_url')
