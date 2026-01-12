"""Add data_types column to roadmap_profiles

Revision ID: b2c3d4e5f6g7
Revises: a1b2c3d4e5f6
Create Date: 2026-01-12 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b2c3d4e5f6g7'
down_revision: Union[str, Sequence[str], None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add data_types column to roadmap_profiles table."""
    # Add data_types column (nullable TEXT for JSON array)
    op.add_column('roadmap_profiles', sa.Column('data_types', sa.Text(), nullable=True))

    # Migrate existing boolean flags to data_types array for existing profiles
    # This ensures backward compatibility
    op.execute("""
        UPDATE roadmap_profiles
        SET data_types = '[]'
        WHERE data_types IS NULL
    """)


def downgrade() -> None:
    """Remove data_types column from roadmap_profiles table."""
    op.drop_column('roadmap_profiles', 'data_types')
