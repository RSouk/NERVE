"""add_phase_to_roadmap_tasks

Revision ID: 097ac2c97d2a
Revises: c3d4e5f6g7h8
Create Date: 2026-01-12 21:23:01.443628

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '097ac2c97d2a'
down_revision: Union[str, Sequence[str], None] = 'c3d4e5f6g7h8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add phase column to roadmap_tasks table."""
    # Add phase column (default to 1 for Foundation)
    op.add_column('roadmap_tasks', sa.Column('phase', sa.Integer(), nullable=True))

    # Set default phase to 1 for existing tasks
    op.execute("UPDATE roadmap_tasks SET phase = 1 WHERE phase IS NULL")


def downgrade() -> None:
    """Remove phase column from roadmap_tasks table."""
    op.drop_column('roadmap_tasks', 'phase')
