"""add_maintenance_checklist_table

Revision ID: g3h4i5j6k7l8
Revises: f2g3h4i5j6k7
Create Date: 2026-01-14 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'g3h4i5j6k7l8'
down_revision: Union[str, Sequence[str], None] = 'f2g3h4i5j6k7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create maintenance_checklist table for user-specific weekly task tracking."""
    op.create_table(
        'maintenance_checklist',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('task_key', sa.String(50), nullable=False),
        sa.Column('task_name', sa.String(200), nullable=False),
        sa.Column('task_description', sa.String(500), nullable=True),
        sa.Column('completed', sa.Boolean(), nullable=False, default=False),
        sa.Column('week_start', sa.Date(), nullable=False, index=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.UniqueConstraint('user_id', 'task_key', 'week_start', name='uq_maintenance_user_task_week')
    )


def downgrade() -> None:
    """Drop maintenance_checklist table."""
    op.drop_table('maintenance_checklist')
