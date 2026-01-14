"""add_user_search_quota_table

Revision ID: e1f2a3b4c5d6
Revises: 097ac2c97d2a
Create Date: 2026-01-13 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e1f2a3b4c5d6'
down_revision: Union[str, Sequence[str], None] = '097ac2c97d2a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create user_search_quota table for tracking daily search usage."""
    op.create_table(
        'user_search_quota',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('date', sa.Date(), nullable=False, index=True),
        sa.Column('searches_used', sa.Integer(), nullable=False, default=0),
        sa.Column('search_limit', sa.Integer(), nullable=False, default=10),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.UniqueConstraint('user_id', 'date', name='uq_user_search_quota_user_date')
    )


def downgrade() -> None:
    """Drop user_search_quota table."""
    op.drop_table('user_search_quota')
