"""add_waitlist_table

Revision ID: i5j6k7l8m9n0
Revises: h4i5j6k7l8m9
Create Date: 2026-01-15 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'i5j6k7l8m9n0'
down_revision: Union[str, Sequence[str], None] = 'h4i5j6k7l8m9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create waitlist table for early access signups."""
    op.create_table(
        'waitlist',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('email', sa.String(255), nullable=False, unique=True, index=True),
        sa.Column('company', sa.String(255), nullable=True),
        sa.Column('signup_date', sa.DateTime(), nullable=True),
        sa.Column('ip_address', sa.String(50), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('status', sa.String(50), nullable=True, default='pending'),
        sa.Column('notes', sa.Text(), nullable=True)
    )


def downgrade() -> None:
    """Drop waitlist table."""
    op.drop_table('waitlist')
