"""Add company_domain column to roadmap_profiles

Revision ID: c3d4e5f6g7h8
Revises: b2c3d4e5f6g7
Create Date: 2026-01-12 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c3d4e5f6g7h8'
down_revision: Union[str, Sequence[str], None] = 'b2c3d4e5f6g7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add company_domain column to roadmap_profiles table."""
    op.add_column('roadmap_profiles', sa.Column('company_domain', sa.String(255), nullable=True))


def downgrade() -> None:
    """Remove company_domain column from roadmap_profiles table."""
    op.drop_column('roadmap_profiles', 'company_domain')
