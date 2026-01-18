"""add_auto_scan_fields_to_cached_asm

Revision ID: j6k7l8m9n0o1
Revises: i5j6k7l8m9n0
Create Date: 2026-01-18 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'j6k7l8m9n0o1'
down_revision: Union[str, Sequence[str], None] = 'i5j6k7l8m9n0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add auto-scan tracking fields for company users"""
    # Add last_scanned timestamp
    op.add_column('cached_asm_scans',
        sa.Column('last_scanned', sa.DateTime(), nullable=True)
    )

    # Add next_scan_at timestamp for scheduling
    op.add_column('cached_asm_scans',
        sa.Column('next_scan_at', sa.DateTime(), nullable=True)
    )

    # Add auto_scan_enabled flag (only true for company users)
    op.add_column('cached_asm_scans',
        sa.Column('auto_scan_enabled', sa.Boolean(), nullable=False, server_default='0')
    )


def downgrade() -> None:
    """Remove auto-scan fields"""
    op.drop_column('cached_asm_scans', 'auto_scan_enabled')
    op.drop_column('cached_asm_scans', 'next_scan_at')
    op.drop_column('cached_asm_scans', 'last_scanned')
