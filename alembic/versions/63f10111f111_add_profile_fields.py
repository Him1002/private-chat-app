"""add profile fields

Revision ID: 63f10111f111
Revises: 404ca8c4c2f9
Create Date: 2026-09-12 18:55:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '63f10111f111'
down_revision: Union[str, Sequence[str], None] = '404ca8c4c2f9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('users', sa.Column('display_name', sa.String(), nullable=True))
    op.add_column('users', sa.Column('about', sa.String(), nullable=True))
    op.add_column('users', sa.Column('profile_picture', sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column('users', 'profile_picture')
    op.drop_column('users', 'about')
    op.drop_column('users', 'display_name')
