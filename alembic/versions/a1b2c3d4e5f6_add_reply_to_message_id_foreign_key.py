"""add reply_to_message_id foreign key constraint

Revision ID: a1b2c3d4e5f6
Revises: 63f10111f111
Create Date: 2026-09-12 23:50:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = '63f10111f111'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add FK constraint on messages.reply_to_message_id -> messages.id.

    Uses batch_alter_table because SQLite does not support
    ALTER TABLE ... ADD CONSTRAINT.  Alembic recreates the table behind
    the scenes, preserving all data, columns, indexes and existing FKs.
    """
    with op.batch_alter_table('messages', schema=None) as batch_op:
        batch_op.create_foreign_key(
            'fk_messages_reply_to_message_id',
            'messages',
            ['reply_to_message_id'],
            ['id'],
            ondelete='SET NULL',
        )


def downgrade() -> None:
    """Remove FK constraint on messages.reply_to_message_id."""
    with op.batch_alter_table('messages', schema=None) as batch_op:
        batch_op.drop_constraint('fk_messages_reply_to_message_id', type_='foreignkey')
