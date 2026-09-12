"""Tests for Message.reply_to_message_id foreign-key integrity.

These tests validate the database-level FK constraint added by migration
a1b2c3d4e5f6.  They use an in-memory SQLite database with
PRAGMA foreign_keys = ON so that FK constraints are actually enforced
(SQLite disables FK enforcement by default).
"""
import unittest
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from backend.db.models import Message
from backend.services import chat_service
from backend.services.chat_service import BadRequestError
from tests.base import BaseTestCase


class TestReplyFKIntegrity(BaseTestCase):
    """Database-level foreign-key constraint tests for reply_to_message_id."""


    # ------------------------------------------------------------------
    # 1. reply_to_message_id can be NULL
    # ------------------------------------------------------------------
    def test_null_reply_to_message_id(self):
        """Messages without a reply reference must remain valid."""
        msg = Message(
            sender_id=self.alice.id,
            receiver_id=self.bob.id,
            content="Hello",
            timestamp=datetime.now(timezone.utc),
            reply_to_message_id=None,
        )
        self.db.add(msg)
        self.db.commit()
        self.db.refresh(msg)

        self.assertIsNone(msg.reply_to_message_id)
        self.assertIsNotNone(msg.id)

    # ------------------------------------------------------------------
    # 2. Valid reply_to_message_id succeeds
    # ------------------------------------------------------------------
    def test_valid_reply_to_message_id(self):
        """A reply pointing to an existing message must succeed."""
        parent = Message(
            sender_id=self.alice.id,
            receiver_id=self.bob.id,
            content="Parent message",
            timestamp=datetime.now(timezone.utc),
        )
        self.db.add(parent)
        self.db.commit()
        self.db.refresh(parent)

        reply = Message(
            sender_id=self.bob.id,
            receiver_id=self.alice.id,
            content="Reply message",
            timestamp=datetime.now(timezone.utc),
            reply_to_message_id=parent.id,
        )
        self.db.add(reply)
        self.db.commit()
        self.db.refresh(reply)

        self.assertEqual(reply.reply_to_message_id, parent.id)
        self.assertEqual(reply.reply_to.id, parent.id)

    # ------------------------------------------------------------------
    # 3. Invalid/nonexistent reply_to_message_id is rejected by DB
    # ------------------------------------------------------------------
    def test_invalid_reply_to_message_id_rejected(self):
        """A reply pointing to a nonexistent message must be rejected by the DB FK constraint."""
        bad_reply = Message(
            sender_id=self.alice.id,
            receiver_id=self.bob.id,
            content="Bad reply",
            timestamp=datetime.now(timezone.utc),
            reply_to_message_id=999999,
        )
        self.db.add(bad_reply)
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()

    # ------------------------------------------------------------------
    # 4. Soft-deleting a parent does NOT physically delete the reply
    # ------------------------------------------------------------------
    def test_soft_delete_parent_preserves_reply(self):
        """Soft-deleting a parent message must not affect the reply row."""
        parent = chat_service.create_message(
            self.db, self.alice, self.bob, "Parent", None,
        )
        reply = chat_service.create_message(
            self.db, self.bob, self.alice, "Reply", None,
            reply_to_message_id=parent.id,
        )

        # Soft-delete the parent
        chat_service.delete_message(self.db, self.alice, parent.id)
        self.db.refresh(parent)
        self.assertTrue(parent.is_deleted)
        self.assertIsNotNone(parent.deleted_at)

        # Reply must still exist and still reference the parent
        self.db.refresh(reply)
        self.assertFalse(reply.is_deleted)
        self.assertEqual(reply.reply_to_message_id, parent.id)

    # ------------------------------------------------------------------
    # 5. Application-level same-conversation validation still works
    # ------------------------------------------------------------------
    def test_app_level_same_conversation_validation(self):
        """Service-layer validation rejects a reply to a message from a different conversation."""
        # alice -> bob message
        msg_ab = chat_service.create_message(
            self.db, self.alice, self.bob, "Alice to Bob", None,
        )

        # charlie tries to reply to alice->bob message (wrong conversation)
        with self.assertRaises(BadRequestError) as ctx:
            chat_service.create_message(
                self.db, self.charlie, self.alice, "Bad cross-conv reply", None,
                reply_to_message_id=msg_ab.id,
            )
        self.assertIn("does not belong to this conversation", str(ctx.exception))

    # ------------------------------------------------------------------
    # 6. Application-level nonexistent reply target validation
    # ------------------------------------------------------------------
    def test_app_level_nonexistent_reply_target(self):
        """Service-layer validation rejects a reply to a nonexistent message."""
        with self.assertRaises(BadRequestError) as ctx:
            chat_service.create_message(
                self.db, self.alice, self.bob, "Bad reply", None,
                reply_to_message_id=999999,
            )
        self.assertIn("not found", str(ctx.exception))

    # ------------------------------------------------------------------
    # 7. Reply chain integrity — multi-level replies
    # ------------------------------------------------------------------
    def test_reply_chain_integrity(self):
        """Multi-level reply chains must preserve all FK references."""
        msg1 = chat_service.create_message(
            self.db, self.alice, self.bob, "Root", None,
        )
        msg2 = chat_service.create_message(
            self.db, self.bob, self.alice, "Reply L1", None,
            reply_to_message_id=msg1.id,
        )
        msg3 = chat_service.create_message(
            self.db, self.alice, self.bob, "Reply L2", None,
            reply_to_message_id=msg2.id,
        )

        self.db.refresh(msg1)
        self.db.refresh(msg2)
        self.db.refresh(msg3)

        self.assertIsNone(msg1.reply_to_message_id)
        self.assertEqual(msg2.reply_to_message_id, msg1.id)
        self.assertEqual(msg3.reply_to_message_id, msg2.id)

    # ------------------------------------------------------------------
    # 8. FK enforcement pragma is active
    # ------------------------------------------------------------------
    def test_pragma_foreign_keys_enabled(self):
        """PRAGMA foreign_keys must report ON (1) in the test session."""
        result = self.db.execute(text("PRAGMA foreign_keys")).scalar()
        self.assertEqual(result, 1)

    # ------------------------------------------------------------------
    # 9. ON DELETE SET NULL behavior (physical delete safety net)
    # ------------------------------------------------------------------
    def test_on_delete_set_null(self):
        """Physically deleting a parent row must SET NULL on the reply's FK, not cascade delete it.

        Note: Base.metadata.create_all() builds the FK from the SQLAlchemy
        model definition, which currently lacks an explicit ondelete= keyword.
        The Alembic migration adds the ON DELETE SET NULL at the DB level for
        the production database.  To test the SET NULL behavior in isolation
        we build a dedicated in-memory table with the constraint.
        """
        from sqlalchemy import MetaData, Table, Column, Integer, String, DateTime, Boolean, ForeignKey

        meta = MetaData()
        t = Table(
            "test_messages", meta,
            Column("id", Integer, primary_key=True),
            Column("sender_id", Integer, nullable=False),
            Column("receiver_id", Integer, nullable=False),
            Column("content", String),
            Column("timestamp", DateTime),
            Column("is_deleted", Boolean, default=False),
            Column("reply_to_message_id", Integer,
                   ForeignKey("test_messages.id", ondelete="SET NULL"),
                   nullable=True),
        )
        meta.create_all(self.engine)

        conn = self.engine.connect()
        # Enable FK enforcement on this raw connection
        conn.execute(text("PRAGMA foreign_keys=ON"))

        # Insert parent
        conn.execute(t.insert().values(
            id=1, sender_id=self.alice.id, receiver_id=self.bob.id,
            content="Parent", timestamp=datetime.now(timezone.utc),
            is_deleted=False, reply_to_message_id=None,
        ))
        # Insert reply pointing to parent
        conn.execute(t.insert().values(
            id=2, sender_id=self.bob.id, receiver_id=self.alice.id,
            content="Reply", timestamp=datetime.now(timezone.utc),
            is_deleted=False, reply_to_message_id=1,
        ))
        conn.commit()

        # Verify reply references parent
        row = conn.execute(text("SELECT reply_to_message_id FROM test_messages WHERE id=2")).fetchone()
        self.assertEqual(row[0], 1)

        # Physically delete parent
        conn.execute(text("DELETE FROM test_messages WHERE id=1"))
        conn.commit()

        # Reply must survive with reply_to_message_id SET NULL
        row = conn.execute(text("SELECT id, reply_to_message_id FROM test_messages WHERE id=2")).fetchone()
        self.assertIsNotNone(row, "Reply row must survive parent deletion")
        self.assertIsNone(row[1], "reply_to_message_id must be SET NULL after parent deletion")

        # Verify parent is gone
        parent_row = conn.execute(text("SELECT id FROM test_messages WHERE id=1")).fetchone()
        self.assertIsNone(parent_row, "Parent row must be deleted")

        conn.close()
        meta.drop_all(self.engine)

    # ------------------------------------------------------------------
    # 10. Confirm the production migration FK has ON DELETE SET NULL
    # ------------------------------------------------------------------
    def test_migration_fk_has_on_delete_set_null(self):
        """Verify the Alembic migration script specifies ondelete='SET NULL'."""
        import os
        migration_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "alembic", "versions",
            "a1b2c3d4e5f6_add_reply_to_message_id_foreign_key.py",
        )
        with open(migration_path, "r") as f:
            source = f.read()
        self.assertIn("ondelete", source)
        self.assertIn("SET NULL", source)
        self.assertIn("batch_alter_table", source)


if __name__ == "__main__":
    unittest.main()
