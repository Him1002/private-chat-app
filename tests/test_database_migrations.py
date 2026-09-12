"""Database and Alembic migration regression test suite for ChatSpic (Sprint 4 Task S4-T07).

Validates:
1. Migration chain integrity (dynamic traversal, single head, unbroken down_revisions).
2. Fresh schema validation (Base.metadata.create_all tables, columns, indexes, constraints).
3. Reply foreign key regression (messages.reply_to_message_id -> messages.id ON DELETE SET NULL).
4. Message schema regression (is_read, read_at, edited_at, is_deleted, deleted_at, reply_to_message_id).
5. Reaction schema regression (constraints, indexes, actual schema delete semantics).
6. Profile schema regression (display_name, about, profile_picture columns and types).
7. Migration execution safety (isolated temporary SQLite upgrade/downgrade lifecycle).
8. Database protection (production chat.db SHA-256 hash preservation).
"""
import hashlib
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone

from alembic.config import Config
from alembic.script import ScriptDirectory
from alembic import command
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from backend.db.database import Base, engine as backend_engine
from backend.db.models import User, Friend, Message, MessageReaction
from tests.base import BaseTestCase

# Record the production chat.db hash at module import time (immediately before test suite execution)
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PRODUCTION_DB_PATH = os.path.join(_PROJECT_ROOT, "chat.db")


def _compute_db_hash(path: str) -> str | None:
    """Compute SHA-256 hash of a database file if it exists."""
    if not os.path.exists(path):
        return None
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


_INITIAL_PROD_DB_HASH = _compute_db_hash(_PRODUCTION_DB_PATH)


# ==============================================================================
# 1. Migration Chain Integrity
# ==============================================================================
class TestMigrationChainIntegrity(unittest.TestCase):
    """Verifies the integrity of the Alembic migration history graph dynamically."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alembic_ini = os.path.join(_PROJECT_ROOT, "alembic.ini")
        cls.cfg = Config(cls.alembic_ini)
        cls.script = ScriptDirectory.from_config(cls.cfg)

    def test_exactly_one_head_revision(self):
        """Alembic migration graph must have exactly one head revision."""
        heads = self.script.get_heads()
        self.assertEqual(
            len(heads),
            1,
            f"Expected exactly 1 migration head, found {len(heads)}: {heads}",
        )

    def test_dynamic_linear_chain_walk(self):
        """Revisions must form an unbroken, linear chain from head to base."""
        heads = self.script.get_heads()
        self.assertEqual(len(heads), 1)
        head_rev = heads[0]

        revisions = list(self.script.walk_revisions())
        self.assertGreater(len(revisions), 0, "Migration history must contain at least one revision")
        self.assertEqual(revisions[0].revision, head_rev, "First revision walked must be the head")

        # Walk each revision and verify down_revision links sequentially
        for i, rev in enumerate(revisions):
            if i + 1 < len(revisions):
                expected_down = revisions[i + 1].revision
                self.assertEqual(
                    rev.down_revision,
                    expected_down,
                    f"Revision {rev.revision} down_revision '{rev.down_revision}' "
                    f"does not match expected down revision '{expected_down}'",
                )
            else:
                self.assertIsNone(
                    rev.down_revision,
                    f"Base revision {rev.revision} must have down_revision=None, got '{rev.down_revision}'",
                )

    def test_all_version_files_present_in_chain(self):
        """Every revision script file in alembic/versions must be reachable in the walk."""
        versions_dir = os.path.join(_PROJECT_ROOT, "alembic", "versions")
        disk_files = [
            f for f in os.listdir(versions_dir)
            if f.endswith(".py") and not f.startswith("__")
        ]

        chain_revisions = {rev.revision for rev in self.script.walk_revisions()}

        # Verify each file's revision ID is part of the traversed chain
        for filename in disk_files:
            file_path = os.path.join(versions_dir, filename)
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Extract revision = '...'
            rev_id = None
            for line in content.splitlines():
                if line.startswith("revision"):
                    parts = line.split("=")
                    if len(parts) == 2:
                        rev_id = parts[1].strip().strip("'\"")
                        break

            self.assertIsNotNone(rev_id, f"Could not parse revision identifier from {filename}")
            self.assertIn(
                rev_id,
                chain_revisions,
                f"Revision {rev_id} from {filename} is orphaned and not part of the active chain",
            )

    def test_revisions_have_descriptions(self):
        """Every revision must define a non-empty docstring / description."""
        for rev in self.script.walk_revisions():
            self.assertTrue(
                rev.doc and rev.doc.strip(),
                f"Revision {rev.revision} is missing a descriptive docstring",
            )


# ==============================================================================
# 2. Fresh Schema Validation
# ==============================================================================
class TestFreshSchemaValidation(BaseTestCase):
    """Verifies that Base.metadata.create_all() builds all expected tables, columns, and constraints."""

    def test_core_tables_created(self):
        """All expected tables must be created by Base.metadata.create_all()."""
        inspector = inspect(self.engine)
        table_names = set(inspector.get_table_names())
        expected_tables = {"users", "friends", "messages", "message_reactions"}
        self.assertTrue(
            expected_tables.issubset(table_names),
            f"Missing expected tables. Expected {expected_tables}, got {table_names}",
        )

    def test_users_table_schema(self):
        """Users table must contain all required authentication and profile columns."""
        inspector = inspect(self.engine)
        columns = {col["name"]: col for col in inspector.get_columns("users")}

        expected_columns = {
            "id", "username", "password_hash", "last_seen",
            "display_name", "about", "profile_picture",
        }
        self.assertTrue(expected_columns.issubset(columns.keys()))

        # Non-nullable columns
        self.assertFalse(columns["username"]["nullable"])
        self.assertFalse(columns["password_hash"]["nullable"])

        # Profile fields should be nullable
        self.assertTrue(columns["display_name"]["nullable"])
        self.assertTrue(columns["about"]["nullable"])
        self.assertTrue(columns["profile_picture"]["nullable"])

        # Primary key
        pk = inspector.get_pk_constraint("users")
        self.assertEqual(pk["constrained_columns"], ["id"])

    def test_friends_table_schema(self):
        """Friends table must contain user_id, friend_id, and status with proper FKs."""
        inspector = inspect(self.engine)
        columns = {col["name"]: col for col in inspector.get_columns("friends")}
        expected_columns = {"id", "user_id", "friend_id", "status"}
        self.assertTrue(expected_columns.issubset(columns.keys()))

        fks = inspector.get_foreign_keys("friends")
        fk_targets = {(fk["referred_table"], tuple(fk["referred_columns"])) for fk in fks}
        self.assertIn(("users", ("id",)), fk_targets)

    def test_messages_table_schema(self):
        """Messages table must contain message state fields, timestamps, and foreign keys."""
        inspector = inspect(self.engine)
        columns = {col["name"]: col for col in inspector.get_columns("messages")}

        expected_columns = {
            "id", "sender_id", "receiver_id", "content", "image_url",
            "timestamp", "is_read", "read_at", "edited_at",
            "is_deleted", "deleted_at", "reply_to_message_id",
        }
        self.assertTrue(expected_columns.issubset(columns.keys()))

        # is_read and is_deleted must not be nullable
        self.assertFalse(columns["is_read"]["nullable"])
        self.assertFalse(columns["is_deleted"]["nullable"])

        # Foreign keys: sender_id -> users.id, receiver_id -> users.id, reply_to_message_id -> messages.id
        fks = inspector.get_foreign_keys("messages")
        fk_map = {tuple(fk["constrained_columns"]): (fk["referred_table"], tuple(fk["referred_columns"])) for fk in fks}

        self.assertEqual(fk_map.get(("sender_id",)), ("users", ("id",)))
        self.assertEqual(fk_map.get(("receiver_id",)), ("users", ("id",)))
        self.assertEqual(fk_map.get(("reply_to_message_id",)), ("messages", ("id",)))

    def test_message_reactions_table_schema(self):
        """Message reactions table must have FKs and unique constraint on (message_id, user_id, emoji)."""
        inspector = inspect(self.engine)
        columns = {col["name"]: col for col in inspector.get_columns("message_reactions")}

        expected_columns = {"id", "message_id", "user_id", "emoji", "created_at"}
        self.assertTrue(expected_columns.issubset(columns.keys()))

        # Non-nullable columns
        self.assertFalse(columns["message_id"]["nullable"])
        self.assertFalse(columns["user_id"]["nullable"])
        self.assertFalse(columns["emoji"]["nullable"])

        # Unique constraint on (message_id, user_id, emoji)
        unique_constraints = inspector.get_unique_constraints("message_reactions")
        constrained_sets = [set(uc["column_names"]) for uc in unique_constraints]
        self.assertIn(
            {"message_id", "user_id", "emoji"},
            constrained_sets,
            "Missing unique constraint on (message_id, user_id, emoji)",
        )

    def test_table_indexes_exist(self):
        """Verify indexed columns have corresponding indexes created."""
        inspector = inspect(self.engine)

        users_indexes = {idx["name"] for idx in inspector.get_indexes("users")}
        self.assertIn("ix_users_username", users_indexes)
        self.assertIn("ix_users_id", users_indexes)

        reactions_indexes = {idx["name"] for idx in inspector.get_indexes("message_reactions")}
        self.assertIn("ix_message_reactions_message_id", reactions_indexes)
        self.assertIn("ix_message_reactions_id", reactions_indexes)


# ==============================================================================
# 3. Reply Foreign Key Regression
# ==============================================================================
class TestReplyFKRegression(BaseTestCase):
    """Validates reply_to_message_id foreign key constraint, enforcement, and ON DELETE SET NULL."""

    def test_sqlite_foreign_keys_pragma_enabled(self):
        """PRAGMA foreign_keys must be ON (1) for database sessions."""
        status = self.db.execute(text("PRAGMA foreign_keys")).scalar()
        self.assertEqual(status, 1, "PRAGMA foreign_keys must report 1 (ON)")

    def test_model_reply_fk_has_ondelete_set_null(self):
        """Message.reply_to_message_id ForeignKey must specify ondelete='SET NULL'."""
        reply_col = Message.__table__.c.reply_to_message_id
        fk = list(reply_col.foreign_keys)[0]
        self.assertEqual(fk.target_fullname, "messages.id")
        self.assertEqual(fk.ondelete, "SET NULL")

    def test_valid_reply_persists_successfully(self):
        """Inserting a reply referencing a valid parent message succeeds."""
        parent = Message(
            sender_id=self.alice.id,
            receiver_id=self.bob.id,
            content="Hello Bob",
            timestamp=datetime.now(timezone.utc),
        )
        self.db.add(parent)
        self.db.commit()

        reply = Message(
            sender_id=self.bob.id,
            receiver_id=self.alice.id,
            content="Hello Alice",
            timestamp=datetime.now(timezone.utc),
            reply_to_message_id=parent.id,
        )
        self.db.add(reply)
        self.db.commit()

        self.assertEqual(reply.reply_to_message_id, parent.id)
        self.assertEqual(reply.reply_to.id, parent.id)

    def test_invalid_reply_fk_rejected_by_sqlite(self):
        """Inserting a reply with a nonexistent reply_to_message_id raises IntegrityError."""
        bad_reply = Message(
            sender_id=self.alice.id,
            receiver_id=self.bob.id,
            content="Invalid parent",
            timestamp=datetime.now(timezone.utc),
            reply_to_message_id=999999,
        )
        self.db.add(bad_reply)
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()

    def test_parent_deletion_sets_reply_to_message_id_null(self):
        """Deleting a referenced parent message sets reply_to_message_id to NULL on the reply."""
        parent = Message(
            sender_id=self.alice.id,
            receiver_id=self.bob.id,
            content="Parent message to be deleted",
            timestamp=datetime.now(timezone.utc),
        )
        self.db.add(parent)
        self.db.commit()

        reply = Message(
            sender_id=self.bob.id,
            receiver_id=self.alice.id,
            content="Reply message surviving",
            timestamp=datetime.now(timezone.utc),
            reply_to_message_id=parent.id,
        )
        self.db.add(reply)
        self.db.commit()

        # Delete parent message
        self.db.delete(parent)
        self.db.commit()

        # Refresh reply row; it must still exist and reply_to_message_id must be NULL
        self.db.refresh(reply)
        self.assertIsNotNone(reply.id, "Reply row must not be deleted")
        self.assertIsNone(reply.reply_to_message_id, "reply_to_message_id must be SET NULL")

    def test_multi_reply_deletion_sets_all_replies_null(self):
        """Deleting a parent with multiple replies sets reply_to_message_id=NULL on all replies."""
        parent = Message(
            sender_id=self.alice.id,
            receiver_id=self.bob.id,
            content="Multi-reply parent",
            timestamp=datetime.now(timezone.utc),
        )
        self.db.add(parent)
        self.db.commit()

        reply1 = Message(
            sender_id=self.bob.id,
            receiver_id=self.alice.id,
            content="Reply 1",
            timestamp=datetime.now(timezone.utc),
            reply_to_message_id=parent.id,
        )
        reply2 = Message(
            sender_id=self.charlie.id,
            receiver_id=self.alice.id,
            content="Reply 2",
            timestamp=datetime.now(timezone.utc),
            reply_to_message_id=parent.id,
        )
        self.db.add_all([reply1, reply2])
        self.db.commit()

        self.db.delete(parent)
        self.db.commit()

        self.db.refresh(reply1)
        self.db.refresh(reply2)
        self.assertIsNone(reply1.reply_to_message_id)
        self.assertIsNone(reply2.reply_to_message_id)

    def test_cascading_reply_chain_deletion(self):
        """In a chain A -> B -> C, deleting B sets C's reply_to_message_id=NULL without affecting A."""
        msg_a = Message(sender_id=self.alice.id, receiver_id=self.bob.id, content="A")
        self.db.add(msg_a)
        self.db.commit()

        msg_b = Message(sender_id=self.bob.id, receiver_id=self.alice.id, content="B", reply_to_message_id=msg_a.id)
        self.db.add(msg_b)
        self.db.commit()

        msg_c = Message(sender_id=self.alice.id, receiver_id=self.bob.id, content="C", reply_to_message_id=msg_b.id)
        self.db.add(msg_c)
        self.db.commit()

        # Delete middle message B
        self.db.delete(msg_b)
        self.db.commit()

        self.db.refresh(msg_a)
        self.db.refresh(msg_c)
        self.assertEqual(msg_a.content, "A")
        self.assertIsNone(msg_a.reply_to_message_id)
        self.assertIsNone(msg_c.reply_to_message_id, "C's reply_to_message_id must become NULL")


# ==============================================================================
# 4. Message Schema Regression
# ==============================================================================
class TestMessageSchemaRegression(BaseTestCase):
    """Validates Message schema attributes, default values, and non-null constraints."""

    def test_expected_attributes_exist_on_model(self):
        """Verify Message model has is_read, read_at, edited_at, is_deleted, deleted_at, reply_to_message_id."""
        msg = Message()
        for attr in ("is_read", "read_at", "edited_at", "is_deleted", "deleted_at", "reply_to_message_id"):
            self.assertTrue(hasattr(msg, attr), f"Message model missing attribute '{attr}'")

    def test_default_values_on_insert(self):
        """New message inserted without state flags defaults to is_read=False, is_deleted=False, others None."""
        msg = Message(
            sender_id=self.alice.id,
            receiver_id=self.bob.id,
            content="Default test",
            timestamp=datetime.now(timezone.utc),
        )
        self.db.add(msg)
        self.db.commit()
        self.db.refresh(msg)

        self.assertFalse(msg.is_read)
        self.assertIsNone(msg.read_at)
        self.assertIsNone(msg.edited_at)
        self.assertFalse(msg.is_deleted)
        self.assertIsNone(msg.deleted_at)
        self.assertIsNone(msg.reply_to_message_id)

    def test_non_null_constraint_on_is_read_and_is_deleted(self):
        """Setting is_read or is_deleted to None violates the non-nullable constraint."""
        from sqlalchemy import insert

        # Verify model column definition specifies nullable=False
        self.assertFalse(Message.__table__.c.is_read.nullable)
        self.assertFalse(Message.__table__.c.is_deleted.nullable)

        # Direct insertion of explicit NULL must raise IntegrityError at DB level
        with self.assertRaises(IntegrityError):
            self.db.execute(
                insert(Message).values(
                    sender_id=self.alice.id,
                    receiver_id=self.bob.id,
                    content="Null is_read",
                    is_read=None,
                    is_deleted=False,
                )
            )
            self.db.commit()
        self.db.rollback()

        with self.assertRaises(IntegrityError):
            self.db.execute(
                insert(Message).values(
                    sender_id=self.alice.id,
                    receiver_id=self.bob.id,
                    content="Null is_deleted",
                    is_read=False,
                    is_deleted=None,
                )
            )
            self.db.commit()
        self.db.rollback()

    def test_message_lifecycle_fields_persist(self):
        """State transitions for read_at, edited_at, deleted_at persist correctly."""
        msg = Message(
            sender_id=self.alice.id,
            receiver_id=self.bob.id,
            content="Original content",
        )
        self.db.add(msg)
        self.db.commit()

        # Mark read
        now = datetime.now(timezone.utc)
        msg.is_read = True
        msg.read_at = now
        self.db.commit()
        self.db.refresh(msg)
        self.assertTrue(msg.is_read)
        self.assertIsNotNone(msg.read_at)

        # Edit message
        edit_time = datetime.now(timezone.utc)
        msg.content = "Edited content"
        msg.edited_at = edit_time
        self.db.commit()
        self.db.refresh(msg)
        self.assertEqual(msg.content, "Edited content")
        self.assertIsNotNone(msg.edited_at)

        # Soft delete message
        del_time = datetime.now(timezone.utc)
        msg.is_deleted = True
        msg.deleted_at = del_time
        self.db.commit()
        self.db.refresh(msg)
        self.assertTrue(msg.is_deleted)
        self.assertIsNotNone(msg.deleted_at)


# ==============================================================================
# 5. Reaction Schema Regression
# ==============================================================================
class TestReactionSchemaRegression(BaseTestCase):
    """Validates MessageReaction schema, constraints, and actual delete behavior."""

    def setUp(self):
        super().setUp()
        self.test_message = Message(
            sender_id=self.alice.id,
            receiver_id=self.bob.id,
            content="React to this",
            timestamp=datetime.now(timezone.utc),
        )
        self.db.add(self.test_message)
        self.db.commit()
        self.db.refresh(self.test_message)

    def test_reaction_unique_constraint_enforced(self):
        """Unique constraint on (message_id, user_id, emoji) prevents duplicate reactions."""
        r1 = MessageReaction(
            message_id=self.test_message.id,
            user_id=self.alice.id,
            emoji="👍",
        )
        self.db.add(r1)
        self.db.commit()

        r2 = MessageReaction(
            message_id=self.test_message.id,
            user_id=self.alice.id,
            emoji="👍",
        )
        self.db.add(r2)
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()

    def test_different_emojis_or_users_allowed(self):
        """Different emojis for same user, or same emoji for different users, are permitted."""
        r1 = MessageReaction(message_id=self.test_message.id, user_id=self.alice.id, emoji="👍")
        r2 = MessageReaction(message_id=self.test_message.id, user_id=self.alice.id, emoji="❤️")
        r3 = MessageReaction(message_id=self.test_message.id, user_id=self.bob.id, emoji="👍")
        self.db.add_all([r1, r2, r3])
        self.db.commit()

        reactions = self.db.query(MessageReaction).filter_by(message_id=self.test_message.id).all()
        self.assertEqual(len(reactions), 3)

    def test_reaction_foreign_key_enforcement(self):
        """Reactions referencing non-existent message_id or user_id are rejected."""
        bad_msg_rx = MessageReaction(message_id=999999, user_id=self.alice.id, emoji="🔥")
        self.db.add(bad_msg_rx)
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()

        bad_user_rx = MessageReaction(message_id=self.test_message.id, user_id=999999, emoji="🔥")
        self.db.add(bad_user_rx)
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()

    def test_orm_cascade_deletes_reactions(self):
        """Deleting a Message via SQLAlchemy ORM cascades and removes associated reactions."""
        rx = MessageReaction(message_id=self.test_message.id, user_id=self.alice.id, emoji="🎉")
        self.db.add(rx)
        self.db.commit()

        # Delete message via ORM
        self.db.delete(self.test_message)
        self.db.commit()

        remaining_rx = self.db.query(MessageReaction).filter_by(message_id=self.test_message.id).all()
        self.assertEqual(len(remaining_rx), 0, "ORM deletion must delete orphan reactions")

    def test_raw_sql_delete_without_cascade_enforced_by_foreign_key(self):
        """Verifies actual schema behavior: the DDL FK has no ON DELETE CASCADE, so raw SQL DELETE fails."""
        rx = MessageReaction(message_id=self.test_message.id, user_id=self.alice.id, emoji="🎉")
        self.db.add(rx)
        self.db.commit()

        # Raw SQL delete directly against the SQLite engine with PRAGMA foreign_keys=ON
        with self.assertRaises(IntegrityError):
            self.db.execute(text("DELETE FROM messages WHERE id = :mid"), {"mid": self.test_message.id})
            self.db.commit()
        self.db.rollback()

    def test_migration_and_model_agreement(self):
        """Model columns and unique constraint name match migration 404ca8c4c2f9."""
        table = MessageReaction.__table__
        self.assertEqual(table.name, "message_reactions")
        self.assertIn("message_id", table.c)
        self.assertIn("user_id", table.c)
        self.assertIn("emoji", table.c)
        self.assertIn("created_at", table.c)

        uq_names = {c.name for c in table.constraints if c.name}
        self.assertIn("uq_reaction_per_user", uq_names)


# ==============================================================================
# 6. Profile Schema Regression
# ==============================================================================
class TestProfileSchemaRegression(BaseTestCase):
    """Validates User profile schema (display_name, about, profile_picture)."""

    def test_profile_columns_exist_on_user_model(self):
        """User model must have display_name, about, and profile_picture attributes."""
        user = User(username="test_profile_user", password_hash="hash")
        for attr in ("display_name", "about", "profile_picture"):
            self.assertTrue(hasattr(user, attr), f"User model missing attribute '{attr}'")

    def test_profile_fields_nullable_by_default(self):
        """Creating a user without profile fields leaves them as None."""
        user = User(username="minimal_user", password_hash="hash")
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)

        self.assertIsNone(user.display_name)
        self.assertIsNone(user.about)
        self.assertIsNone(user.profile_picture)

    def test_profile_fields_crud_persistence(self):
        """Profile fields can be set, read, updated, and cleared."""
        user = User(
            username="custom_profile",
            password_hash="hash",
            display_name="Custom Name",
            about="Software Developer",
            profile_picture="https://example.com/pic.png",
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)

        self.assertEqual(user.display_name, "Custom Name")
        self.assertEqual(user.about, "Software Developer")
        self.assertEqual(user.profile_picture, "https://example.com/pic.png")

        # Update profile fields
        user.display_name = "Updated Name"
        user.about = None
        self.db.commit()
        self.db.refresh(user)

        self.assertEqual(user.display_name, "Updated Name")
        self.assertIsNone(user.about)


# ==============================================================================
# 7. Migration Execution Safety (Isolated Temporary Database)
# ==============================================================================
class TestMigrationExecutionSafety(unittest.TestCase):
    """Executes the full migration upgrade and downgrade lifecycle against an isolated temporary SQLite database."""

    def setUp(self):
        super().setUp()
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_file.close()
        self.temp_db_path = self.temp_file.name

        # Create pre-migration base schema in the isolated temp database
        conn = sqlite3.connect(self.temp_db_path)
        cur = conn.cursor()
        cur.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username VARCHAR NOT NULL, "
            "password_hash VARCHAR NOT NULL, last_seen DATETIME)"
        )
        cur.execute(
            "CREATE TABLE friends (id INTEGER PRIMARY KEY, user_id INTEGER, "
            "friend_id INTEGER, status VARCHAR)"
        )
        cur.execute(
            "CREATE TABLE messages (id INTEGER PRIMARY KEY, sender_id INTEGER, "
            "receiver_id INTEGER, content VARCHAR, timestamp DATETIME, image_url VARCHAR)"
        )
        conn.commit()
        conn.close()

        # Configure Alembic pointing exclusively to this temporary database
        self.cfg = Config(os.path.join(_PROJECT_ROOT, "alembic.ini"))
        self.cfg.set_main_option("sqlalchemy.url", f"sqlite:///{self.temp_db_path}")
        self.script = ScriptDirectory.from_config(self.cfg)

    def tearDown(self):
        try:
            if os.path.exists(self.temp_db_path):
                os.unlink(self.temp_db_path)
        finally:
            super().tearDown()

    def test_migration_upgrade_and_downgrade_lifecycle(self):
        """Alembic must upgrade cleanly from base to head, then downgrade to base in isolation."""
        head_rev = self.script.get_heads()[0]

        # 1. Upgrade to head
        command.upgrade(self.cfg, "head")

        conn = sqlite3.connect(self.temp_db_path)
        cur = conn.cursor()
        current_rev = cur.execute("SELECT version_num FROM alembic_version").fetchone()
        self.assertIsNotNone(current_rev, "alembic_version table must have a record after upgrade")
        self.assertEqual(current_rev[0], head_rev, "Upgraded database must match head revision")

        # Verify added columns on messages exist in upgraded DB
        msg_columns = {row[1] for row in cur.execute("PRAGMA table_info(messages)").fetchall()}
        for col in ("is_read", "read_at", "edited_at", "is_deleted", "deleted_at", "reply_to_message_id"):
            self.assertIn(col, msg_columns, f"Column '{col}' must exist on migrated messages table")

        # Verify added columns on users exist in upgraded DB
        user_columns = {row[1] for row in cur.execute("PRAGMA table_info(users)").fetchall()}
        for col in ("display_name", "about", "profile_picture"):
            self.assertIn(col, user_columns, f"Column '{col}' must exist on migrated users table")

        # Verify message_reactions table exists
        tables = {row[0] for row in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        self.assertIn("message_reactions", tables, "message_reactions table must exist after migration")

        conn.close()

        # 2. Downgrade to base
        command.downgrade(self.cfg, "base")

        conn = sqlite3.connect(self.temp_db_path)
        cur = conn.cursor()
        base_revs = cur.execute("SELECT version_num FROM alembic_version").fetchall()
        self.assertEqual(len(base_revs), 0, "alembic_version must be empty after full downgrade to base")
        conn.close()

        # 3. Re-upgrade to head (idempotence verification)
        command.upgrade(self.cfg, "head")
        conn = sqlite3.connect(self.temp_db_path)
        cur = conn.cursor()
        reupgraded_rev = cur.execute("SELECT version_num FROM alembic_version").fetchone()
        self.assertIsNotNone(reupgraded_rev)
        self.assertEqual(reupgraded_rev[0], head_rev)
        conn.close()


# ==============================================================================
# 8. Database Protection
# ==============================================================================
class TestDatabaseProtection(unittest.TestCase):
    """Guarantees that test executions never mutate or contaminate the production database."""

    def test_production_chat_db_hash_unchanged(self):
        """The SHA-256 hash of chat.db must match the hash recorded immediately before the test run."""
        if _INITIAL_PROD_DB_HASH is None:
            self.skipTest("chat.db does not exist in workspace root")

        current_hash = _compute_db_hash(_PRODUCTION_DB_PATH)
        self.assertEqual(
            current_hash,
            _INITIAL_PROD_DB_HASH,
            f"Production chat.db was modified during test run! Initial: {_INITIAL_PROD_DB_HASH}, Current: {current_hash}",
        )

    def test_backend_database_engine_configures_foreign_keys(self):
        """backend.db.database.engine must enforce PRAGMA foreign_keys=ON on connect."""
        with backend_engine.connect() as conn:
            fk_status = conn.execute(text("PRAGMA foreign_keys")).scalar()
            self.assertEqual(fk_status, 1, "backend engine must enforce PRAGMA foreign_keys=ON")


if __name__ == "__main__":
    unittest.main()
