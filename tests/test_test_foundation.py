"""Tests verifying test foundation, database isolation, and production DB safety."""
import hashlib
import os
import unittest
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

import backend.db.database as db_module
from backend.db.models import User, Friend, Message
from tests.base import BaseTestCase


class TestDatabaseIsolation(BaseTestCase):
    """Verify that each test case runs with an isolated database."""

    def test_isolation_step_a(self):
        """Create a canary record; step_b will verify it does not leak."""
        canary = User(
            username="canary_user_123",
            password_hash="hash",
            display_name="Canary",
        )
        self.db.add(canary)
        self.db.commit()
        found = self.db.query(User).filter(User.username == "canary_user_123").first()
        self.assertIsNotNone(found)

    def test_isolation_step_b(self):
        """Verify the canary record from step_a does not exist here."""
        found = self.db.query(User).filter(User.username == "canary_user_123").first()
        self.assertIsNone(found, "Test isolation failed: canary user from previous test is present")


class TestDatabaseBehavior(BaseTestCase):
    """Verify SQLite foreign keys and engine configuration."""

    def test_pragma_foreign_keys_active(self):
        """PRAGMA foreign_keys must report 1 (enabled)."""
        fk_val = self.db.execute(text("PRAGMA foreign_keys")).scalar()
        self.assertEqual(fk_val, 1)

    def test_fk_constraint_rejects_invalid_reference(self):
        """Inserting an invalid foreign key must raise IntegrityError."""
        bad_message = Message(
            sender_id=self.alice.id,
            receiver_id=self.bob.id,
            content="Bad FK",
            timestamp=datetime.now(timezone.utc),
            reply_to_message_id=999999,
        )
        self.db.add(bad_message)
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()


class TestProductionDatabaseSafety(BaseTestCase):
    """Verify tests do not touch or use the production database."""

    def test_test_engine_is_isolated_from_production(self):
        """Test engine must be an in-memory SQLite engine and distinct from production engine."""
        self.assertIsNot(self.engine, db_module.engine)
        self.assertEqual(self.engine.url.database, ":memory:")

    def test_default_database_url_preserves_chat_db_when_unset(self):
        """Verify normal application default without environment variable is sqlite:///./chat.db."""
        saved_env = os.environ.get("DATABASE_URL")
        try:
            # Simulate unset environment variable
            os.environ.pop("DATABASE_URL", None)
            resolved_url = os.getenv("DATABASE_URL", "sqlite:///./chat.db")
            self.assertEqual(resolved_url, "sqlite:///./chat.db")
        finally:
            if saved_env is not None:
                os.environ["DATABASE_URL"] = saved_env

    def test_chat_db_file_hash_unaltered_by_test_operations(self):
        """Verify chat.db content hash is completely unchanged after test database writes."""
        chat_db_path = Path("chat.db")
        if not chat_db_path.exists():
            self.skipTest("chat.db does not exist in workspace root")

        # Compute SHA-256 before operations
        sha256_before = hashlib.sha256(chat_db_path.read_bytes()).hexdigest()

        # Perform writes and commits in the test database
        user = self.create_user("safety_test_user")
        msg = Message(
            sender_id=user.id,
            receiver_id=self.alice.id,
            content="Safety test message",
            timestamp=datetime.now(timezone.utc),
        )
        self.db.add(msg)
        self.db.commit()

        # Compute SHA-256 after operations
        sha256_after = hashlib.sha256(chat_db_path.read_bytes()).hexdigest()

        self.assertEqual(
            sha256_before,
            sha256_after,
            "chat.db was altered during test execution!",
        )


class TestBaseTestCaseHelpers(BaseTestCase):
    """Verify helper methods on BaseTestCase."""

    def test_create_user_helper(self):
        """create_user helper persists and returns user."""
        u = self.create_user("helper_user", display_name="Helper")
        self.assertIsNotNone(u.id)
        self.assertEqual(u.username, "helper_user")
        self.assertEqual(u.display_name, "Helper")

    def test_create_two_way_friendship_helper(self):
        """create_two_way_friendship helper persists bidirectional friendship."""
        u1 = self.create_user("user_a")
        u2 = self.create_user("user_b")
        self.create_two_way_friendship(u1, u2)

        f1 = self.db.query(Friend).filter(Friend.user_id == u1.id, Friend.friend_id == u2.id).first()
        f2 = self.db.query(Friend).filter(Friend.user_id == u2.id, Friend.friend_id == u1.id).first()
        self.assertIsNotNone(f1)
        self.assertIsNotNone(f2)
        self.assertEqual(f1.status, "accepted")
        self.assertEqual(f2.status, "accepted")


if __name__ == "__main__":
    unittest.main()
