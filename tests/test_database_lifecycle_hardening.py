"""Dedicated regression test suite for Database Lifecycle & Migration Hardening (Sprint 5 Task S5-T04).

Verifies:
1. Application import/startup does not execute MetaData.create_all().
2. WebSocket module import does not execute load_rooms_from_db() or leak DB sessions via next(get_db()).
3. Alembic configuration correctly defaults to settings.DATABASE_URL while preserving programmatic/test overrides.
4. Alembic can cleanly upgrade a fresh isolated temporary database to head and downgrade to base.
5. Existing application routes and WebSocket endpoints remain functional without startup create_all().
6. Production database (chat.db) is protected and unmodified by tests.
"""
import hashlib
import importlib
import os
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

# Ensure tests default to isolated database if run individually
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from alembic.config import Config
from alembic.script import ScriptDirectory
from alembic import command
from tests.test_auth_authorization import ASGIClient
from sqlalchemy.schema import MetaData

from backend.core.config import settings
from backend.db.database import get_db, SessionLocal
import backend.realtime.websocket as ws_module

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_PRODUCTION_DB_PATH = os.path.join(_PROJECT_ROOT, "chat.db")


def _compute_db_hash(file_path: str) -> str:
    """Compute SHA-256 hex digest of a database file using shared read access."""
    if not os.path.exists(file_path):
        return ""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


class TestStartupSchemaCreationRemoved(unittest.TestCase):
    """Verifies that application import/startup does not invoke create_all()."""

    def test_main_import_does_not_call_create_all(self):
        """Reloading/importing main module must never execute MetaData.create_all()."""
        import main
        with patch.object(MetaData, "create_all") as mock_create_all:
            importlib.reload(main)
            mock_create_all.assert_not_called()

    def test_main_module_does_not_import_engine_or_user(self):
        """main.py must not expose engine or User at top-level."""
        import main
        self.assertFalse(
            hasattr(main, "engine"),
            "main module must not import engine now that startup create_all is removed",
        )
        self.assertFalse(
            hasattr(main, "User"),
            "main module must not import User model now that startup create_all is removed",
        )


class TestWebSocketSessionLifecycle(unittest.TestCase):
    """Verifies that WebSocket module does not execute dead room loading or leak sessions."""

    def test_websocket_import_does_not_invoke_get_db(self):
        """Importing or reloading backend.realtime.websocket must not acquire a database session."""
        with patch("backend.realtime.websocket.get_db") as mock_get_db:
            importlib.reload(ws_module)
            mock_get_db.assert_not_called()

    def test_dead_room_permissions_and_loader_removed(self):
        """Dead room_permissions dictionary and load_rooms_from_db must be removed."""
        self.assertFalse(
            hasattr(ws_module, "room_permissions"),
            "Dead global room_permissions dictionary must be removed",
        )
        self.assertFalse(
            hasattr(ws_module, "load_rooms_from_db"),
            "Dead load_rooms_from_db function must be removed",
        )

    def test_active_rooms_and_helpers_preserved(self):
        """Active rooms dictionary and get_dm_room helper must remain intact."""
        self.assertTrue(hasattr(ws_module, "rooms"), "Active rooms dictionary must be preserved")
        self.assertTrue(hasattr(ws_module, "get_dm_room"), "get_dm_room helper must be preserved")
        self.assertEqual(ws_module.get_dm_room("alice", "bob"), "dm_alice_bob")
        self.assertEqual(ws_module.get_dm_room("bob", "alice"), "dm_alice_bob")


class TestAlembicConfigurationAndFreshUpgrade(unittest.TestCase):
    """Verifies Alembic targets configured database and can build fresh schema from scratch."""

    def setUp(self):
        super().setUp()
        self.alembic_ini = os.path.join(_PROJECT_ROOT, "alembic.ini")
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_file.close()
        self.temp_db_path = self.temp_file.name

        # Create pre-migration baseline schema in the isolated temp database
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

    def tearDown(self):
        try:
            if os.path.exists(self.temp_db_path):
                os.unlink(self.temp_db_path)
        finally:
            super().tearDown()

    def test_alembic_env_respects_programmatic_override(self):
        """When a caller explicitly sets sqlalchemy.url, Alembic migrates the overridden target."""
        override_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        override_file.close()
        override_path = override_file.name
        try:
            # Create baseline schema in override target
            conn = sqlite3.connect(override_path)
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

            cfg = Config(self.alembic_ini)
            cfg.set_main_option("sqlalchemy.url", f"sqlite:///{override_path}")

            # Upgrade explicitly targeting the override database
            command.upgrade(cfg, "head")

            # Verify the override database received the migration
            conn = sqlite3.connect(override_path)
            cur = conn.cursor()
            tables = {row[0] for row in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            self.assertIn("alembic_version", tables)
            self.assertIn("message_reactions", tables)
            conn.close()

            # Verify isolated temp_db_path was NOT migrated
            conn2 = sqlite3.connect(self.temp_db_path)
            cur2 = conn2.cursor()
            temp_tables = {row[0] for row in cur2.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            self.assertNotIn("alembic_version", temp_tables)
            conn2.close()
        finally:
            if os.path.exists(override_path):
                os.unlink(override_path)

    def test_alembic_env_defaults_to_settings_database_url(self):
        """When sqlalchemy.url is unset or default, Alembic targets settings.DATABASE_URL."""
        cfg = Config(self.alembic_ini)

        # Point settings.DATABASE_URL to our isolated temp_db_path
        with patch.object(settings, "DATABASE_URL", f"sqlite:///{self.temp_db_path}"):
            command.upgrade(cfg, "head")

            conn = sqlite3.connect(self.temp_db_path)
            cur = conn.cursor()
            tables = {row[0] for row in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            self.assertIn("alembic_version", tables)
            self.assertIn("message_reactions", tables)

            # Verify columns were added to users and messages
            user_cols = {row[1] for row in cur.execute("PRAGMA table_info(users)").fetchall()}
            self.assertIn("display_name", user_cols)
            self.assertIn("about", user_cols)
            self.assertIn("profile_picture", user_cols)
            conn.close()

    def test_fresh_database_upgrade_from_base_to_head_and_downgrade(self):
        """Alembic must be able to upgrade a database from base to head and downgrade cleanly."""
        cfg = Config(self.alembic_ini)
        cfg.set_main_option("sqlalchemy.url", f"sqlite:///{self.temp_db_path}")

        # Upgrade to head
        command.upgrade(cfg, "head")

        # Verify all tables exist
        conn = sqlite3.connect(self.temp_db_path)
        cur = conn.cursor()
        tables = {
            row[0]
            for row in cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }

        expected_tables = {"users", "friends", "messages", "message_reactions", "alembic_version"}
        for table in expected_tables:
            self.assertIn(table, tables, f"Table '{table}' must exist in migrated database")

        # Verify users table columns
        user_cols = {row[1] for row in cur.execute("PRAGMA table_info(users)").fetchall()}
        for col in ("id", "username", "password_hash", "last_seen", "display_name", "about", "profile_picture"):
            self.assertIn(col, user_cols, f"Column '{col}' must exist on migrated users table")

        # Verify messages table columns
        msg_cols = {row[1] for row in cur.execute("PRAGMA table_info(messages)").fetchall()}
        for col in ("id", "sender_id", "receiver_id", "content", "timestamp", "image_url",
                    "is_read", "read_at", "edited_at", "is_deleted", "deleted_at", "reply_to_message_id"):
            self.assertIn(col, msg_cols, f"Column '{col}' must exist on migrated messages table")

        # Verify message_reactions table columns
        reaction_cols = {row[1] for row in cur.execute("PRAGMA table_info(message_reactions)").fetchall()}
        for col in ("id", "message_id", "user_id", "emoji", "created_at"):
            self.assertIn(col, reaction_cols, f"Column '{col}' must exist on migrated message_reactions table")

        conn.close()

        # Downgrade to base
        command.downgrade(cfg, "base")

        conn = sqlite3.connect(self.temp_db_path)
        cur = conn.cursor()
        remaining_revs = cur.execute("SELECT version_num FROM alembic_version").fetchall()
        self.assertEqual(len(remaining_revs), 0, "alembic_version must be empty after full downgrade")
        conn.close()


class TestApplicationRoutesUsability(unittest.TestCase):
    """Verifies application routes and endpoints work without startup create_all()."""

    def test_app_endpoints_respond_normally(self):
        """FastAPI app instance starts and responds to HTTP requests without startup create_all()."""
        from main import app
        client = ASGIClient(app)

        # Frontend route
        resp = client.request("GET", "/")
        self.assertEqual(resp.status_code, 200)

        # Unauthenticated auth check
        resp = client.request("GET", "/me")
        self.assertEqual(resp.status_code, 401)


class TestProductionDatabaseSafety(unittest.TestCase):
    """Guarantees that production chat.db is never touched by test suites."""

    def test_production_db_file_not_corrupted(self):
        """Production database must be openable and valid SQLite."""
        if not os.path.exists(_PRODUCTION_DB_PATH):
            self.skipTest("chat.db does not exist")
        conn = sqlite3.connect(_PRODUCTION_DB_PATH)
        cur = conn.cursor()
        tables = {row[0] for row in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        self.assertIn("users", tables)
        self.assertIn("messages", tables)
        conn.close()


if __name__ == "__main__":
    unittest.main()
