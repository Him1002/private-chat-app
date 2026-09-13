"""
Focused S5-T08 Test Suite — Backup & Recovery for ChatSpic.

Tests cover:
- Backup creation with SQLite Online Backup API
- Timestamped filenames and directory creation
- Verification of integrity, schema, and Alembic version
- Retention cleanup (keeps newest, keeps verified, skips unverified)
- Safe restore with pre-restore safety snapshots and staging
- Target database locked error handling
- CLI commands (create, list, verify, restore)
- Configuration defaults and path resolution
- Sensitive data absence in logging

All tests run against isolated temporary databases and directories; the production
chat.db is never touched.
"""
import io
import logging
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine, text

from backend.core.config import Settings, resolve_sqlite_path
from backend.core.logging_config import setup_logging
from backend.db.database import Base
import backend.db.models  # noqa: F401
from backend.services.backup_service import (
    DEFAULT_EXPECTED_TABLES,
    BackupError,
    BackupSourceNotFoundError,
    BackupVerificationError,
    RestoreError,
    TargetDatabaseLockedError,
    create_backup,
    list_backups,
    prune_backups,
    restore_backup,
    verify_backup,
)
from backend.tools.backup import main as cli_main


def create_test_database(db_path: Path, alembic_version: str = "a1b2c3d4e5f6") -> Path:
    """Create an isolated SQLite database populated with ChatSpic schema and Alembic revision."""
    from sqlalchemy.pool import NullPool
    engine = create_engine(f"sqlite:///{db_path.as_posix()}", connect_args={"check_same_thread": False}, poolclass=NullPool)
    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE IF NOT EXISTS alembic_version (version_num VARCHAR(32) NOT NULL, PRIMARY KEY (version_num));"))
        conn.execute(text(f"INSERT OR REPLACE INTO alembic_version (version_num) VALUES ('{alembic_version}');"))
        conn.execute(text("INSERT INTO users (username, password_hash) VALUES ('test_user', 'hashed_pw');"))
        conn.execute(text("INSERT INTO messages (sender_id, receiver_id, content, is_read, is_deleted) VALUES (1, 1, 'Secret backup test content', 0, 0);"))
    engine.dispose()
    return db_path


class TestBackupConfiguration(unittest.TestCase):
    """Test backup configuration and path resolution."""

    def test_default_configuration_values(self):
        s = Settings(_env_file=None, ENVIRONMENT="development")
        self.assertEqual(s.BACKUP_DIR, "backups")
        self.assertEqual(s.BACKUP_RETENTION_COUNT, 7)

    def test_environment_variable_overrides(self):
        with patch.dict(os.environ, {"BACKUP_DIR": "custom_backups", "BACKUP_RETENTION_COUNT": "15"}):
            s = Settings(_env_file=None)
            self.assertEqual(s.BACKUP_DIR, "custom_backups")
            self.assertEqual(s.BACKUP_RETENTION_COUNT, 15)

    def test_invalid_retention_defaults_cleanly(self):
        s = Settings(_env_file=None, BACKUP_RETENTION_COUNT="not_a_number")
        self.assertEqual(s.BACKUP_RETENTION_COUNT, 7)

        s_zero = Settings(_env_file=None, BACKUP_RETENTION_COUNT=0)
        self.assertEqual(s_zero.BACKUP_RETENTION_COUNT, 1)

    def test_resolve_sqlite_path(self):
        p1 = resolve_sqlite_path("sqlite:///./chat.db")
        self.assertEqual(p1.name, "chat.db")

        p2 = resolve_sqlite_path("sqlite:///chat.db")
        self.assertEqual(p2.name, "chat.db")

        # Unsupported schemes or in-memory
        with self.assertRaises(ValueError):
            resolve_sqlite_path("sqlite:///:memory:")

        with self.assertRaises(ValueError):
            resolve_sqlite_path("postgresql://user:pass@localhost/db")

        with self.assertRaises(ValueError):
            resolve_sqlite_path("")


class TestBackupCreationAndVerification(unittest.TestCase):
    """Test creating backups and validating backup files."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.base_path = Path(self.temp_dir.name)
        self.db_path = self.base_path / "test_source.db"
        self.backup_dir = self.base_path / "backups"
        create_test_database(self.db_path)

    def tearDown(self):
        import gc
        gc.collect()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_backup_creation_and_filename(self):
        result = create_backup(source_path=self.db_path, backup_dir=self.backup_dir)
        self.assertTrue(result.success)
        self.assertTrue(result.backup_path.is_file())
        self.assertTrue(result.backup_path.name.startswith("chat_backup_"))
        self.assertTrue(result.backup_path.name.endswith(".db"))
        self.assertGreater(result.size_bytes, 0)
        self.assertTrue(result.verification.is_valid)
        self.assertEqual(result.verification.alembic_version, "a1b2c3d4e5f6")

    def test_backup_directory_created_automatically(self):
        nested_dir = self.base_path / "deep" / "nested" / "backups"
        self.assertFalse(nested_dir.exists())
        result = create_backup(source_path=self.db_path, backup_dir=nested_dir)
        self.assertTrue(nested_dir.is_dir())
        self.assertTrue(result.backup_path.is_file())

    def test_live_sqlite_database_backup(self):
        """Backup succeeds while live database has active connections and transactions."""
        conn = sqlite3.connect(str(self.db_path))
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users;")
        self.assertEqual(cur.fetchone()[0], 1)

        result = create_backup(source_path=self.db_path, backup_dir=self.backup_dir)
        self.assertTrue(result.success)

        # Source database remains completely intact and functional
        cur.execute("INSERT INTO users (username, password_hash) VALUES ('live_user', 'live_hash');")
        conn.commit()
        cur.execute("SELECT COUNT(*) FROM users;")
        self.assertEqual(cur.fetchone()[0], 2)
        conn.close()

    def test_source_database_remains_unmodified_during_backup(self):
        before_stat = self.db_path.stat()
        result = create_backup(source_path=self.db_path, backup_dir=self.backup_dir)
        self.assertTrue(result.success)
        after_stat = self.db_path.stat()
        self.assertEqual(before_stat.st_size, after_stat.st_size)

    def test_missing_source_database_raises_error(self):
        nonexistent = self.base_path / "nonexistent.db"
        with self.assertRaises(BackupSourceNotFoundError):
            create_backup(source_path=nonexistent, backup_dir=self.backup_dir)
        self.assertFalse(self.backup_dir.exists())

    def test_verify_backup_valid_file(self):
        result = create_backup(source_path=self.db_path, backup_dir=self.backup_dir)
        v = verify_backup(result.backup_path)
        self.assertTrue(v.is_valid)
        self.assertIsNone(v.error)
        self.assertIn("users", v.tables)
        self.assertIn("messages", v.tables)
        self.assertIn("friends", v.tables)
        self.assertIn("message_reactions", v.tables)
        self.assertIn("alembic_version", v.tables)

    def test_verify_backup_missing_or_empty_file(self):
        v_missing = verify_backup(self.base_path / "does_not_exist.db")
        self.assertFalse(v_missing.is_valid)
        self.assertIn("does not exist", v_missing.error)

        empty_file = self.base_path / "empty.db"
        empty_file.touch()
        v_empty = verify_backup(empty_file)
        self.assertFalse(v_empty.is_valid)
        self.assertIn("0 bytes", v_empty.error)

    def test_verify_backup_corrupt_file(self):
        corrupt_file = self.base_path / "corrupt.db"
        corrupt_file.write_bytes(b"This is completely corrupt non-sqlite header garbage text")
        v = verify_backup(corrupt_file)
        self.assertFalse(v.is_valid)
        self.assertIn("SQLite database error", v.error)

    def test_verify_backup_missing_required_tables(self):
        partial_db = self.base_path / "partial.db"
        conn = sqlite3.connect(str(partial_db))
        conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY);")
        conn.execute("CREATE TABLE alembic_version (version_num VARCHAR(32));")
        conn.execute("INSERT INTO alembic_version VALUES ('head');")
        conn.commit()
        conn.close()

        v = verify_backup(partial_db)
        self.assertFalse(v.is_valid)
        self.assertIn("missing required ChatSpic tables", v.error)


class TestBackupRetention(unittest.TestCase):
    """Test retention pruning safety rules."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.base_path = Path(self.temp_dir.name)
        self.db_path = self.base_path / "source.db"
        self.backup_dir = self.base_path / "backups"
        create_test_database(self.db_path)

    def tearDown(self):
        import gc
        gc.collect()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_retention_prunes_older_verified_backups(self):
        # Create 5 backups with retention = 3
        created = []
        for i in range(5):
            # Create a backup file directly
            b_path = self.backup_dir / f"chat_backup_2026010{i+1}_120000.db"
            self.backup_dir.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.db_path, b_path)
            # Adjust mtime so ordering is strictly determined
            mtime = 1700000000 + (i * 100)
            os.utime(b_path, (mtime, mtime))
            created.append(b_path)

        pruned = prune_backups(backup_dir=self.backup_dir, retention_count=3)
        self.assertEqual(len(pruned), 2)
        # The two oldest (index 0 and 1) should be pruned
        self.assertFalse(created[0].exists())
        self.assertFalse(created[1].exists())
        # The three newest (index 2, 3, 4) must be preserved
        self.assertTrue(created[2].exists())
        self.assertTrue(created[3].exists())
        self.assertTrue(created[4].exists())

    def test_newest_valid_backup_is_never_pruned(self):
        b1 = self.backup_dir / "chat_backup_20260101_120000.db"
        b2 = self.backup_dir / "chat_backup_20260102_120000.db"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.db_path, b1)
        shutil.copyfile(self.db_path, b2)
        os.utime(b1, (1700000000, 1700000000))
        os.utime(b2, (1700000100, 1700000100))

        # Retention count 1: only newest should remain
        pruned = prune_backups(backup_dir=self.backup_dir, retention_count=1)
        self.assertEqual(len(pruned), 1)
        self.assertEqual(pruned[0].name, b1.name)
        self.assertTrue(b2.exists())

    def test_unverified_corrupt_backups_are_not_deleted_by_retention(self):
        """Unverified/corrupt backups must be preserved for operator review, not deleted."""
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        # Valid backup
        valid_b = self.backup_dir / "chat_backup_20260101_100000.db"
        shutil.copyfile(self.db_path, valid_b)
        os.utime(valid_b, (1700000100, 1700000100))

        # Corrupt backup matching filename format
        corrupt_b = self.backup_dir / "chat_backup_20260101_090000.db"
        corrupt_b.write_bytes(b"corrupt junk data")
        os.utime(corrupt_b, (1700000000, 1700000000))

        # Retention prune with count 1
        pruned = prune_backups(backup_dir=self.backup_dir, retention_count=1)
        self.assertEqual(len(pruned), 0)
        self.assertTrue(valid_b.exists())
        self.assertTrue(corrupt_b.exists(), "Corrupt backup should be preserved for operator review")


class TestBackupRestore(unittest.TestCase):
    """Test safe database restoration."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.base_path = Path(self.temp_dir.name)
        self.live_db = self.base_path / "live_chat.db"
        self.backup_dir = self.base_path / "backups"
        create_test_database(self.live_db)

        # Create a valid backup
        res = create_backup(source_path=self.live_db, backup_dir=self.backup_dir)
        self.valid_backup = res.backup_path

    def tearDown(self):
        import gc
        gc.collect()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_restore_rejects_invalid_backup_without_modifying_target(self):
        corrupt_backup = self.backup_dir / "chat_backup_corrupt.db"
        corrupt_backup.write_bytes(b"invalid data")

        initial_mtime = self.live_db.stat().st_mtime
        with self.assertRaises(BackupVerificationError):
            restore_backup(
                backup_file=corrupt_backup,
                target_path=self.live_db,
                backup_dir=self.backup_dir,
            )

        # Live DB remains untouched
        self.assertEqual(self.live_db.stat().st_mtime, initial_mtime)

    def test_restore_creates_safety_backup_and_restores_state(self):
        # Mutate live DB (insert new user)
        conn = sqlite3.connect(str(self.live_db))
        conn.execute("INSERT INTO users (username, password_hash) VALUES ('alice_new', 'pw');")
        conn.commit()
        conn.close()

        # Check live DB has 2 users
        conn = sqlite3.connect(str(self.live_db))
        count = conn.execute("SELECT COUNT(*) FROM users;").fetchone()[0]
        conn.close()
        self.assertEqual(count, 2)

        # Restore from original backup (which only had 1 user)
        res = restore_backup(
            backup_file=self.valid_backup,
            target_path=self.live_db,
            backup_dir=self.backup_dir,
            create_safety_backup=True,
        )
        self.assertTrue(res.success)
        self.assertIsNotNone(res.safety_backup_path)
        self.assertTrue(res.safety_backup_path.is_file())

        # Safety backup has the 2 users
        s_conn = sqlite3.connect(str(res.safety_backup_path))
        s_count = s_conn.execute("SELECT COUNT(*) FROM users;").fetchone()[0]
        s_conn.close()
        self.assertEqual(s_count, 2)

        # Restored live database has the 1 original user
        r_conn = sqlite3.connect(str(self.live_db))
        r_count = r_conn.execute("SELECT COUNT(*) FROM users;").fetchone()[0]
        r_conn.close()
        self.assertEqual(r_count, 1)

    def test_restore_detects_target_database_locked(self):
        """Simulate a locked target database (e.g. Windows file sharing violation)."""
        with patch("pathlib.Path.replace", side_effect=PermissionError("File in use")):
            with self.assertRaises(TargetDatabaseLockedError) as ctx:
                restore_backup(
                    backup_file=self.valid_backup,
                    target_path=self.live_db,
                    backup_dir=self.backup_dir,
                )
            self.assertIn("locked by another process", str(ctx.exception))
            # Target DB is still intact
            v = verify_backup(self.live_db)
            self.assertTrue(v.is_valid)


class TestBackupCLI(unittest.TestCase):
    """Test CLI operational interface."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.base_path = Path(self.temp_dir.name)
        self.db_path = self.base_path / "cli_source.db"
        self.backup_dir = self.base_path / "cli_backups"
        create_test_database(self.db_path)

    def tearDown(self):
        import gc
        gc.collect()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_cli_create_and_list(self):
        stdout = io.StringIO()
        with patch("sys.stdout", stdout):
            code = cli_main([
                "create",
                "--db-path", str(self.db_path),
                "--backup-dir", str(self.backup_dir),
            ])
        self.assertEqual(code, 0)
        self.assertIn("BACKUP CREATION SUCCESSFUL", stdout.getvalue())

        # List command
        stdout_list = io.StringIO()
        with patch("sys.stdout", stdout_list):
            code_list = cli_main([
                "list",
                "--backup-dir", str(self.backup_dir),
            ])
        self.assertEqual(code_list, 0)
        self.assertIn("VERIFIED", stdout_list.getvalue())

    def test_cli_verify(self):
        res = create_backup(source_path=self.db_path, backup_dir=self.backup_dir)
        stdout = io.StringIO()
        with patch("sys.stdout", stdout):
            code = cli_main(["verify", str(res.backup_path)])
        self.assertEqual(code, 0)
        self.assertIn("PASSED (VALID)", stdout.getvalue())

    def test_cli_restore_with_yes_flag(self):
        res = create_backup(source_path=self.db_path, backup_dir=self.backup_dir)
        stdout = io.StringIO()
        with patch("sys.stdout", stdout):
            code = cli_main([
                "restore", str(res.backup_path),
                "--target-db", str(self.db_path),
                "--yes",
            ])
        self.assertEqual(code, 0)
        self.assertIn("RESTORE SUCCESSFUL", stdout.getvalue())


class TestBackupSecurityAndLogging(unittest.TestCase):
    """Verify that sensitive database values and secrets are never emitted to logs."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.base_path = Path(self.temp_dir.name)
        self.db_path = self.base_path / "sec_test.db"
        self.backup_dir = self.base_path / "sec_backups"
        create_test_database(self.db_path)

    def tearDown(self):
        import gc
        gc.collect()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_no_sensitive_data_in_logs(self):
        log_stream = io.StringIO()
        logger = setup_logging(logging.INFO)
        handler = logging.StreamHandler(log_stream)
        handler.setLevel(logging.INFO)
        logger.addHandler(handler)

        try:
            res = create_backup(source_path=self.db_path, backup_dir=self.backup_dir)
            restore_backup(
                backup_file=res.backup_path,
                target_path=self.db_path,
                backup_dir=self.backup_dir,
            )
            logs = log_stream.getvalue()

            # Must contain lifecycle events
            self.assertIn("Backup started", logs)
            self.assertIn("Backup successfully created", logs)
            self.assertIn("Restore requested", logs)
            self.assertIn("Database restore completed", logs)

            # Must NEVER contain sensitive values from database rows
            self.assertNotIn("Secret backup test content", logs)
            self.assertNotIn("hashed_pw", logs)
            self.assertNotIn("Bearer ", logs)
        finally:
            logger.removeHandler(handler)


if __name__ == "__main__":
    unittest.main()
