"""
Backup and Recovery Service for ChatSpic (S5-T08).

Provides standard-library-based SQLite database backup, integrity verification,
retention management, and safe recovery workflows for single-instance deployments.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import sqlite3
from typing import List, Optional, Set, Union
import uuid

from backend.core.config import resolve_sqlite_path, settings

logger = logging.getLogger("backend.services.backup_service")

# Core persistent tables expected in a valid ChatSpic database as of S5-T08.
# NOTE: Future Alembic migrations that introduce new permanent application tables
# should update this baseline set so backup verification encompasses them.
DEFAULT_EXPECTED_TABLES: Set[str] = {
    "users",
    "friends",
    "messages",
    "message_reactions",
    "alembic_version",
}


class BackupError(Exception):
    """Base exception for all backup and restore operations."""
    pass


class BackupSourceNotFoundError(BackupError):
    """Raised when the configured or specified source database file does not exist."""
    pass


class BackupVerificationError(BackupError):
    """Raised when a backup fails integrity or schema verification."""
    pass


class RestoreError(BackupError):
    """Raised when a restore operation fails or cannot proceed."""
    pass


class TargetDatabaseLockedError(RestoreError):
    """Raised when the target database is locked by another running process (e.g. on Windows)."""
    pass


@dataclass
class VerificationResult:
    """Represents the outcome of a backup verification check."""
    is_valid: bool
    file_path: Path
    size_bytes: int
    tables: List[str]
    alembic_version: Optional[str] = None
    error: Optional[str] = None

    def __str__(self) -> str:
        if self.is_valid:
            return (
                f"VALID: {self.file_path.name} "
                f"(size: {self.size_bytes} bytes, alembic_version: {self.alembic_version or 'N/A'}, "
                f"tables: {len(self.tables)})"
            )
        return f"INVALID: {self.file_path.name} (error: {self.error})"


@dataclass
class BackupInfo:
    """Metadata summary of a backup file in the backup directory."""
    filename: str
    path: Path
    size_bytes: int
    modified_time: datetime
    is_verified: bool
    verification_error: Optional[str] = None


@dataclass
class BackupResult:
    """Result of a backup creation operation."""
    success: bool
    backup_path: Path
    size_bytes: int
    timestamp: datetime
    verification: VerificationResult
    pruned_backups: List[Path]


@dataclass
class RestoreResult:
    """Result of a database restore operation."""
    success: bool
    restored_path: Path
    backup_source: Path
    safety_backup_path: Optional[Path] = None


def verify_backup(
    backup_file: Union[str, Path],
    expected_tables: Optional[Set[str]] = None,
) -> VerificationResult:
    """Verify the integrity, schema, and Alembic version of an SQLite database backup.

    Checks:
    1. File exists and is non-empty.
    2. Opens cleanly with SQLite.
    3. PRAGMA integrity_check returns 'ok'.
    4. Expected tables are present.
    5. alembic_version table contains a valid recorded revision.

    Args:
        backup_file: Path to the SQLite backup file to verify.
        expected_tables: Optional set of required tables (defaults to DEFAULT_EXPECTED_TABLES).

    Returns:
        VerificationResult detailing validity, tables found, and any errors.
    """
    path = Path(backup_file).resolve()
    if expected_tables is None:
        expected_tables = DEFAULT_EXPECTED_TABLES

    if not path.is_file():
        return VerificationResult(
            is_valid=False,
            file_path=path,
            size_bytes=0,
            tables=[],
            error=f"Backup file does not exist or is not a file: {path}",
        )

    size = path.stat().st_size
    if size == 0:
        return VerificationResult(
            is_valid=False,
            file_path=path,
            size_bytes=0,
            tables=[],
            error="Backup file is 0 bytes (empty file).",
        )

    conn: Optional[sqlite3.Connection] = None
    cursor: Optional[sqlite3.Cursor] = None
    try:
        # Open in read-only mode to guarantee verification never alters the backup file
        conn = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=10.0)
        cursor = conn.cursor()

        # 1. Run SQLite integrity check
        cursor.execute("PRAGMA integrity_check;")
        rows = cursor.fetchall()
        if not rows or rows[0][0] != "ok":
            error_details = "; ".join(r[0] for r in rows) if rows else "Unknown corruption"
            return VerificationResult(
                is_valid=False,
                file_path=path,
                size_bytes=size,
                tables=[],
                error=f"SQLite integrity check failed: {error_details}",
            )

        # 2. Inspect table schema
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        tables_set = set(tables)

        missing_tables = expected_tables - tables_set
        if missing_tables:
            return VerificationResult(
                is_valid=False,
                file_path=path,
                size_bytes=size,
                tables=tables,
                error=f"Backup is missing required ChatSpic tables: {sorted(missing_tables)}",
            )

        # 3. Inspect Alembic migration version
        alembic_version: Optional[str] = None
        if "alembic_version" in tables_set:
            cursor.execute("SELECT version_num FROM alembic_version LIMIT 1;")
            v_row = cursor.fetchone()
            if v_row and v_row[0]:
                alembic_version = str(v_row[0]).strip()

        if not alembic_version:
            return VerificationResult(
                is_valid=False,
                file_path=path,
                size_bytes=size,
                tables=tables,
                alembic_version=None,
                error="Backup alembic_version table contains no recorded migration revision.",
            )

        return VerificationResult(
            is_valid=True,
            file_path=path,
            size_bytes=size,
            tables=sorted(tables),
            alembic_version=alembic_version,
            error=None,
        )

    except sqlite3.DatabaseError as exc:
        return VerificationResult(
            is_valid=False,
            file_path=path,
            size_bytes=size,
            tables=[],
            error=f"SQLite database error during verification: {exc}",
        )
    except Exception as exc:
        return VerificationResult(
            is_valid=False,
            file_path=path,
            size_bytes=size,
            tables=[],
            error=f"Unexpected error during verification: {exc}",
        )
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def create_backup(
    source_path: Optional[Union[str, Path]] = None,
    backup_dir: Optional[Union[str, Path]] = None,
    retention_count: Optional[int] = None,
    expected_tables: Optional[Set[str]] = None,
) -> BackupResult:
    """Create a verified SQLite database backup using sqlite3.Connection.backup().

    Ensures consistent point-in-time snapshot of the database while the application
    may be actively running, works with DELETE rollback journal mode, writes to a
    temporary file first, verifies integrity and schema before finalizing, and
    executes retention pruning on older verified backups.

    Args:
        source_path: Path to the source database file (defaults to settings.DATABASE_URL).
        backup_dir: Directory for storing backups (defaults to settings.BACKUP_DIR).
        retention_count: Number of verified backups to retain (defaults to settings.BACKUP_RETENTION_COUNT).
        expected_tables: Optional set of required tables for verification.

    Returns:
        BackupResult with details of the created backup and any pruned files.

    Raises:
        BackupSourceNotFoundError: If the source database does not exist.
        BackupVerificationError: If the created backup fails integrity checks.
        BackupError: If an unexpected error occurs during backup.
    """
    # 1. Resolve source database path
    resolved_src: Path
    if source_path is not None:
        resolved_src = Path(source_path).resolve()
    else:
        resolved_src = settings.get_sqlite_db_path()

    if not resolved_src.is_file():
        logger.error("Backup aborted: source database file '%s' does not exist", resolved_src)
        raise BackupSourceNotFoundError(f"Source database file not found: {resolved_src}")

    # 2. Resolve backup directory
    target_dir: Path
    if backup_dir is not None:
        target_dir = Path(backup_dir).resolve()
    else:
        target_dir = Path(settings.BACKUP_DIR).resolve()

    target_dir.mkdir(parents=True, exist_ok=True)

    # 3. Formulate unique timestamped filename and temporary staging path
    now_utc = datetime.now(timezone.utc)
    timestamp_str = now_utc.strftime("%Y%m%d_%H%M%S")
    base_filename = f"chat_backup_{timestamp_str}.db"
    final_backup_path = target_dir / base_filename

    # Handle collision if multiple backups happen in the same second
    counter = 1
    while final_backup_path.exists():
        final_backup_path = target_dir / f"chat_backup_{timestamp_str}_{counter}.db"
        counter += 1

    temp_backup_path = target_dir / f".tmp_{final_backup_path.name}_{uuid.uuid4().hex[:8]}.tmp"

    logger.info("Backup started: '%s' -> '%s'", resolved_src, final_backup_path)

    src_conn: Optional[sqlite3.Connection] = None
    dst_conn: Optional[sqlite3.Connection] = None

    try:
        # Open source with read lock using SQLite URI
        src_conn = sqlite3.connect(
            resolved_src.as_uri() + "?mode=ro",
            uri=True,
            timeout=30.0,
        )
        dst_conn = sqlite3.connect(str(temp_backup_path), timeout=30.0)

        # Execute safe online SQLite backup
        src_conn.backup(dst_conn)

        dst_conn.close()
        dst_conn = None
        src_conn.close()
        src_conn = None

        # 4. Verify the newly created temporary backup
        verification = verify_backup(temp_backup_path, expected_tables=expected_tables)
        if not verification.is_valid:
            temp_backup_path.unlink(missing_ok=True)
            logger.error("Backup verification failed: %s", verification.error)
            raise BackupVerificationError(
                f"Backup verification failed for '{final_backup_path.name}': {verification.error}"
            )

        # 5. Atomically promote temporary file to final backup filename
        temp_backup_path.replace(final_backup_path)
        size = final_backup_path.stat().st_size

        logger.info(
            "Backup successfully created and verified: '%s' (size: %d bytes, alembic_version: %s)",
            final_backup_path.name,
            size,
            verification.alembic_version,
        )

        # 6. Retention cleanup: prune older verified backups beyond retention count
        pruned = prune_backups(backup_dir=target_dir, retention_count=retention_count)

        return BackupResult(
            success=True,
            backup_path=final_backup_path,
            size_bytes=size,
            timestamp=now_utc,
            verification=verification,
            pruned_backups=pruned,
        )

    except Exception as exc:
        # Ensure temporary file is cleaned up on any failure
        temp_backup_path.unlink(missing_ok=True)
        if isinstance(exc, (BackupSourceNotFoundError, BackupVerificationError)):
            raise
        logger.error("Backup failed unexpectedly: %s", exc, exc_info=True)
        raise BackupError(f"Backup operation failed: {exc}") from exc
    finally:
        if dst_conn is not None:
            try:
                dst_conn.close()
            except Exception:
                pass
        if src_conn is not None:
            try:
                src_conn.close()
            except Exception:
                pass


def list_backups(
    backup_dir: Optional[Union[str, Path]] = None,
    expected_tables: Optional[Set[str]] = None,
) -> List[BackupInfo]:
    """Scan the backup directory and return metadata and verification status for all backups.

    Args:
        backup_dir: Directory to scan (defaults to settings.BACKUP_DIR).
        expected_tables: Optional required tables for verification.

    Returns:
        List of BackupInfo objects sorted newest to oldest.
    """
    target_dir: Path
    if backup_dir is not None:
        target_dir = Path(backup_dir).resolve()
    else:
        target_dir = Path(settings.BACKUP_DIR).resolve()

    if not target_dir.is_dir():
        return []

    results: List[BackupInfo] = []
    for entry in target_dir.iterdir():
        if entry.is_file() and entry.name.startswith("chat_backup_") and entry.suffix == ".db":
            stat = entry.stat()
            v_res = verify_backup(entry, expected_tables=expected_tables)
            mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
            results.append(
                BackupInfo(
                    filename=entry.name,
                    path=entry,
                    size_bytes=stat.st_size,
                    modified_time=mtime,
                    is_verified=v_res.is_valid,
                    verification_error=v_res.error,
                )
            )

    # Sort newest first based on modified_time
    results.sort(key=lambda b: b.modified_time, reverse=True)
    return results


def prune_backups(
    backup_dir: Optional[Union[str, Path]] = None,
    retention_count: Optional[int] = None,
) -> List[Path]:
    """Prune older verified backups while strictly preserving the newest verified backups.

    Safety rules:
    - Only deletes older backups that have passed verification.
    - If a backup file is unverified or corrupted, do NOT delete it automatically;
      preserve it for operator inspection.
    - Never delete the newest verified backup.
    - Never delete the live production database.

    Args:
        backup_dir: Directory containing backups (defaults to settings.BACKUP_DIR).
        retention_count: Number of verified backups to retain (defaults to settings.BACKUP_RETENTION_COUNT).

    Returns:
        List of Paths of deleted verified backup files.
    """
    target_dir: Path
    if backup_dir is not None:
        target_dir = Path(backup_dir).resolve()
    else:
        target_dir = Path(settings.BACKUP_DIR).resolve()

    if not target_dir.is_dir():
        return []

    limit: int
    if retention_count is not None:
        limit = max(1, retention_count)
    else:
        limit = max(1, settings.BACKUP_RETENTION_COUNT)

    all_backups = list_backups(target_dir)

    # Separate verified from unverified
    verified_backups = [b for b in all_backups if b.is_verified]
    unverified_backups = [b for b in all_backups if not b.is_verified]

    if unverified_backups:
        for ub in unverified_backups:
            logger.warning(
                "Retention cleanup skipped unverified backup '%s' (preserved for operator investigation): %s",
                ub.filename,
                ub.verification_error,
            )

    # If verified backups count <= retention limit, nothing to prune
    if len(verified_backups) <= limit:
        return []

    # Keep the first `limit` verified backups (newest), prune the rest
    to_prune = verified_backups[limit:]
    pruned_paths: List[Path] = []

    for item in to_prune:
        try:
            item.path.unlink(missing_ok=True)
            pruned_paths.append(item.path)
            logger.info("Retention cleanup removed older verified backup: '%s'", item.filename)
        except Exception as exc:
            logger.warning("Failed to remove older backup '%s': %s", item.filename, exc)

    return pruned_paths


def restore_backup(
    backup_file: Union[str, Path],
    target_path: Optional[Union[str, Path]] = None,
    backup_dir: Optional[Union[str, Path]] = None,
    expected_tables: Optional[Set[str]] = None,
    create_safety_backup: bool = True,
) -> RestoreResult:
    """Safely restore a database backup to the target database path.

    Safety workflow:
    1. Validate candidate backup file with integrity_check and schema verification.
       Abort immediately if invalid before touching target.
    2. If target database exists, create a verified pre-restore safety backup.
    3. Stage restore into a temporary file first and verify the staged copy.
    4. Atomically replace the target database file.
    5. If Windows file locking blocks replacement, fail clearly without corrupting
       the live database, leaving the target database and safety backup intact.
    6. Verify final target database integrity.

    Args:
        backup_file: Path to candidate backup file to restore.
        target_path: Destination database file path (defaults to settings.DATABASE_URL).
        backup_dir: Directory for saving safety backups (defaults to settings.BACKUP_DIR).
        expected_tables: Optional set of required tables.
        create_safety_backup: Whether to create a pre-restore safety snapshot (default: True).

    Returns:
        RestoreResult detailing restored path, source backup, and safety backup path.

    Raises:
        BackupVerificationError: If candidate backup is invalid.
        TargetDatabaseLockedError: If the target database is locked by a running process.
        RestoreError: If restore fails for another reason.
    """
    src_backup_path = Path(backup_file).resolve()

    # 1. Validate the source backup file first
    logger.info("Restore requested from backup: '%s'", src_backup_path)
    verification = verify_backup(src_backup_path, expected_tables=expected_tables)
    if not verification.is_valid:
        logger.error("Restore aborted: candidate backup '%s' failed verification: %s", src_backup_path, verification.error)
        raise BackupVerificationError(
            f"Cannot restore from invalid or corrupt backup '{src_backup_path.name}': {verification.error}"
        )

    # 2. Resolve target database path
    resolved_target: Path
    if target_path is not None:
        resolved_target = Path(target_path).resolve()
    else:
        resolved_target = settings.get_sqlite_db_path()

    target_dir = resolved_target.parent
    target_dir.mkdir(parents=True, exist_ok=True)

    # 3. Create pre-restore safety backup if target database exists
    safety_backup_path: Optional[Path] = None
    if create_safety_backup and resolved_target.is_file() and resolved_target.stat().st_size > 0:
        safety_dir: Path
        if backup_dir is not None:
            safety_dir = Path(backup_dir).resolve()
        else:
            safety_dir = Path(settings.BACKUP_DIR).resolve()
        safety_dir.mkdir(parents=True, exist_ok=True)

        now_utc = datetime.now(timezone.utc)
        safety_name = f"chat_pre_restore_safety_{now_utc.strftime('%Y%m%d_%H%M%S')}.db"
        safety_backup_path = safety_dir / safety_name

        logger.info("Creating pre-restore safety backup of '%s' at '%s'", resolved_target, safety_backup_path)
        t_conn: Optional[sqlite3.Connection] = None
        s_conn: Optional[sqlite3.Connection] = None
        try:
            t_conn = sqlite3.connect(resolved_target.as_uri() + "?mode=ro", uri=True, timeout=10.0)
            s_conn = sqlite3.connect(str(safety_backup_path), timeout=10.0)
            t_conn.backup(s_conn)
            s_conn.close()
            s_conn = None
            t_conn.close()
            t_conn = None

            # Verify safety backup
            s_verify = verify_backup(safety_backup_path, expected_tables=None)
            if not s_verify.is_valid:
                logger.warning("Pre-restore safety backup verification warning: %s", s_verify.error)
            else:
                logger.info("Pre-restore safety backup verified at '%s'", safety_backup_path)
        except Exception as exc:
            logger.error("Failed to create pre-restore safety backup: %s", exc)
            raise RestoreError(f"Could not create pre-restore safety backup: {exc}") from exc
        finally:
            if s_conn is not None:
                try:
                    s_conn.close()
                except Exception:
                    pass
            if t_conn is not None:
                try:
                    t_conn.close()
                except Exception:
                    pass

    # 4. Stage the restore in a temporary file in the target directory
    staging_path = target_dir / f".restore_staging_{uuid.uuid4().hex[:8]}.tmp"
    b_conn: Optional[sqlite3.Connection] = None
    stage_conn: Optional[sqlite3.Connection] = None
    try:
        b_conn = sqlite3.connect(src_backup_path.as_uri() + "?mode=ro", uri=True, timeout=10.0)
        stage_conn = sqlite3.connect(str(staging_path), timeout=10.0)
        b_conn.backup(stage_conn)
        stage_conn.close()
        stage_conn = None
        b_conn.close()
        b_conn = None

        # Verify the staged database
        stage_verify = verify_backup(staging_path, expected_tables=expected_tables)
        if not stage_verify.is_valid:
            staging_path.unlink(missing_ok=True)
            raise RestoreError(f"Staged restore database failed verification: {stage_verify.error}")

        # 5. Atomically replace target database with the validated staged database
        try:
            staging_path.replace(resolved_target)
        except PermissionError as exc:
            staging_path.unlink(missing_ok=True)
            safety_msg = f" (Pre-restore safety backup preserved at: '{safety_backup_path}')" if safety_backup_path else ""
            error_msg = (
                f"Target database '{resolved_target}' is locked by another process (e.g. running ChatSpic server). "
                f"You must stop the ChatSpic server before performing a database restore on Windows. "
                f"The target database has NOT been modified.{safety_msg}"
            )
            logger.error(error_msg)
            raise TargetDatabaseLockedError(error_msg) from exc

        # 6. Final verification of replaced target database
        final_target_verify = verify_backup(resolved_target, expected_tables=expected_tables)
        if not final_target_verify.is_valid:
            logger.error("Final restored database verification failed: %s", final_target_verify.error)
            raise RestoreError(
                f"Restored target database failed final verification: {final_target_verify.error}. "
                f"Safety backup available at: {safety_backup_path}"
            )

        logger.info(
            "Database restore completed successfully: '%s' restored from '%s' (tables: %d, alembic_version: %s)",
            resolved_target,
            src_backup_path.name,
            len(final_target_verify.tables),
            final_target_verify.alembic_version,
        )

        return RestoreResult(
            success=True,
            restored_path=resolved_target,
            backup_source=src_backup_path,
            safety_backup_path=safety_backup_path,
        )

    except Exception as exc:
        staging_path.unlink(missing_ok=True)
        if isinstance(exc, (BackupVerificationError, TargetDatabaseLockedError, RestoreError)):
            raise
        logger.error("Restore operation failed: %s", exc, exc_info=True)
        raise RestoreError(f"Restore operation failed: {exc}") from exc
    finally:
        if stage_conn is not None:
            try:
                stage_conn.close()
            except Exception:
                pass
        if b_conn is not None:
            try:
                b_conn.close()
            except Exception:
                pass
