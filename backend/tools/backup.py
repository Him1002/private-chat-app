"""
ChatSpic SQLite Backup and Recovery CLI (S5-T08).

Provides operator commands for database backup creation, verification,
retention listing, and safe database restoration.

Usage:
    python -m backend.tools.backup create [--db-path PATH] [--backup-dir DIR] [--retention N]
    python -m backend.tools.backup list [--backup-dir DIR]
    python -m backend.tools.backup verify <backup_file>
    python -m backend.tools.backup restore <backup_file> [--target-db PATH] [--yes]
"""
import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

from backend.core.config import settings
from backend.core.logging_config import setup_logging
from backend.services.backup_service import (
    create_backup,
    list_backups,
    restore_backup,
    verify_backup,
    BackupError,
    TargetDatabaseLockedError,
)


def cmd_create(args: argparse.Namespace) -> int:
    """Execute backup creation command."""
    try:
        result = create_backup(
            source_path=args.db_path,
            backup_dir=args.backup_dir,
            retention_count=args.retention,
        )
        print("=" * 60)
        print("BACKUP CREATION SUCCESSFUL")
        print("=" * 60)
        print(f"Backup File:     {result.backup_path}")
        print(f"File Size:       {result.size_bytes:,} bytes")
        print(f"Timestamp (UTC): {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Alembic Version: {result.verification.alembic_version or 'N/A'}")
        print(f"Verified Tables: {len(result.verification.tables)} tables ({', '.join(result.verification.tables)})")
        if result.pruned_backups:
            print(f"Pruned Backups:  {len(result.pruned_backups)} older backup(s) removed")
            for p in result.pruned_backups:
                print(f"                 - {p.name}")
        else:
            print("Pruned Backups:  None")
        print("=" * 60)
        return 0
    except BackupError as exc:
        print(f"ERROR: Backup failed: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"UNEXPECTED ERROR: Backup failed: {exc}", file=sys.stderr)
        return 1


def cmd_list(args: argparse.Namespace) -> int:
    """Execute backup listing command."""
    backups = list_backups(backup_dir=args.backup_dir)
    target_dir = Path(args.backup_dir).resolve() if args.backup_dir else Path(settings.BACKUP_DIR).resolve()

    print("=" * 80)
    print(f"CHATSPIC BACKUPS DIRECTORY: {target_dir}")
    print("=" * 80)
    if not backups:
        print("No backup files found.")
        print("=" * 80)
        return 0

    header = f"{'Filename':<35} {'Size (bytes)':<14} {'Modified (UTC)':<20} {'Status':<10}"
    print(header)
    print("-" * 80)
    for b in backups:
        status = "VERIFIED" if b.is_verified else "INVALID"
        mod_str = b.modified_time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"{b.filename:<35} {b.size_bytes:<14} {mod_str:<20} {status:<10}")
        if not b.is_verified and b.verification_error:
            print(f"  └─ Error: {b.verification_error}")

    verified_count = sum(1 for b in backups if b.is_verified)
    print("=" * 80)
    print(f"Total backups: {len(backups)} ({verified_count} verified, {len(backups) - verified_count} invalid/unverified)")
    print("=" * 80)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Execute backup verification command."""
    backup_file = Path(args.backup_file)
    print("=" * 60)
    print(f"VERIFYING BACKUP: {backup_file}")
    print("=" * 60)

    result = verify_backup(backup_file)
    if result.is_valid:
        print("STATUS:          PASSED (VALID)")
        print(f"File Size:       {result.size_bytes:,} bytes")
        print(f"Alembic Version: {result.alembic_version or 'N/A'}")
        print(f"Verified Tables: {len(result.tables)} tables")
        for tbl in result.tables:
            print(f"                 - {tbl}")
        print("=" * 60)
        return 0
    else:
        print("STATUS:          FAILED (INVALID)")
        print(f"Error Details:   {result.error}")
        print("=" * 60)
        return 1


def cmd_restore(args: argparse.Namespace) -> int:
    """Execute backup restoration command."""
    backup_file = Path(args.backup_file).resolve()
    target_db = Path(args.target_db).resolve() if args.target_db else settings.get_sqlite_db_path()

    print("=" * 70)
    print("CHATSPIC DATABASE RESTORE")
    print("=" * 70)
    print(f"Source Backup:   {backup_file}")
    print(f"Target Database: {target_db}")
    print("WARNING: Restoring will overwrite the current live database state.")
    print("         All messages, friendships, and accounts created since this")
    print("         backup was taken will be rolled back to the backup's point in time.")
    print("=" * 70)

    if not args.yes:
        try:
            confirm = input("Are you sure you want to proceed with restore? Type 'yes' to confirm: ")
            if confirm.strip().lower() != "yes":
                print("Restore cancelled by operator.")
                return 1
        except (KeyboardInterrupt, EOFError):
            print("\nRestore cancelled by operator.")
            return 1

    try:
        result = restore_backup(
            backup_file=backup_file,
            target_path=target_db,
            backup_dir=args.backup_dir,
            create_safety_backup=True,
        )
        print("=" * 70)
        print("RESTORE SUCCESSFUL")
        print("=" * 70)
        print(f"Restored Target: {result.restored_path}")
        print(f"Restored From:   {result.backup_source.name}")
        if result.safety_backup_path:
            print(f"Pre-Restore Safety Snapshot: {result.safety_backup_path}")
        print("Integrity check and schema validation passed on restored database.")
        print("=" * 70)
        return 0
    except TargetDatabaseLockedError as exc:
        print("\n" + "!" * 70, file=sys.stderr)
        print("RESTORE BLOCKED - DATABASE FILE LOCKED", file=sys.stderr)
        print("!" * 70, file=sys.stderr)
        print(f"{exc}", file=sys.stderr)
        print("\nPlease stop the ChatSpic server process, then re-run the restore command.", file=sys.stderr)
        print("!" * 70, file=sys.stderr)
        return 1
    except BackupError as exc:
        print(f"\nERROR: Restore failed: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"\nUNEXPECTED ERROR: Restore failed: {exc}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="python -m backend.tools.backup",
        description="ChatSpic SQLite Backup and Recovery Utility",
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Backup operation")

    # Command: create
    parser_create = subparsers.add_parser("create", help="Create a new verified timestamped backup")
    parser_create.add_argument("--db-path", type=str, default=None, help="Source database file (defaults to configured DATABASE_URL)")
    parser_create.add_argument("--backup-dir", type=str, default=None, help="Directory to save backup (defaults to configured BACKUP_DIR)")
    parser_create.add_argument("--retention", type=int, default=None, help="Number of verified backups to retain (defaults to BACKUP_RETENTION_COUNT)")
    parser_create.set_defaults(func=cmd_create)

    # Command: list
    parser_list = subparsers.add_parser("list", help="List all backups in backup directory")
    parser_list.add_argument("--backup-dir", type=str, default=None, help="Directory containing backups (defaults to configured BACKUP_DIR)")
    parser_list.set_defaults(func=cmd_list)

    # Command: verify
    parser_verify = subparsers.add_parser("verify", help="Verify integrity and schema of a backup file")
    parser_verify.add_argument("backup_file", type=str, help="Path to backup file to verify")
    parser_verify.set_defaults(func=cmd_verify)

    # Command: restore
    parser_restore = subparsers.add_parser("restore", help="Safely restore database from a verified backup")
    parser_restore.add_argument("backup_file", type=str, help="Path to backup file to restore from")
    parser_restore.add_argument("--target-db", type=str, default=None, help="Target database path (defaults to configured DATABASE_URL)")
    parser_restore.add_argument("--backup-dir", type=str, default=None, help="Directory to save pre-restore safety backup")
    parser_restore.add_argument("-y", "--yes", action="store_true", help="Skip interactive confirmation prompt")
    parser_restore.set_defaults(func=cmd_restore)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Main CLI entrypoint."""
    setup_logging()
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
