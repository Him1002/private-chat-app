# ChatSpic Backup & Recovery Runbook (S5-T08)

This operational guide describes the backup, verification, retention, and disaster recovery procedures for the ChatSpic SQLite database.

---

## 1. Overview & Architecture

- **Database Engine**: SQLite 3 using rollback journal mode (`journal_mode=DELETE`).
- **Backup Mechanism**: Uses Python standard library and SQLite's Online Backup API (`sqlite3.Connection.backup()`). This creates consistent point-in-time snapshots while the application may be active without taking the database offline and without corrupting active read/write transactions.
- **CLI Utility**: Executable with zero external dependencies via:
  ```powershell
  python -m backend.tools.backup <command> [options]
  ```
- **Logging**: All backup and recovery events are recorded using the centralized application logging system (`backend.core.logging_config`) with sensitive data redaction and zero leakage of database contents.

---

## 2. Configuration Settings

Backup and retention settings can be configured via environment variables or in `.env`:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `DATABASE_URL` | `sqlite:///./chat.db` | SQLAlchemy SQLite connection URL |
| `BACKUP_DIR` | `backups` | Directory where database backup files are stored |
| `BACKUP_RETENTION_COUNT` | `7` | Number of verified backups to retain during retention pruning |

---

## 3. Backup Operations

### 3.1 Creating a Backup

To create a new timestamped, verified backup:

```powershell
python -m backend.tools.backup create
```

**Options**:
- `--db-path <path>`: Override the source database file (default: resolved from `DATABASE_URL`).
- `--backup-dir <dir>`: Override the backup storage directory (default: `backups`).
- `--retention <N>`: Override retention limit for this run (default: `7`).

**Backup Lifecycle**:
1. Connects to source database with a shared read lock via SQLite Online Backup API.
2. Writes the snapshot initially to a hidden temporary file (`.tmp_chat_backup_*.tmp`).
3. Executes automated verification (`PRAGMA integrity_check`, schema table presence, and Alembic version check).
4. Atomically renames the validated temporary file to its final timestamped filename: `chat_backup_YYYYMMDD_HHMMSS.db`.
5. Executes retention pruning to remove older verified backups beyond the configured retention count.

### 3.2 Listing Backups

To inspect all backups and their verification status:

```powershell
python -m backend.tools.backup list
```

Example output:
```text
================================================================================
CHATSPIC BACKUPS DIRECTORY: D:\ChatApp2\backups
================================================================================
Filename                            Size (bytes)   Modified (UTC)       Status    
--------------------------------------------------------------------------------
chat_backup_20260913_140000.db      176,128        2026-09-13 14:00:00  VERIFIED  
chat_backup_20260913_130000.db      172,032        2026-09-13 13:00:00  VERIFIED  
================================================================================
Total backups: 2 (2 verified, 0 invalid/unverified)
================================================================================
```

### 3.3 Verifying a Backup

To verify an existing backup file before considering it for restoration:

```powershell
python -m backend.tools.backup verify backups/chat_backup_20260913_140000.db
```

**Verification Criteria**:
- File exists and is non-empty (> 0 bytes).
- SQLite can open the file cleanly.
- `PRAGMA integrity_check;` returns `ok`.
- Required ChatSpic tables are present: `users`, `friends`, `messages`, `message_reactions`, `alembic_version`.
- `alembic_version` contains a valid recorded migration revision.

> [!NOTE]
> **Future Schema Compatibility**:
> When future Alembic migrations introduce new persistent application tables, update `DEFAULT_EXPECTED_TABLES` in `backend/services/backup_service.py` to ensure new tables are incorporated into backup verification checks.

### 3.4 Retention Policy

- Retention pruning runs automatically after a new backup is successfully created and verified.
- Retention keeps the newest **verified** backups up to `BACKUP_RETENTION_COUNT` (default: 7).
- **Safety Rules**:
  - The newest verified backup is **never** deleted.
  - The live production database is **never** touched by retention.
  - If an unverified or corrupted backup is encountered in the backup directory, it is **not** deleted automatically during retention cleanup; it is preserved for operator investigation.

---

## 4. Disaster Recovery & Restore Runbook

> [!WARNING]
> **Data Rollback Warning**:
> Restoring a previous backup will replace the live database state. Any user accounts, passwords, messages, reactions, friendships, or profile updates created *after* the backup timestamp will be rolled back to the backup's point in time.

### Step 1: Stop ChatSpic (Windows File Locking)

On Windows operating systems, running Python processes (such as Uvicorn or background tasks) maintain exclusive sharing locks on open SQLite database files.

1. Locate the running server terminal or process.
2. Stop the server safely using `Ctrl + C` (or terminate the Uvicorn process).
3. Confirm no active Python processes are holding locks on `chat.db`.

### Step 2: Select and Verify the Backup Candidate

List and inspect available backups:

```powershell
python -m backend.tools.backup list
```

Verify the candidate backup file to guarantee it is intact:

```powershell
python -m backend.tools.backup verify backups/chat_backup_20260913_140000.db
```

### Step 3: Execute Restore

Run the restore command with interactive confirmation:

```powershell
python -m backend.tools.backup restore backups/chat_backup_20260913_140000.db
```

Or for automated/scripted workflows:

```powershell
python -m backend.tools.backup restore backups/chat_backup_20260913_140000.db --yes
```

**Restore Safety Steps**:
1. **Source Pre-Check**: Validates the candidate backup integrity before touching the live database.
2. **Pre-Restore Safety Snapshot**: Automatically creates a timestamped safety backup of the existing live database (`chat_pre_restore_safety_YYYYMMDD_HHMMSS.db`) before modifying anything.
3. **Staging**: Restores the database into a temporary staging file first and verifies its integrity.
4. **Atomic Replacement**: Atomically replaces `chat.db` with the validated staging file.
5. **Lock Handling**: If a running server locks the database file, the restore aborts cleanly, leaving the live database untouched and preserving the pre-restore safety snapshot.
6. **Post-Restore Validation**: Runs a final SQLite integrity and schema check on the live database.

### Step 4: Check Alembic Migration Status

After restoring the database, verify that the restored database schema aligns with the current application code:

```powershell
python -m alembic current
```

- If the restored database version matches application head (e.g. `a1b2c3d4e5f6`), proceed to Step 5.
- If the restored database was backed up from an older application version, review pending migrations:
  ```powershell
  python -m alembic upgrade head
  ```
  *(Note: Restoring does NOT run destructive or automatic migrations).*

### Step 5: Restart ChatSpic

Restart the ChatSpic server:

```powershell
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```
