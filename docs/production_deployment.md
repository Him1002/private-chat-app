# ChatSpic Production Deployment & Operations Runbook

This runbook describes the production configuration, initial deployment, update procedures, operational requirements, and security practices for **ChatSpic**.

---

## 1. Architecture & Scope

ChatSpic V1 is engineered for a lightweight, focused deployment profile:
- **Target Profile**: 2–5 users, single-instance on Windows or Linux.
- **Database Engine**: Local SQLite database with foreign keys enabled (`chat.db`).
- **Application Process**: Single Uvicorn worker (`--workers 1`, no `--reload`).
- **State Management**: In-process memory stores active WebSocket connection rooms (`rooms`), presence tracking (`online_users`), and rate limiting (`failed_login_limiter`, `registration_limiter`).
- **Schema Management**: Strictly managed out-of-band via Alembic migrations. The application never mutates or creates schema on startup (`create_all()` is forbidden).

> [!IMPORTANT]
> **Single Worker Process Requirement**:
> Production MUST run with a single Uvicorn worker (`--workers 1`). Do NOT increase the number of worker processes.
> 1. **WebSocket & Presence State**: WebSocket connections and active rooms are stored in Python process memory. Multiple workers would isolate users across different processes, breaking presence status and cross-tab/peer messaging.
> 2. **In-Memory Rate Limiting**: Brute-force login and registration throttling are enforced in-process. Splitting across multiple workers would divide and weaken rate-limiting windows.
> 3. **SQLite Concurrency**: SQLite employs file-level database locking. Multiple worker processes running concurrent writes under load can encounter file lock contention (`database is locked`).

---

## 2. Initial Setup & Installation

### Step 1: Clone Repository & Create Virtual Environment

Ensure Python 3.11+ is installed. Open PowerShell in the project directory:

```powershell
# Create dedicated virtual environment
python -m venv chatapp

# Activate the virtual environment
.\chatapp\Scripts\Activate.ps1
```

### Step 2: Install Runtime Dependencies

Install all pinned runtime dependencies from `requirements.txt` (includes FastAPI, Uvicorn, SQLAlchemy, Alembic, and security packages):

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Step 3: Configure Production Environment Variables

Copy `.env.example` to `.env`:

```powershell
Copy-Item .env.example .env
```

Edit `.env` and set the following production settings:

```dotenv
# 1. Environment mode
ENVIRONMENT=production

# 2. Secret Key (REQUIRED: >= 32 characters, cryptographically random)
# Generate using: python -c "import secrets; print(secrets.token_urlsafe(32))"
SECRET_KEY=replace-with-generated-cryptographic-32-char-secret

# 3. JWT Settings
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60

# 4. Database Connection (Persistent file-based SQLite URL)
DATABASE_URL=sqlite:///./chat.db

# 5. Storage Directories
UPLOADS_DIR=uploads
STATIC_DIR=static

# 6. Backup Directory & Retention
BACKUP_DIR=backups
BACKUP_RETENTION_COUNT=7

# 7. Allowed CORS Origins (EXPLICIT ORIGINS REQUIRED - Wildcard '*' is strictly forbidden)
ALLOWED_ORIGINS=http://localhost:8000,http://127.0.0.1:8000

# 8. Logging Verbosity (INFO avoids excessive debug noise while retaining audit trail)
LOG_LEVEL=INFO
```

> [!CAUTION]
> **Production Configuration Validation**:
> When `ENVIRONMENT=production` is set, ChatSpic fails fast during startup if:
> - `SECRET_KEY` is missing, shorter than 32 characters, or matches known insecure placeholders.
> - `ALLOWED_ORIGINS` contains a wildcard (`*`). Explicit origin URLs are mandatory.
> - `DATABASE_URL` is an in-memory database (`:memory:`).
> - `ALGORITHM` is set to `"none"`.

### Step 4: Verify Required Storage Directories

Ensure the configured `uploads`, `static`, and `backups` directories exist:

```powershell
if (!(Test-Path .\uploads)) { New-Item -ItemType Directory -Path .\uploads }
if (!(Test-Path .\backups)) { New-Item -ItemType Directory -Path .\backups }
```

---

## 3. Database Schema Initialization (Alembic)

Database schema is strictly managed via Alembic. ChatSpic intentionally does **not** call `Base.metadata.create_all()` on startup.

### Run Alembic Migrations

Execute the Alembic migration command using the project's virtual environment:

```powershell
# With virtual environment activated:
python -m alembic upgrade head
```

Or invoke directly via the virtualenv interpreter:

```powershell
.\chatapp\Scripts\python.exe -m alembic upgrade head
```

### Verify Current Migration State

Verify that the database has reached the current head revision:

```powershell
python -m alembic current
```

Expected output:
```text
INFO  [alembic.runtime.migration] Context impl SQLiteImpl.
INFO  [alembic.runtime.migration] Will assume non-transactional DDL.
a1b2c3d4e5f6 (head)
```

---

## 4. Production Server Startup

### Supported Production Startup Command

Run the application using Uvicorn with a single worker and no `--reload` mode:

```powershell
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --workers 1
```

Or use the provided Windows PowerShell startup script:

```powershell
.\start_production.ps1
```

### Key Startup Rules

1. **Do NOT pass `--reload`**: Development reload mode launches extra monitoring processes, consumes extra memory, and may restart unpredictably during file operations.
2. **Do NOT pass `--workers > 1`**: A single worker is mandatory for in-process WebSocket connection tracking and SQLite concurrency.
3. **Listen Address**:
   - Use `--host 127.0.0.1` if ChatSpic should only be accessible from the local host.
   - Use `--host 0.0.0.0` if ChatSpic should be accessible across the local network to authenticated users.

---

## 5. Controlled Maintenance & Deployment Update Runbook

Because ChatSpic uses a single-worker architecture with SQLite and in-process WebSocket state, updates are executed as **controlled maintenance deployments with brief downtime**.

### Deployment Update Sequence

Follow this step-by-step procedure during maintenance windows:

```
[1. Stop Application]
       │
       ▼
[2. Create & Verify Backup]
       │
       ▼
[3. Update Code & Dependencies]
       │
       ▼
[4. Apply Alembic Migrations (if any)]
       │
       ▼
[5. Start Application]
       │
       ▼
[6. Verify Health & Functionality]
```

#### Step 1: Stop the Running Server
Locate the running server terminal or process and stop Uvicorn safely using `Ctrl + C` (or kill the process).
Confirm no Python processes hold locks on `chat.db`.

#### Step 2: Create and Verify Database Backup
Before making code or schema changes, create a verified point-in-time snapshot:

```powershell
python -m backend.tools.backup create
```

Verify that the backup was created and validated:

```powershell
python -m backend.tools.backup list
```

#### Step 3: Update Application Code & Dependencies
Pull latest changes or unpack the release package:

```powershell
# Update codebase
git pull origin develop

# Install updated dependencies if requirements changed
python -m pip install -r requirements.txt
```

#### Step 4: Apply Database Migrations
If the release includes new database migrations, apply them:

```powershell
python -m alembic upgrade head
```

Verify the revision:

```powershell
python -m alembic current
```

#### Step 5: Start the Server
Start the production server:

```powershell
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --workers 1
```

#### Step 6: Health & Smoke Verification
Verify server readiness via the health check endpoint:

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/health" -Method Get
```

Expected response:
```json
{"status": "ok"}
```

---

## 6. Backup & Disaster Recovery Operations

Refer to [backup_recovery.md](file:///d:/ChatApp2/docs/backup_recovery.md) for full operational recovery details. Key CLI commands:

- **Create a Backup**:
  ```powershell
  python -m backend.tools.backup create
  ```
- **List Backups**:
  ```powershell
  python -m backend.tools.backup list
  ```
- **Verify a Backup**:
  ```powershell
  python -m backend.tools.backup verify backups/chat_backup_YYYYMMDD_HHMMSS.db
  ```
- **Restore from Backup** (Requires server to be stopped):
  ```powershell
  python -m backend.tools.backup restore backups/chat_backup_YYYYMMDD_HHMMSS.db
  ```

### Windows Task Scheduler (Recommended Periodic Backups)

To automate daily backups without introducing background scheduler dependencies in Python, use Windows Task Scheduler:

1. Open **Task Scheduler** on Windows (`taskschd.msc`).
2. Create a basic task named `ChatSpic Database Backup`.
3. Set trigger to daily (e.g. 02:00 AM).
4. Set Action to **Start a program**:
   - **Program/script**: `powershell.exe`
   - **Arguments**: `-ExecutionPolicy Bypass -File .\start_backup.ps1` (or `-Command ".\chatapp\Scripts\python.exe -m backend.tools.backup create"`)
   - **Start in**: `D:\ChatApp2`

---

## 7. Security Hardening & Operational Policies

1. **Secrets Protection**:
   - Never commit `.env` or production secrets to Git.
   - Always generate random keys with `secrets.token_urlsafe(32)`.
   - Settings automatically masks `SECRET_KEY` in `repr` and `str` output.
2. **CORS Restrictions**:
   - Production forbids wildcard `*` origins. Explicit origins must be defined in `ALLOWED_ORIGINS`.
3. **HTTP Security Headers**:
   - Starlette middleware automatically attaches `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy: strict-origin-when-cross-origin`.
4. **File Upload Hardening**:
   - Uploads are validated against magic byte allowlists (JPEG, PNG, GIF, WebP).
   - Maximum upload file size is capped at 5 MB.
   - Preserves UUID-based filename generation to prevent directory traversal or name collisions.
5. **Centralized Error Handling**:
   - All unhandled exceptions (500) log full stack traces server-side while returning generic `{"detail": "Internal server error"}` to clients.
   - Database queries, filesystem paths, and internal stack traces are never leaked in client responses.
6. **Logging Redaction**:
   - Passwords, hashes, JWTs, and Authorization Bearer tokens are automatically redacted by `SensitiveDataFilter`.
   - Production log level is set to `INFO`.
