# ChatSpic V1.0.0 Release Baseline

## 1. Release Identity
- **Product**: ChatSpic
- **Release**: V1.0.0
- **Release Tag**: `v1.0.0`
- **Commit Baseline**: `a8b2beb60eb95577b1542d82b9f88402e4e4582c` (`a8b2beb`)
- **Branch Baseline**: `develop`
- **Release State**: V1 complete / frozen baseline
- **Audit Status**: Passed the final Sprint 5 Release Audit (S5-T11) with status **V1 READY**.

---

## 2. V1 Scope
The V1.0.0 release provides a self-hosted, secure one-to-one messaging platform. Implemented capabilities include:

### Core messaging
- **One-to-one conversations**: Direct real-time communication between mutual friends.
- **Message timestamps**: UTC ISO-8601 timestamps stored in SQLite and formatted into localized client representations.
- **Sent / delivered / read status**: Message lifecycle status indicators (single check `✓` sent, double check `✓✓` delivered/read).
- **Message editing**: Inline composer editing for existing messages with `edited_at` tracking and visual `(edited)` indicator.
- **Soft deletion**: Message deletion via `is_deleted` flag, replacing message body with *"This message was deleted"* while preserving conversation chronology.
- **Conversation-specific search**: Filter and search messages within an active conversation with search term matching and navigation.

### Advanced messaging
- **Emoji reactions**: 10 standard emoji reactions per message with unique user-reaction constraints and realtime socket broadcast updates.
- **Reply to messages**: Quoted reply threading referencing parent messages, including graceful handling for deleted parent messages.

### User profile
- **Display name**: Customizable user display name with automatic fallback to username across views.
- **About/bio**: User biography and status text (length-capped, persisted to profile).
- **Profile picture**: Custom avatar upload support with validation and default fallback avatars.

### Presence / realtime
- **Online/offline presence**: Instant socket-driven presence tracking supplemented by client polling fallback.
- **Last seen**: Precise timestamp recording on user disconnect and activity with relative time rendering.
- **Typing indicator**: Real-time typing signals with automatic 3-second silence timeout.
- **WebSocket reconnect behavior**: Automatic client reconnection with exponential backoff on unexpected disconnection.
- **Realtime messaging**: Low-latency bidirectional WebSocket communication for messages, status receipts, reactions, and typing indicators.

### Supporting functionality
- **Authentication**: Registration and login with JWT access tokens and password hashing.
- **Friends/friend requests**: Mutual friend request workflow (send, accept, decline, list) gating conversation access.
- **Conversation access control**: Strict server-side verification ensuring only mutual friends can access conversation history and exchange messages.
- **Secure image/media uploads**: Authenticated image upload pipeline with magic-byte verification, file-size limits, and extension whitelisting.
- **Persistent message history**: Full chat history persistence in SQLite loaded sequentially on room join.
- **Responsive/mobile UI**: Clean, mobile-friendly interface with sidebar navigation, active conversation view, and touch-compatible controls.

For foundational architectural details, see [docs/system_blueprint.md](file:///d:/ChatApp2/docs/system_blueprint.md).

---

## 3. Security Baseline
ChatSpic V1 incorporates comprehensive security controls established and audited during Sprint 5:

| Security Domain | Implementation Details |
| :--- | :--- |
| **Secrets & Configuration** | Environment-driven configuration via `.env` with validated settings schema (`backend.core.config`). |
| **Production SECRET_KEY** | Strict production validator requiring cryptographically secure, random keys (minimum 32 characters), rejecting default placeholders. |
| **Password Policy** | Enforced length bounds for new passwords (minimum 8 UTF-8 bytes, maximum 72 UTF-8 bytes) without mandatory composition rules, while existing legacy/weak passwords remain valid for backward compatibility. |
| **Rate Limiting** | In-memory sliding-window throttling on `/login` and `/register` to mitigate brute-force and credential stuffing attempts. |
| **JWT Authentication** | Signed HMAC-SHA256 bearer tokens with expiration enforcement, validated on HTTP endpoints and WebSocket connections. |
| **WebSocket Pre-Accept Auth** | Token validation occurs prior to `websocket.accept()`, rejecting missing or invalid authentication before the connection is established. |
| **WebSocket Validation & Cleanup** | Strict payload schema validation, graceful handling of malformed JSON without disconnects, and cleanup of dead connections and presence state. |
| **Stored XSS Protection** | Strict HTML escaping and sanitization on all message contents, user profile bios, and display names across rendering layers. |
| **Media URL Sanitization** | Strict validation of upload URLs against allowed schemes and formats, preventing `javascript:` or unsafe URI injection. |
| **Upload Validation** | Multi-layer file inspection checking magic bytes (PNG, JPEG, GIF, WEBP), file size thresholds, and safe filename generation. |
| **HTTP Security Headers** | Automated injection of defensive HTTP headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, `Referrer-Policy: strict-origin-when-cross-origin`). |
| **CORS Configuration** | Restricted cross-origin resource sharing; wildcard `*` strictly disallowed in production environments. |
| **Centralized Error Handling** | Structured, safe error handlers that mask internal tracebacks and unhandled exceptions from API responses. |
| **Sensitive Data Logging Protection** | Redaction filters in `backend.core.logging_config` preventing credential, secret, and sensitive token leakage into log files. |
| **WebSocket Query-String Redaction** | Uvicorn access logger filters ensuring JWT query tokens in `/ws?token=...` are masked as `/ws?token=[REDACTED_TOKEN]`. |
| **SQLite Foreign Key Enforcement** | `PRAGMA foreign_keys = ON;` enforced on every database connection to maintain referential integrity. |

---

## 4. Database & Migration Baseline
The database layer adheres to strict lifecycle and migration practices:
- **Database Engine**: SQLite 3 file-based database (`chat.db`) using rollback journal mode (`DELETE`).
- **Migration Mechanism**: Schema changes are managed exclusively via Alembic (`alembic/`). Runtime `Base.metadata.create_all()` is forbidden on server startup.
- **Migration Head**: Verified at revision `a1b2c3d4e5f6` (`add_reply_to_message_id_foreign_key`).
- **Referential Integrity**: Self-referential message reply relationships enforced with foreign key constraint (`FOREIGN KEY (reply_to_message_id) REFERENCES messages(id) ON DELETE SET NULL`).
- **Foreign Key Enforcement**: Explicit connection listener executes `PRAGMA foreign_keys = ON` on every SQLite connection.
- **Schema Lifecycle**: Application startup strictly verifies database connectivity without altering or generating tables.
- **Backup & Recovery Tooling**: Dedicated CLI utility (`python -m backend.tools.backup`) utilizing SQLite's Online Backup API for hot, verified snapshots, retention management, and safe restore with pre-restore safety copies.

For complete database operations and restore runbooks, see [docs/backup_recovery.md](file:///d:/ChatApp2/docs/backup_recovery.md).

---

## 5. Deployment / Operations Baseline
The supported operational architecture is documented in [docs/production_deployment.md](file:///d:/ChatApp2/docs/production_deployment.md):

- **Supported Architecture**: Single-instance deployment profile designed for 2–5 users.
- **Application Server**: Single Uvicorn worker (`python -m uvicorn main:app --workers 1`, no `--reload`).
- **Operating Environment**: Windows-oriented production startup script (`start_production.ps1`) and multiplatform Python execution.
- **State Model**: In-process memory stores active WebSocket rooms, presence sets (`online_users`), and sliding-window rate limit counters.
- **Architectural Constraints**: Multi-worker or distributed deployments are outside the V1 architecture because in-process WebSocket connection state, presence tracking, and rate limit windows are not shared across processes.
- **Health Monitoring**: Dedicated `/health` endpoint returning system readiness and status.
- **Production Configuration**: Enforces production environment variables (32+ character `SECRET_KEY`, non-memory `DATABASE_URL`, explicit `ALLOWED_ORIGINS`).
- **Maintenance Model**: Deployments and updates follow a controlled maintenance window procedure with brief planned downtime. The V1 deployment model is not zero-downtime.
- **Backup Integration**: Pre-deployment backup verification integrated into operational workflows.

---

## 6. V1 Validation
ChatSpic V1.0.0 successfully completed the comprehensive S5-T11 V1 Release Audit with zero blocking defects:

- **Automated Test Suite**:
  - Total Tests: **369**
  - Failures: **0**
  - Errors: **0**
  - Skips: **0**
  - Execution Command: `.\chatapp\Scripts\python.exe -m unittest discover tests`
- **Release Audit Assessment**: **V1 READY** (all P0 and P1 criteria satisfied).
- **Live HTTP & WebSocket Smoke Validation**: Verified health endpoint (`GET /health`), web interface asset delivery (`GET /`), authentication workflow, live WebSocket bidirectional message and typing dispatch, malformed payload resilience, and clean disconnection presence handling.
- **Access Log Credential Protection**: Verified that live WebSocket query-string authentication tokens are masked as `[REDACTED_TOKEN]` in Uvicorn access logs.
- **Production Data Integrity**: Production database state was preserved intact with no test corruption or unwanted modifications during audit execution.

---

## 7. Known Non-Goals / Deferred Items
The following capabilities were intentionally excluded from V1 scope and remain deferred to future milestones:

| Feature Area | V1 Status | Description |
| :--- | :---: | :--- |
| **Group Chat** | Deferred | V1 is strictly focused on one-to-one direct messaging between mutual friends. |
| **End-to-End Encryption (E2EE)** | Deferred | V1 relies on transport-layer encryption (TLS/HTTPS/WSS); client-side cryptographic ratchet is deferred. |
| **Voice / Video Calling** | Deferred | WebRTC audio/video signaling and peer media streams are outside V1 scope. |
| **Push Notifications** | Deferred | Mobile/Web push notification services (APNs, FCM, WebPush) are deferred. |
| **AI Features** | Deferred | AI summarization, smart replies, or bots are outside V1 scope. |
| **Message Forwarding** | Deferred | Forwarding messages between conversations is deferred. |
| **Pinned Messages** | Deferred | Chat header message pinning is deferred. |
| **Starred / Saved Messages** | Deferred | Personal message bookmarking and star lists are deferred. |
| **Wallpaper** | Deferred | Custom chat background wallpaper customization is deferred. |
| **Custom Themes** | Deferred | User-selectable UI themes beyond the core design system are deferred. |
| **Stories / Status Features** | Deferred | Ephemeral status posts or media stories are deferred. |
| **Multi-Device Synchronization** | Deferred | Distributed session synchronization across simultaneous client devices is deferred. |

These items represent deliberate scope boundaries established for the V1 release rather than defects or incomplete implementations.

---

## 8. Known Operational Notes
- **Single-Worker Requirement**: Uvicorn must be run with `--workers 1`. Distributing across multiple worker processes without external pub/sub infrastructure (such as Redis) breaks presence tracking, real-time message delivery, and in-memory rate limiting.
- **Dependency Deprecation Notice**: Starlette logs a `DeprecationWarning` regarding `HTTP_413_REQUEST_ENTITY_TOO_LARGE` in favor of `HTTP_413_CONTENT_TOO_LARGE`. This warning is benign and does not impact upload limits or runtime stability.
- **Windows File Locking**: When executing database restores or file-level backups on Windows, active Uvicorn processes maintain file locks on `chat.db`. Restores must be performed with the application stopped as detailed in [docs/backup_recovery.md](file:///d:/ChatApp2/docs/backup_recovery.md).

---

## 9. V1 Freeze Statement
ChatSpic V1.0.0 is the frozen, security-audited and regression-tested baseline. Future product development should proceed as V2 work from this release baseline rather than modifying the definition of V1.
