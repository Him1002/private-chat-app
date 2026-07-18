# System Blueprint

## 1) Current Architecture

### Backend structure
- Framework: FastAPI (`main.py`).
- Routing split by domain under `backend/api/`:
  - `auth.py` (login/register/me)
  - `friends.py` (search, friend requests, friend list)
  - `chat.py` (conversation list, history, send, read marker, delete)
  - `upload.py` (file upload + uploads static mount)
- Business logic in `backend/services/`:
  - `friend_service.py`
  - `chat_service.py`
  - `upload_service.py`
- Core/shared modules:
  - `backend/core/security.py` (JWT, password hashing, auth dependencies)
  - `backend/core/config.py` (secret/jwt/static/upload settings)
- Realtime handling in `backend/realtime/websocket.py`.

### Frontend structure
- Entry page: `static/index.html`.
- JavaScript modules under `static/js/`:
  - `core.js` (auth mode toggle + login/logout orchestration)
  - `auth.js` (currently mostly state placeholders)
  - `sidebar.js` (tabs, friend/request/search rendering)
  - `websocket.js` (WS lifecycle, reconnect, inbound event handling)
  - `chat.js` (chat open/send/render + typing signal)
  - `upload.js` (image upload then chat send)
  - `utils.js` (toast, last seen formatting, enter key handling)
- CSS split under `static/css/` (`variables`, `base`, `layout`, `components`).

### Database
- Engine/session in `backend/db/database.py` using SQLite (`sqlite:///./chat.db`).
- ORM models in `backend/db/models.py`:
  - `users`: id, username, password_hash, last_seen
  - `friends`: id, user_id, friend_id, status
  - `messages`: id, sender_id, receiver_id, content, image_url, timestamp, is_read, read_at, edited_at, is_deleted, deleted_at, reply_to_message_id
- Migrations managed by Alembic (`alembic/`), current revision file:
  - `89507b65cda7_message_schema_foundation.py`

### WebSocket architecture
- Single WS endpoint: `/ws?token=<jwt>`.
- JWT verified server-side before participation.
- In-memory connection state:
  - `online_users` map for presence count per user id.
  - `rooms` map for active DM room socket members.
- Room naming strategy: deterministic DM room id from two usernames.
- Chat history replay is sent on `join`.
- Live messages are persisted then broadcast to room participants.

---

## 2) Database Roadmap

### Existing schema (current)
- `users`
  - identity/auth: `id`, `username`, `password_hash`
  - presence baseline: `last_seen`
- `friends`
  - relationship graph: `user_id`, `friend_id`, `status`
- `messages`
  - content: `content`, `image_url`
  - timeline: `timestamp`
  - read/edit/delete fields already present: `is_read`, `read_at`, `edited_at`, `is_deleted`, `deleted_at`
  - reply foundation field present: `reply_to_message_id`

### Future schema additions (planned, no model changes in this task)

#### User Profile
- Add to `users`:
  - `display_name` (nullable initially)
  - `about` (nullable, capped text)
  - `profile_picture_url` (nullable)
  - `wallpaper_url` (nullable, optional per-user UI preference)
  - `updated_at` (optional audit)

#### Message Reactions
- New table: `message_reactions`
  - `id` (PK)
  - `message_id` (FK -> messages.id)
  - `user_id` (FK -> users.id)
  - `reaction` (emoji/code)
  - `created_at`
- Constraint: unique (`message_id`, `user_id`, `reaction`) to prevent duplicate same reaction by same user.

#### Reply support (future completion)
- Existing `reply_to_message_id` can be fully activated by:
  - adding/ensuring FK constraint in migration
  - optional index on `reply_to_message_id`
  - optional denormalized `reply_preview` strategy kept at service/API layer (no hard DB requirement)

#### Other planned features
- Read receipts scaling:
  - current per-message flags may remain for 1:1 chat
  - optional future `message_receipts` table if multi-device/group semantics are needed
- Search performance:
  - indexes on `messages(sender_id, receiver_id, timestamp)`
  - optional FTS virtual table for message content search

---

## 3) REST API Roadmap

### Existing endpoints

#### Auth
- `POST /login`
- `POST /register`
- `GET /me`

#### Friends/people
- `GET /search`
- `POST /friends/request/{friend_username}`
- `GET /friends/requests`
- `POST /friends/accept/{request_id}`
- `GET /friends`

#### Chat/messages
- `GET /chats`
- `GET /conversations`
- `GET /chat/list`
- `GET /conversation/list`
- `GET /chat/history/{friend_username}`
- `GET /messages/{friend_username}`
- `GET /chat/{friend_username}`
- `POST /messages/{friend_username}`
- `POST /chat/send/{friend_username}`
- `POST /message/{friend_username}`
- `POST /messages/{message_id}/read`
- `POST /chat/messages/{message_id}/read`
- `DELETE /messages/{message_id}`
- `DELETE /chat/messages/{message_id}`

#### Upload
- `POST /upload`

### Future endpoints required

#### Read receipts
- Keep/expand current:
  - `POST /messages/{message_id}/read` (single)
- Add:
  - `POST /messages/read-batch` (mark conversation window as read)
  - `GET /messages/{message_id}/receipts` (if detailed receipt timeline is needed)

#### Edit message
- Add:
  - `PATCH /messages/{message_id}`
    - body: `{ "content": "...", "image_url": null|"...", ... }`
    - sets `edited_at`

#### Delete message (soft delete)
- Current endpoint physically deletes.
- Planned behavior endpoint:
  - `DELETE /messages/{message_id}` should become soft-delete implementation using `is_deleted/deleted_at`
  - optional admin/hard purge endpoint later

#### Search
- Add:
  - `GET /messages/search?query=&friend_username=&cursor=`
  - optional `GET /search/messages` alias if API naming is consolidated

#### User profile
- Add:
  - `GET /profile/me`
  - `PATCH /profile/me`
  - `GET /profile/{username}` (public-safe projection)
  - optional `POST /profile/me/avatar` and `POST /profile/me/wallpaper`

---

## 4) WebSocket Event Roadmap

### Existing events (current)

#### Client -> Server
- `join` (`room` = friend username)
- `chat` (`room`, `text`, optional `image_url`)
- `typing` (`room`)

#### Server -> Client
- `chat` (sender/text/image payload)
- `typing` (sender)
- `error` (message)

### Future events required
- `message_read`
  - notify sender that one/more message IDs were read
- `message_edited`
  - broadcast edited content + `edited_at`
- `message_deleted`
  - broadcast soft-delete state (replace content UI)
- `typing`
  - keep existing; formalize payload with conversation/message metadata
- `stop_typing`
  - explicit end-of-typing signal instead of timeout-only UI
- `reactions`
  - add/remove reaction updates for a message
- `presence`
  - explicit online/offline/last-seen updates to reduce polling dependency

---

## 5) Frontend Component Roadmap

### Existing components/modules
- Authentication flow (`core.js` + login overlay in `index.html`)
- Sidebar tabs:
  - Chats tab
  - People tab
  - Friend request actions
  - User search and add friend
- Chat area:
  - message stream rendering
  - send text
  - image upload send
  - typing indicator display
  - online/last-seen status display
- WebSocket reconnect and message handling (`websocket.js`)
- Notification toasts (`utils.js`)

### Suggested future components
- Message metadata UI:
  - timestamp renderer
  - read receipt markers
  - edited/deleted badges
- Message actions:
  - edit message inline composer
  - soft-delete confirmation/action
  - reply composer + reply preview block
  - reaction picker + reaction bar
- Search experience:
  - search panel
  - highlighted result navigation/jump-to-message
- Profile UI:
  - profile viewer card
  - profile editor modal/page
  - avatar/wallpaper upload controls
- Presence/typing refinements:
  - typing indicator service with debounce/throttle + stop typing signal
  - last-seen/presence badge component shared across sidebar/chat header

---

## 6) Feature Milestones

### Milestone 1
- Message timestamp
- Read receipts
- Edit message
- Soft delete

### Milestone 2
- Search
- Reply
- Emoji reactions

### Milestone 3
- Profile picture
- Display name
- About

### Milestone 4
- Wallpaper
- Typing indicator hardening (`typing` + `stop_typing`)
- Last seen/presence push events

---

## 7) Implementation Dependencies

- Read receipts before Last Seen refinements (shared presence/read semantics).
- Soft delete before Search finalization (search must respect deleted visibility rules).
- Reply before Reactions UI enrichment (reaction anchors should handle replied/deleted contexts cleanly).
- Edit message before Search relevance tuning (search index/display should support edited content policy).
- Profile core fields (display name/avatar) before wallpaper (identity first, personalization second).
- Presence WS events before removing/reducing sidebar polling.

---

## 8) Migration Roadmap (expected future Alembic revisions)

> Planning list only. No migrations are generated in this task.

1. **users_profile_fields**
   - add `display_name`, `about`, `profile_picture_url`, optional `wallpaper_url`, optional `updated_at` to `users`.

2. **message_reactions_table**
   - create `message_reactions` with FKs to `messages` and `users`.
   - add uniqueness and supporting indexes.

3. **messages_reply_fk_and_indexes**
   - enforce/confirm FK on `messages.reply_to_message_id`.
   - add index on `reply_to_message_id`.

4. **messages_soft_delete_indexes**
   - add indexes involving `is_deleted`, `timestamp`, sender/receiver combinations for list/history/search performance.

5. **messages_search_support**
   - optional FTS table and triggers (if full-text search is adopted), or additional conventional indexes if FTS is deferred.

6. **message_receipts_optional_normalization** (conditional)
   - create `message_receipts` if future requirements exceed current per-row read flags.
