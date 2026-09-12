"""Focused API integration tests for ChatSpic HTTP endpoints.

Verifies the complete HTTP path:
request
-> FastAPI routing
-> authentication/dependencies
-> API validation
-> service layer
-> isolated test database
-> response status/body

All tests run against an isolated in-memory SQLite database via FastAPI
dependency overrides. No test connects to or modifies the development chat.db.
"""
import asyncio
import json
import os
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlparse

from backend.core.config import settings
from backend.core.security import create_access_token
from backend.db.database import get_db
from backend.db.models import Message, User
from backend.services import chat_service
from main import app
from tests.base import BaseTestCase
from tests.test_auth_authorization import ASGIClient, ASGIResponse


# ==============================================================================
# Extended ASGI Test Client
# ==============================================================================
class IntegrationASGIClient(ASGIClient):
    """Extended ASGIClient supporting raw binary bodies and multipart uploads."""

    def request(
        self,
        method: str,
        url: str,
        headers: dict = None,
        json_body=None,
        content: bytes = None,
    ) -> ASGIResponse:
        parsed = urlparse(url)
        path = parsed.path
        query_string = parsed.query.encode("ascii")
        headers_dict = dict(headers or {})

        raw_headers = []
        body_bytes = b""
        if json_body is not None:
            body_bytes = json.dumps(json_body).encode("utf-8")
            headers_dict.setdefault("content-type", "application/json")
        elif content is not None:
            body_bytes = content

        for key, val in headers_dict.items():
            raw_headers.append((key.lower().encode("latin1"), str(val).encode("latin1")))

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method.upper(),
            "path": path,
            "raw_path": quote(path).encode("ascii"),
            "query_string": query_string,
            "headers": raw_headers,
            "client": ("127.0.0.1", 12345),
            "server": ("127.0.0.1", 80),
        }

        status_code = None
        resp_headers = {}
        resp_body = []

        async def receive():
            return {"type": "http.request", "body": body_bytes, "more_body": False}

        async def send(message):
            nonlocal status_code, resp_headers, resp_body
            if message["type"] == "http.response.start":
                status_code = message["status"]
                for hk, hv in message.get("headers", []):
                    resp_headers[hk.decode("latin1").lower()] = hv.decode("latin1")
            elif message["type"] == "http.response.body":
                resp_body.append(message.get("body", b""))

        asyncio.run(self.app(scope, receive, send))
        return ASGIResponse(status_code, resp_headers, b"".join(resp_body))

    def post_file(
        self,
        url: str,
        field_name: str,
        filename: str,
        file_bytes: bytes,
        content_type: str = "image/png",
        headers: dict = None,
    ) -> ASGIResponse:
        """Helper to send a multipart/form-data upload request."""
        boundary = "----TestFormBoundary" + uuid.uuid4().hex
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n"
        ).encode("latin1") + file_bytes + f"\r\n--{boundary}--\r\n".encode("latin1")

        req_headers = dict(headers or {})
        req_headers["content-type"] = f"multipart/form-data; boundary={boundary}"
        return self.request("POST", url, headers=req_headers, content=body)


# ==============================================================================
# Base API Integration Test Case
# ==============================================================================
class ApiIntegrationTestCase(BaseTestCase):
    """Base test case providing isolated database wiring and helper methods."""

    def setUp(self):
        super().setUp()

        def _override_get_db():
            try:
                yield self.db
            finally:
                pass

        self.addCleanup(self._cleanup_overrides)
        self.addCleanup(self._cleanup_tracked_files)
        app.dependency_overrides[get_db] = _override_get_db
        self.client = IntegrationASGIClient(app)
        self._tracked_files = []

    def tearDown(self):
        try:
            self._cleanup_overrides()
            self._cleanup_tracked_files()
        finally:
            super().tearDown()

    def _cleanup_overrides(self):
        app.dependency_overrides.pop(get_db, None)

    def _cleanup_tracked_files(self):
        for path in self._tracked_files:
            try:
                if os.path.exists(path):
                    os.remove(path)
            except OSError:
                pass

    def track_file(self, filepath_or_url: str):
        """Track an uploaded file path or URL for safe cleanup after test execution."""
        if filepath_or_url.startswith("/uploads/"):
            filename = filepath_or_url.replace("/uploads/", "")
            path = os.path.join(settings.UPLOADS_DIR, filename)
        else:
            path = filepath_or_url
        self._tracked_files.append(path)

    def auth_headers(self, username: str) -> dict:
        """Generate Bearer authorization headers for the given username."""
        token = create_access_token(
            data={"sub": username},
            expires_delta=timedelta(minutes=30),
        )
        return {"Authorization": f"Bearer {token}"}


# ==============================================================================
# 1. Authentication API
# ==============================================================================
class TestAuthenticationApi(ApiIntegrationTestCase):
    """Tests covering HTTP registration, login, and token usage."""

    def test_register_login_and_protected_access(self):
        """Register -> login -> access protected endpoint with the returned token."""
        # 1. Register
        reg_resp = self.client.post(
            "/register",
            json={"username": "diana", "password": "securepassword123"},
        )
        self.assertEqual(reg_resp.status_code, 200)
        self.assertEqual(reg_resp.json(), {"msg": "User created successfully"})

        # Verify persisted in isolated test DB
        user = self.db.query(User).filter(User.username == "diana").first()
        self.assertIsNotNone(user)

        # 2. Login
        login_resp = self.client.post(
            "/login",
            json={"username": "diana", "password": "securepassword123"},
        )
        self.assertEqual(login_resp.status_code, 200)
        login_data = login_resp.json()
        self.assertIn("access_token", login_data)
        token = login_data["access_token"]
        self.assertTrue(isinstance(token, str) and len(token) > 10)

        # 3. Access protected endpoint using the returned token
        profile_resp = self.client.get(
            "/profile/",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(profile_resp.status_code, 200)
        self.assertEqual(profile_resp.json().get("username"), "diana")

    def test_authentication_validation_and_errors(self):
        """Test representative validation and error contracts for auth endpoints."""
        # Missing required field on registration -> 422
        resp_missing = self.client.post("/register", json={"username": "missing_pass"})
        self.assertEqual(resp_missing.status_code, 422)

        # Duplicate username -> 400
        resp_dup = self.client.post(
            "/register",
            json={"username": "alice", "password": "password123"},
        )
        self.assertEqual(resp_dup.status_code, 400)
        self.assertEqual(resp_dup.json().get("detail"), "Username already taken")

        # Register a valid user with standard bcrypt password hash
        self.client.post("/register", json={"username": "auth_test_user", "password": "correctpassword"})

        # Invalid password -> 401
        resp_bad_pass = self.client.post(
            "/login",
            json={"username": "auth_test_user", "password": "wrongpassword"},
        )
        self.assertEqual(resp_bad_pass.status_code, 401)
        self.assertEqual(resp_bad_pass.json().get("detail"), "Invalid credentials")

        # Nonexistent user -> 401
        resp_nonexistent = self.client.post(
            "/login",
            json={"username": "ghost_user", "password": "somepassword"},
        )
        self.assertEqual(resp_nonexistent.status_code, 401)
        self.assertEqual(resp_nonexistent.json().get("detail"), "Invalid credentials")


# ==============================================================================
# 2. Profile API
# ==============================================================================
class TestProfileApi(ApiIntegrationTestCase):
    """Tests covering profile retrieval, field updates, and avatar URL updates."""

    def test_get_profile(self):
        """GET /profile/ returns authenticated user's profile with expected keys."""
        resp = self.client.get("/profile/", headers=self.auth_headers("alice"))
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        for key in ("username", "display_name", "about", "profile_picture"):
            self.assertIn(key, data)
        self.assertEqual(data["username"], "alice")
        self.assertEqual(data["display_name"], "Alice")

    def test_update_profile_and_persistence(self):
        """PUT /profile/ updates display_name/about and persists through subsequent GET."""
        update_resp = self.client.put(
            "/profile/",
            json={"display_name": "Alice Wonderland", "about": "Down the rabbit hole"},
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(update_resp.status_code, 200)
        update_data = update_resp.json()
        self.assertEqual(update_data.get("msg"), "Profile updated")
        self.assertEqual(update_data.get("profile", {}).get("display_name"), "Alice Wonderland")
        self.assertEqual(update_data.get("profile", {}).get("about"), "Down the rabbit hole")

        # Verify persistence through subsequent GET
        get_resp = self.client.get("/profile/", headers=self.auth_headers("alice"))
        self.assertEqual(get_resp.status_code, 200)
        get_data = get_resp.json()
        self.assertEqual(get_data.get("display_name"), "Alice Wonderland")
        self.assertEqual(get_data.get("about"), "Down the rabbit hole")

        # Verify Bob's profile was not affected
        bob_resp = self.client.get("/profile/", headers=self.auth_headers("bob"))
        self.assertEqual(bob_resp.status_code, 200)
        self.assertEqual(bob_resp.json().get("display_name"), "Bob")

    def test_update_profile_picture(self):
        """PUT /profile/picture updates the avatar URL and persists through subsequent GET."""
        put_resp = self.client.put(
            "/profile/picture",
            json={"profile_picture": "/uploads/test_avatar.png"},
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(put_resp.status_code, 200)
        put_data = put_resp.json()
        self.assertEqual(put_data.get("msg"), "Profile picture updated")
        self.assertEqual(put_data.get("profile_picture"), "/uploads/test_avatar.png")

        # Verify persistence
        get_resp = self.client.get("/profile/", headers=self.auth_headers("alice"))
        self.assertEqual(get_resp.status_code, 200)
        self.assertEqual(get_resp.json().get("profile_picture"), "/uploads/test_avatar.png")


# ==============================================================================
# 3. Friends API
# ==============================================================================
class TestFriendsApi(ApiIntegrationTestCase):
    """Tests covering friends listing, user search, and friend request lifecycle."""

    def test_get_friends_list(self):
        """GET /friends returns accepted friends with status and profile attributes."""
        resp = self.client.get("/friends", headers=self.auth_headers("alice"))
        self.assertEqual(resp.status_code, 200)
        friends = resp.json()
        self.assertTrue(isinstance(friends, list))
        usernames = {f["username"] for f in friends}
        self.assertIn("bob", usernames)
        self.assertIn("charlie", usernames)

        # Check fields on a friend item
        bob_item = next(f for f in friends if f["username"] == "bob")
        for key in ("username", "display_name", "about", "profile_picture", "last_seen", "is_online"):
            self.assertIn(key, bob_item)

    def test_search_users(self):
        """GET /search returns users with their friendship relationship status."""
        # Search for bob (already friends)
        resp = self.client.get("/search?query=bo", headers=self.auth_headers("alice"))
        self.assertEqual(resp.status_code, 200)
        results = resp.json()
        self.assertTrue(any(u["username"] == "bob" and u["status"] == "friend" for u in results))

        # Create un-friended user david and search
        self.create_user("david")
        resp_david = self.client.get("/search?query=dav", headers=self.auth_headers("alice"))
        self.assertEqual(resp_david.status_code, 200)
        david_results = resp_david.json()
        self.assertTrue(any(u["username"] == "david" and u["status"] == "none" for u in david_results))

    def test_friend_request_and_accept_lifecycle(self):
        """Send friend request -> query pending requests -> accept request."""
        self.create_user("david")

        # 1. Alice sends request to David
        send_resp = self.client.post(
            "/friends/request/david",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(send_resp.status_code, 200)
        self.assertEqual(send_resp.json().get("msg"), "Friend request sent")

        # 2. David checks pending requests
        reqs_resp = self.client.get("/friends/requests", headers=self.auth_headers("david"))
        self.assertEqual(reqs_resp.status_code, 200)
        pending = reqs_resp.json()
        self.assertTrue(any(r.get("username") == "alice" for r in pending))
        request_id = next(r["request_id"] for r in pending if r["username"] == "alice")

        # 3. David accepts the friend request
        accept_resp = self.client.post(
            f"/friends/accept/{request_id}",
            headers=self.auth_headers("david"),
        )
        self.assertEqual(accept_resp.status_code, 200)
        self.assertEqual(accept_resp.json().get("msg"), "Friend request accepted")

        # 4. Verify both now appear in each other's friends list
        david_friends = self.client.get("/friends", headers=self.auth_headers("david")).json()
        self.assertTrue(any(f["username"] == "alice" for f in david_friends))

        # 5. Duplicate request when already friends returns informative message
        dup_resp = self.client.post("/friends/request/bob", headers=self.auth_headers("alice"))
        self.assertEqual(dup_resp.status_code, 200)
        self.assertEqual(dup_resp.json().get("msg"), "You are already friends")


# ==============================================================================
# 4. Chat History API
# ==============================================================================
class TestChatHistoryApi(ApiIntegrationTestCase):
    """Tests covering chat history retrieval, ordering, empty states, and metadata."""

    def test_chat_history_contract_and_ordering(self):
        """GET /chat/history/{friend_username} returns messages ordered chronologically."""
        self.client.post(
            "/messages/bob",
            json={"text": "Message 1"},
            headers=self.auth_headers("alice"),
        )
        self.client.post(
            "/messages/bob",
            json={"text": "Message 2"},
            headers=self.auth_headers("alice"),
        )

        resp = self.client.get("/chat/history/bob", headers=self.auth_headers("alice"))
        self.assertEqual(resp.status_code, 200)
        messages = resp.json()
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0]["content"], "Message 1")
        self.assertEqual(messages[1]["content"], "Message 2")

        # Verify contract keys on the message structure
        first = messages[0]
        expected_keys = (
            "id", "sender", "sender_display_name", "receiver", "content",
            "image_url", "timestamp", "edited_at", "status", "is_read",
            "read_at", "is_deleted", "deleted_at", "reactions", "reply_to"
        )
        for key in expected_keys:
            self.assertIn(key, first)

    def test_chat_history_empty_conversation(self):
        """GET /chat/history with accepted friend having zero messages returns empty list."""
        resp = self.client.get("/chat/history/charlie", headers=self.auth_headers("alice"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), [])

    def test_chat_history_edited_deleted_reply_and_reactions_representation(self):
        """History correctly represents edited, soft-deleted, replied, and reacted messages."""
        # 1. Alice sends msg1 and edits it
        send1 = self.client.post("/messages/bob", json={"text": "Original text"}, headers=self.auth_headers("alice"))
        msg1_id = send1.json()["id"]
        self.client.patch(f"/messages/{msg1_id}", json={"text": "Edited text"}, headers=self.auth_headers("alice"))

        # 2. Bob reacts to msg1
        self.client.post(f"/messages/{msg1_id}/reactions", json={"emoji": "👍"}, headers=self.auth_headers("bob"))

        # 3. Alice sends msg2 and deletes it
        send2 = self.client.post("/messages/bob", json={"text": "Will delete"}, headers=self.auth_headers("alice"))
        msg2_id = send2.json()["id"]
        self.client.delete(f"/messages/{msg2_id}", headers=self.auth_headers("alice"))

        # 4. Alice replies to msg1 (via service for reply_to_message_id)
        chat_service.create_message(self.db, self.alice, self.bob, "Reply to msg1", None, reply_to_message_id=msg1_id)

        # 5. Retrieve history through HTTP
        resp = self.client.get("/chat/history/bob", headers=self.auth_headers("alice"))
        self.assertEqual(resp.status_code, 200)
        messages = resp.json()
        self.assertEqual(len(messages), 3)

        # Verify msg1 (edited + reaction)
        m1 = next(m for m in messages if m["id"] == msg1_id)
        self.assertEqual(m1["content"], "Edited text")
        self.assertIsNotNone(m1["edited_at"])
        self.assertTrue(any(r["emoji"] == "👍" for r in m1["reactions"]))

        # Verify msg2 (soft deleted)
        m2 = next(m for m in messages if m["id"] == msg2_id)
        self.assertTrue(m2["is_deleted"])
        self.assertEqual(m2["content"], "This message was deleted")
        self.assertIsNotNone(m2["deleted_at"])

        # Verify msg3 (reply metadata)
        m3 = messages[2]
        self.assertIsNotNone(m3["reply_to"])
        self.assertEqual(m3["reply_to"]["id"], msg1_id)
        self.assertEqual(m3["reply_to"]["content"], "Edited text")

    def test_conversations_list_contract(self):
        """GET /conversations returns conversation summaries with unread count and last message."""
        self.client.post("/messages/bob", json={"text": "Latest greeting"}, headers=self.auth_headers("alice"))
        resp = self.client.get("/conversations", headers=self.auth_headers("alice"))
        self.assertEqual(resp.status_code, 200)
        convs = resp.json()
        self.assertTrue(isinstance(convs, list))
        bob_conv = next((c for c in convs if c["username"] == "bob"), None)
        self.assertIsNotNone(bob_conv)
        self.assertEqual(bob_conv["last_message"], "Latest greeting")
        self.assertIn("unread_count", bob_conv)

        # Non-friend chat history access is rejected with 404
        david = self.create_user("david")
        non_friend_resp = self.client.get("/chat/history/david", headers=self.auth_headers("alice"))
        self.assertEqual(non_friend_resp.status_code, 404)
        self.assertEqual(non_friend_resp.json().get("detail"), "Friend not found")


# ==============================================================================
# 5. Message API
# ==============================================================================
class TestMessageApi(ApiIntegrationTestCase):
    """Tests covering message send, edit, delete, and read operations through HTTP."""

    def test_send_message_and_retrieve_through_history(self):
        """POST /messages/{friend_username} sends message and it appears in GET history."""
        send_resp = self.client.post(
            "/messages/bob",
            json={"text": "Hello Bob over HTTP!"},
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(send_resp.status_code, 200)
        msg = send_resp.json()
        self.assertEqual(msg["content"], "Hello Bob over HTTP!")
        self.assertEqual(msg["sender"], "alice")
        self.assertEqual(msg["receiver"], "bob")

        # Bob verifies via chat history
        hist_resp = self.client.get("/chat/history/alice", headers=self.auth_headers("bob"))
        self.assertEqual(hist_resp.status_code, 200)
        self.assertTrue(any(m["content"] == "Hello Bob over HTTP!" for m in hist_resp.json()))

    def test_edit_message_and_retrieve_through_history(self):
        """PATCH /messages/{message_id} updates content and reflects in history."""
        send_resp = self.client.post(
            "/messages/bob",
            json={"text": "Draft text"},
            headers=self.auth_headers("alice"),
        )
        msg_id = send_resp.json()["id"]

        edit_resp = self.client.patch(
            f"/messages/{msg_id}",
            json={"text": "Final polished text"},
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(edit_resp.status_code, 200)
        self.assertEqual(edit_resp.json()["content"], "Final polished text")

        # Verify through history
        hist_resp = self.client.get("/chat/history/alice", headers=self.auth_headers("bob"))
        self.assertEqual(hist_resp.status_code, 200)
        m = next(item for item in hist_resp.json() if item["id"] == msg_id)
        self.assertEqual(m["content"], "Final polished text")
        self.assertIsNotNone(m["edited_at"])

    def test_delete_message_and_retrieve_through_history(self):
        """DELETE /messages/{message_id} soft-deletes message and masks content in history."""
        send_resp = self.client.post(
            "/messages/bob",
            json={"text": "Secret note"},
            headers=self.auth_headers("alice"),
        )
        msg_id = send_resp.json()["id"]

        del_resp = self.client.delete(f"/messages/{msg_id}", headers=self.auth_headers("alice"))
        self.assertEqual(del_resp.status_code, 200)
        del_data = del_resp.json()
        self.assertEqual(del_data.get("msg"), "Message deleted")
        self.assertTrue(del_data.get("is_deleted"))

        # Verify through history
        hist_resp = self.client.get("/chat/history/alice", headers=self.auth_headers("bob"))
        self.assertEqual(hist_resp.status_code, 200)
        m = next(item for item in hist_resp.json() if item["id"] == msg_id)
        self.assertTrue(m["is_deleted"])
        self.assertEqual(m["content"], "This message was deleted")

    def test_mark_message_read_and_verify_state(self):
        """POST /messages/{message_id}/read marks message read and updates read_at/status."""
        send_resp = self.client.post(
            "/messages/bob",
            json={"text": "Please acknowledge"},
            headers=self.auth_headers("alice"),
        )
        msg_id = send_resp.json()["id"]

        # Bob marks as read
        read_resp = self.client.post(
            f"/messages/{msg_id}/read",
            headers=self.auth_headers("bob"),
        )
        self.assertEqual(read_resp.status_code, 200)
        read_data = read_resp.json()
        self.assertEqual(read_data.get("msg"), "Message marked as read")
        self.assertTrue(read_data.get("is_read"))
        self.assertEqual(read_data.get("status"), "read")

        # History confirms read status
        hist_resp = self.client.get("/chat/history/alice", headers=self.auth_headers("bob"))
        self.assertEqual(hist_resp.status_code, 200)
        m = next(item for item in hist_resp.json() if item["id"] == msg_id)
        self.assertTrue(m["is_read"])
        self.assertEqual(m["status"], "read")
        self.assertIsNotNone(m["read_at"])


# ==============================================================================
# 6. Search API
# ==============================================================================
class TestSearchApi(ApiIntegrationTestCase):
    """Tests covering HTTP message search within a conversation."""

    def test_search_conversation_messages(self):
        """GET /chat/{friend_username}/search returns matching messages case-insensitively."""
        self.client.post("/messages/bob", json={"text": "Deployment checklist"}, headers=self.auth_headers("alice"))
        self.client.post("/messages/bob", json={"text": "Lunch plan"}, headers=self.auth_headers("alice"))
        self.client.post("/messages/bob", json={"text": "Post-deployment review"}, headers=self.auth_headers("alice"))

        resp = self.client.get("/chat/bob/search?query=deployment", headers=self.auth_headers("alice"))
        self.assertEqual(resp.status_code, 200)
        results = resp.json()
        self.assertEqual(len(results), 2)

        # Case-insensitive query
        resp_ci = self.client.get("/chat/bob/search?query=LUNCH", headers=self.auth_headers("alice"))
        self.assertEqual(resp_ci.status_code, 200)
        self.assertEqual(len(resp_ci.json()), 1)
        self.assertEqual(resp_ci.json()[0]["content"], "Lunch plan")

    def test_search_no_match(self):
        """Search query with no matches returns empty list."""
        self.client.post("/messages/bob", json={"text": "Regular message"}, headers=self.auth_headers("alice"))
        resp = self.client.get("/chat/bob/search?query=zebra_token_123", headers=self.auth_headers("alice"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), [])

    def test_search_conversation_scoping(self):
        """Search is scoped to the specified conversation and excludes messages from others."""
        self.client.post("/messages/bob", json={"text": "Confidential for Bob"}, headers=self.auth_headers("alice"))
        self.client.post("/messages/charlie", json={"text": "Confidential for Charlie"}, headers=self.auth_headers("alice"))

        resp = self.client.get("/chat/bob/search?query=Confidential", headers=self.auth_headers("alice"))
        self.assertEqual(resp.status_code, 200)
        results = resp.json()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["content"], "Confidential for Bob")

    def test_search_excludes_deleted_messages(self):
        """Deleted messages must be excluded from search results."""
        send_resp = self.client.post("/messages/bob", json={"text": "Temporary passcode"}, headers=self.auth_headers("alice"))
        msg_id = send_resp.json()["id"]

        self.client.delete(f"/messages/{msg_id}", headers=self.auth_headers("alice"))

        resp = self.client.get("/chat/bob/search?query=passcode", headers=self.auth_headers("alice"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), [])


# ==============================================================================
# 7. Reactions API
# ==============================================================================
class TestReactionsApi(ApiIntegrationTestCase):
    """Tests covering adding and removing emoji reactions via HTTP."""

    def test_add_and_remove_reaction_through_history(self):
        """Add reaction -> verify in history -> remove reaction -> verify in history."""
        send_resp = self.client.post("/messages/bob", json={"text": "Awesome job!"}, headers=self.auth_headers("alice"))
        msg_id = send_resp.json()["id"]

        # 1. Bob adds flame reaction
        add_resp = self.client.post(
            f"/messages/{msg_id}/reactions",
            json={"emoji": "🔥"},
            headers=self.auth_headers("bob"),
        )
        self.assertEqual(add_resp.status_code, 200)
        reactions = add_resp.json()
        self.assertTrue(any(r["emoji"] == "🔥" and r["count"] == 1 for r in reactions))

        # Verify via history
        hist1 = self.client.get("/chat/history/alice", headers=self.auth_headers("bob")).json()
        msg1 = next(m for m in hist1 if m["id"] == msg_id)
        self.assertTrue(any(r["emoji"] == "🔥" for r in msg1["reactions"]))

        # 2. Bob removes the reaction
        del_resp = self.client.delete(
            f"/messages/{msg_id}/reactions/🔥",
            headers=self.auth_headers("bob"),
        )
        self.assertEqual(del_resp.status_code, 200)
        self.assertEqual(del_resp.json(), [])

        # Verify via history
        hist2 = self.client.get("/chat/history/alice", headers=self.auth_headers("bob")).json()
        msg2 = next(m for m in hist2 if m["id"] == msg_id)
        self.assertEqual(msg2["reactions"], [])

    def test_reaction_validation_and_error(self):
        """Representative validation and error cases for reactions API."""
        send_resp = self.client.post("/messages/bob", json={"text": "React here"}, headers=self.auth_headers("alice"))
        msg_id = send_resp.json()["id"]

        # Invalid emoji -> 400
        resp_invalid = self.client.post(
            f"/messages/{msg_id}/reactions",
            json={"emoji": "invalid_emoji"},
            headers=self.auth_headers("bob"),
        )
        self.assertEqual(resp_invalid.status_code, 400)
        self.assertEqual(resp_invalid.json().get("detail"), "Invalid emoji")

        # Nonexistent message -> 404
        resp_404 = self.client.post(
            "/messages/999999/reactions",
            json={"emoji": "👍"},
            headers=self.auth_headers("bob"),
        )
        self.assertEqual(resp_404.status_code, 404)
        self.assertEqual(resp_404.json().get("detail"), "Message not found")


# ==============================================================================
# 8. Upload API
# ==============================================================================
class TestUploadApi(ApiIntegrationTestCase):
    """Tests covering file upload validation, size limits, and media flows."""

    def test_valid_image_upload_and_integration(self):
        """Valid PNG upload succeeds, returns URL, and integrates with profile/chat."""
        png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
        resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="avatar.png",
            file_bytes=png_bytes,
            content_type="image/png",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("url", data)
        file_url = data["url"]
        self.assertTrue(file_url.startswith("/uploads/"))
        self.assertTrue(file_url.endswith(".png"))
        self.track_file(file_url)

        # 1. Integrate with profile picture
        prof_resp = self.client.put(
            "/profile/picture",
            json={"profile_picture": file_url},
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(prof_resp.status_code, 200)
        self.assertEqual(prof_resp.json().get("profile_picture"), file_url)

        # 2. Integrate with chat message
        msg_resp = self.client.post(
            "/messages/bob",
            json={"text": "Look at this image", "image_url": file_url},
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(msg_resp.status_code, 200)
        self.assertEqual(msg_resp.json().get("image_url"), file_url)

    def test_upload_invalid_type_rejected(self):
        """Non-image and spoofed signature uploads are rejected with 415."""
        # Plain text
        resp_text = self.client.post_file(
            "/upload",
            field_name="file",
            filename="script.txt",
            file_bytes=b"plain text content",
            content_type="text/plain",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp_text.status_code, 415)
        self.assertEqual(resp_text.json().get("detail"), "Unsupported or invalid image file type")

        # Spoofed extension with invalid magic bytes
        resp_spoofed = self.client.post_file(
            "/upload",
            field_name="file",
            filename="fake.png",
            file_bytes=b"FAKE_SIGNATURE_BYTES_12345",
            content_type="image/png",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp_spoofed.status_code, 415)

    def test_upload_oversized_rejected(self):
        """Uploads exceeding max file size limit (5MB) are rejected with 413."""
        # 5MB + 1KB of data with valid PNG header
        oversized_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * (5 * 1024 * 1024 + 1024)
        resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="huge.png",
            file_bytes=oversized_bytes,
            content_type="image/png",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp.status_code, 413)
        self.assertEqual(resp.json().get("detail"), "File too large")


if __name__ == "__main__":
    unittest.main()
