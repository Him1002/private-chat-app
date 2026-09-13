"""Authentication and authorization boundary tests for ChatSpic.

Tests cover:
1. Registration (valid input, duplicate usernames, missing fields, password hashing).
2. Login (valid credentials, wrong password, nonexistent user, token generation).
3. JWT Authentication (valid token, malformed token, invalid signature, expired token,
   nonexistent/deleted user, missing auth headers, invalid scheme, WebSocket token verification).
4. Protected endpoint authorization and access boundaries.
5. Message ownership (editing, deleting, reading).
6. Profile ownership contract (session-scoped profile updates).
7. Reply authorization (same-conversation, cross-conversation, nonexistent target, DB FK).
8. Friend-request ownership and authorization.

All endpoint tests run against an isolated in-memory SQLite database via FastAPI
dependency overrides. No test connects to or modifies the development chat.db.
"""
import asyncio
import json
import unittest
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from jose import jwt
from sqlalchemy.exc import IntegrityError

from main import app
from backend.core.config import settings
from backend.core.security import (
    create_access_token,
    pwd_context,
    verify_password,
    verify_ws_token,
)
from backend.db.database import get_db
from backend.db.models import Friend, Message, User
from backend.services import chat_service
from backend.services.chat_service import BadRequestError
from backend.services.friend_service import (
    create_friend_request as service_create_friend_request,
)
from tests.base import BaseTestCase


# ==============================================================================
# Minimal Zero-Dependency ASGI Client
# ==============================================================================
class ASGIResponse:
    """Wrapper around an ASGI response matching standard test client semantics."""

    def __init__(self, status_code: int, headers: dict, body: bytes):
        self.status_code = status_code
        self.headers = headers
        self.content = body

    def json(self):
        if not self.content:
            return None
        return json.loads(self.content.decode("utf-8"))

    @property
    def text(self) -> str:
        return self.content.decode("utf-8")


class ASGIClient:
    """Minimal zero-dependency ASGI test client for FastAPI.

    Directly invokes the ASGI callable with an in-memory HTTP scope and streams
    request and response buffers using standard library asyncio.
    """

    def __init__(self, asgi_app):
        self.app = asgi_app

    def request(
        self,
        method: str,
        url: str,
        headers: dict = None,
        json_body=None,
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

        for key, val in headers_dict.items():
            raw_headers.append((key.lower().encode("latin1"), str(val).encode("latin1")))

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method.upper(),
            "path": path,
            "raw_path": path.encode("ascii"),
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

    def get(self, url: str, headers: dict = None) -> ASGIResponse:
        return self.request("GET", url, headers=headers)

    def post(self, url: str, json: dict = None, headers: dict = None) -> ASGIResponse:
        return self.request("POST", url, headers=headers, json_body=json)

    def put(self, url: str, json: dict = None, headers: dict = None) -> ASGIResponse:
        return self.request("PUT", url, headers=headers, json_body=json)

    def patch(self, url: str, json: dict = None, headers: dict = None) -> ASGIResponse:
        return self.request("PATCH", url, headers=headers, json_body=json)

    def delete(self, url: str, headers: dict = None) -> ASGIResponse:
        return self.request("DELETE", url, headers=headers)


# ==============================================================================
# Helper Verification Tests
# ==============================================================================
class TestASGIHelper(unittest.TestCase):
    """Tests verifying the zero-dependency ASGI test helper itself."""

    def test_asgi_helper_operates_correctly(self):
        client = ASGIClient(app)

        # GET frontend root (static/index.html) -> 200
        resp = client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/html", resp.headers.get("content-type", ""))

        # Nonexistent route -> 404 JSON
        resp_404 = client.get("/nonexistent_test_route_xyz")
        self.assertEqual(resp_404.status_code, 404)
        self.assertIn("detail", resp_404.json())


# ==============================================================================
# Base Endpoint Test Case with Database Isolation
# ==============================================================================
class AuthEndpointTestCase(BaseTestCase):
    """Base class for authentication and authorization endpoint tests.

    Sets up FastAPI dependency overrides so all route dependencies resolve to
    the isolated test database session. Guarantees overrides are cleaned up
    even if test assertions raise exceptions.
    """

    def setUp(self):
        super().setUp()

        def _override_get_db():
            try:
                yield self.db
            finally:
                pass

        # Guarantee cleanup even if setUp or test fails
        self.addCleanup(self._cleanup_overrides)
        app.dependency_overrides[get_db] = _override_get_db
        self.client = ASGIClient(app)

    def tearDown(self):
        try:
            self._cleanup_overrides()
        finally:
            super().tearDown()

    def _cleanup_overrides(self):
        app.dependency_overrides.pop(get_db, None)

    def auth_headers(self, username: str) -> dict:
        """Create valid Bearer authorization headers for the given username."""
        token = create_access_token(
            data={"sub": username},
            expires_delta=timedelta(minutes=30),
        )
        return {"Authorization": f"Bearer {token}"}


# ==============================================================================
# Authentication Boundaries
# ==============================================================================
class TestAuthentication(AuthEndpointTestCase):
    """Tests covering user registration, login, and JWT token authentication."""

    def test_registration_success(self):
        """Valid registration creates the user and returns success message."""
        resp = self.client.post(
            "/register",
            json={"username": "diana", "password": "securepassword123"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"msg": "User created successfully"})

        # Verify user exists in the isolated database
        user = self.db.query(User).filter(User.username == "diana").first()
        self.assertIsNotNone(user)
        self.assertEqual(user.username, "diana")

    def test_registration_duplicate_username_rejected(self):
        """Registration with an existing username must be rejected with 400."""
        # 'alice' is seeded in standard fixtures
        resp = self.client.post(
            "/register",
            json={"username": "alice", "password": "newpassword123"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json().get("detail"), "Username already taken")

        # Verify database still has exactly one alice
        alice_count = self.db.query(User).filter(User.username == "alice").count()
        self.assertEqual(alice_count, 1)

    def test_registration_invalid_input_rejected(self):
        """Registration requests missing required fields must return 422."""
        # Missing password
        resp_no_pass = self.client.post("/register", json={"username": "nopassuser"})
        self.assertEqual(resp_no_pass.status_code, 422)

        # Missing username
        resp_no_user = self.client.post("/register", json={"password": "nopassworduser"})
        self.assertEqual(resp_no_user.status_code, 422)

        # Empty body
        resp_empty = self.client.post("/register", json={})
        self.assertEqual(resp_empty.status_code, 422)

    def test_registration_password_stored_as_hash(self):
        """Plaintext passwords must never be stored in the database."""
        plain_password = "supersecretplainpassword"
        resp = self.client.post(
            "/register",
            json={"username": "eve", "password": plain_password},
        )
        self.assertEqual(resp.status_code, 200)

        user = self.db.query(User).filter(User.username == "eve").first()
        self.assertIsNotNone(user)
        self.assertNotEqual(user.password_hash, plain_password)
        self.assertTrue(verify_password(plain_password, user.password_hash))

    def test_login_valid_credentials_succeeds(self):
        """Login with valid credentials returns 200 and a valid JWT access token."""
        # Create a test user with a known hashed password
        password = "validpassword123"
        hashed = pwd_context.hash(password)
        self.create_user("frank", password_hash=hashed)

        resp = self.client.post(
            "/login",
            json={"username": "frank", "password": password},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("access_token", data)

        # Verify token contents
        token = data["access_token"]
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        self.assertEqual(payload.get("sub"), "frank")

    def test_login_wrong_password_rejected(self):
        """Login with incorrect password returns 401 Invalid credentials."""
        password = "correctpassword"
        self.create_user("grace", password_hash=pwd_context.hash(password))

        resp = self.client.post(
            "/login",
            json={"username": "grace", "password": "wrongpassword"},
        )
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json().get("detail"), "Invalid credentials")

    def test_login_nonexistent_user_rejected(self):
        """Login for a user that does not exist returns 401 Invalid credentials."""
        resp = self.client.post(
            "/login",
            json={"username": "ghost_user", "password": "somepassword"},
        )
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json().get("detail"), "Invalid credentials")

    def test_jwt_valid_token_accepted(self):
        """A valid JWT token allows access to protected endpoints."""
        resp = self.client.get("/profile/", headers=self.auth_headers("alice"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json().get("username"), "alice")

    def test_jwt_malformed_token_rejected(self):
        """Malformed or non-JWT token strings must be rejected with 401."""
        headers = {"Authorization": "Bearer not.a.valid.jwt.token"}
        resp = self.client.get("/profile/", headers=headers)
        self.assertEqual(resp.status_code, 401)

    def test_jwt_invalid_signature_rejected(self):
        """Tokens signed with a different secret key must be rejected with 401."""
        wrong_token = jwt.encode(
            {"sub": "alice", "exp": datetime.now(timezone.utc) + timedelta(minutes=15)},
            "different-secret-key-xyz",
            algorithm="HS256",
        )
        headers = {"Authorization": f"Bearer {wrong_token}"}
        resp = self.client.get("/profile/", headers=headers)
        self.assertEqual(resp.status_code, 401)

    def test_jwt_expired_token_rejected(self):
        """Expired JWT tokens must be rejected with 401."""
        expired_token = create_access_token(
            data={"sub": "alice"},
            expires_delta=timedelta(seconds=-30),
        )
        headers = {"Authorization": f"Bearer {expired_token}"}
        resp = self.client.get("/profile/", headers=headers)
        self.assertEqual(resp.status_code, 401)

    def test_jwt_nonexistent_or_deleted_user_rejected(self):
        """A validly signed token referring to a nonexistent user returns 401."""
        headers = self.auth_headers("deleted_or_nonexistent_user")
        resp = self.client.get("/profile/", headers=headers)
        self.assertEqual(resp.status_code, 401)

    def test_protected_endpoint_missing_auth_rejected(self):
        """Requests without Authorization credentials must be rejected with 401."""
        resp = self.client.get("/profile/")
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json().get("detail"), "Not authenticated")

    def test_protected_endpoint_invalid_auth_scheme_rejected(self):
        """Requests using a non-Bearer scheme must be rejected."""
        headers = {"Authorization": "Basic dXNlcjpwYXNzd29yZA=="}
        resp = self.client.get("/profile/", headers=headers)
        self.assertIn(resp.status_code, (401, 403))

    def test_websocket_token_verification(self):
        """Unit verification of WebSocket token authentication logic."""
        # 1. Valid token returns user
        valid_token = create_access_token(
            {"sub": "alice"},
            expires_delta=timedelta(minutes=15),
        )
        user = verify_ws_token(valid_token, self.db)
        self.assertIsNotNone(user)
        self.assertEqual(user.username, "alice")

        # 2. Expired token returns None
        expired_token = create_access_token(
            {"sub": "alice"},
            expires_delta=timedelta(seconds=-15),
        )
        self.assertIsNone(verify_ws_token(expired_token, self.db))

        # 3. Malformed token returns None
        self.assertIsNone(verify_ws_token("not-a-token", self.db))

        # 4. Token with unknown user returns None
        ghost_token = create_access_token(
            {"sub": "nonexistent_ghost"},
            expires_delta=timedelta(minutes=15),
        )
        self.assertIsNone(verify_ws_token(ghost_token, self.db))

        # 5. Token without 'sub' claim returns None
        no_sub_token = jwt.encode(
            {"custom": "data"},
            settings.SECRET_KEY,
            algorithm=settings.ALGORITHM,
        )
        self.assertIsNone(verify_ws_token(no_sub_token, self.db))


# ==============================================================================
# Authorization and Ownership Boundaries
# ==============================================================================
class TestAuthorization(AuthEndpointTestCase):
    """Tests covering resource ownership and authorization boundaries."""

    def test_protected_endpoint_access_control(self):
        """Verify access control boundaries across representative protected routes."""
        # Unauthenticated calls must fail with 401
        for endpoint in ("/profile/", "/friends", "/chat/history/bob"):
            resp = self.client.get(endpoint)
            self.assertEqual(
                resp.status_code,
                401,
                f"Endpoint {endpoint} failed to reject unauthenticated access",
            )

        # Authenticated calls to permitted resources must succeed
        alice_headers = self.auth_headers("alice")
        resp_prof = self.client.get("/profile/", headers=alice_headers)
        self.assertEqual(resp_prof.status_code, 200)

        resp_friends = self.client.get("/friends", headers=alice_headers)
        self.assertEqual(resp_friends.status_code, 200)

        # Authenticated call to an un-friended user returns 404 Not Found
        self.create_user("stranger")
        resp_stranger = self.client.get("/chat/history/stranger", headers=alice_headers)
        self.assertEqual(resp_stranger.status_code, 404)

    def test_me_endpoint_returns_username_string_and_no_hash(self):
        """GET /me must return only the authenticated username string and never leak password_hash."""
        alice_headers = self.auth_headers("alice")
        resp = self.client.get("/me", headers=alice_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data, {"username": "alice"})
        self.assertNotIn("password_hash", str(data))

    def test_message_edit_ownership(self):
        """A user may only edit their own message; other users are rejected."""
        # Alice sends message to Bob
        msg = chat_service.create_message(self.db, self.alice, self.bob, "Original text", None)

        # 1. Message sender (Alice) can edit their own message -> 200
        alice_headers = self.auth_headers("alice")
        resp_alice = self.client.patch(
            f"/messages/{msg.id}",
            json={"text": "Alice updated text"},
            headers=alice_headers,
        )
        self.assertEqual(resp_alice.status_code, 200)
        self.assertEqual(resp_alice.json().get("content"), "Alice updated text")

        # 2. Recipient (Bob) attempts to edit Alice's message -> 403 Forbidden
        bob_headers = self.auth_headers("bob")
        resp_bob = self.client.patch(
            f"/messages/{msg.id}",
            json={"text": "Bob illicit update"},
            headers=bob_headers,
        )
        self.assertEqual(resp_bob.status_code, 403)
        self.assertEqual(resp_bob.json().get("detail"), "You can only edit your own messages")

        # Verify in database that Bob's unauthorized edit was not applied
        self.db.refresh(msg)
        self.assertEqual(msg.content, "Alice updated text")

        # 3. Third-party user (Charlie) attempts to edit -> 404 Not Found
        charlie_headers = self.auth_headers("charlie")
        resp_charlie = self.client.patch(
            f"/messages/{msg.id}",
            json={"text": "Charlie illicit update"},
            headers=charlie_headers,
        )
        self.assertEqual(resp_charlie.status_code, 404)

    def test_message_delete_ownership(self):
        """A user may only delete their own message; other users are rejected."""
        # Alice sends message to Bob
        msg = chat_service.create_message(self.db, self.alice, self.bob, "Message to delete", None)

        # 1. Recipient (Bob) attempts to delete Alice's message -> 403 Forbidden
        bob_headers = self.auth_headers("bob")
        resp_bob = self.client.delete(f"/messages/{msg.id}", headers=bob_headers)
        self.assertEqual(resp_bob.status_code, 403)
        self.assertEqual(resp_bob.json().get("detail"), "You can only delete your own messages")

        # Verify message remains undeleted in DB
        self.db.refresh(msg)
        self.assertFalse(msg.is_deleted)

        # 2. Third-party user (Charlie) attempts to delete -> 404 Not Found
        charlie_headers = self.auth_headers("charlie")
        resp_charlie = self.client.delete(f"/messages/{msg.id}", headers=charlie_headers)
        self.assertEqual(resp_charlie.status_code, 404)

        # 3. Owner (Alice) deletes own message -> 200
        alice_headers = self.auth_headers("alice")
        resp_alice = self.client.delete(f"/messages/{msg.id}", headers=alice_headers)
        self.assertEqual(resp_alice.status_code, 200)

        # Verify message is marked deleted in DB
        self.db.refresh(msg)
        self.assertTrue(msg.is_deleted)

    def test_message_read_authorization(self):
        """Only the intended recipient can mark a message as read."""
        # Alice sends message to Bob
        msg = chat_service.create_message(self.db, self.alice, self.bob, "Unread message", None)
        self.assertFalse(msg.is_read)

        # 1. Sender (Alice) attempts to mark own sent message as read -> 404
        alice_headers = self.auth_headers("alice")
        resp_alice = self.client.post(f"/messages/{msg.id}/read", headers=alice_headers)
        self.assertEqual(resp_alice.status_code, 404)

        # 2. Third party (Charlie) attempts to mark read -> 404
        charlie_headers = self.auth_headers("charlie")
        resp_charlie = self.client.post(f"/messages/{msg.id}/read", headers=charlie_headers)
        self.assertEqual(resp_charlie.status_code, 404)

        # 3. Intended recipient (Bob) marks message read -> 200
        bob_headers = self.auth_headers("bob")
        resp_bob = self.client.post(f"/messages/{msg.id}/read", headers=bob_headers)
        self.assertEqual(resp_bob.status_code, 200)

        self.db.refresh(msg)
        self.assertTrue(msg.is_read)

    def test_profile_ownership_contract(self):
        """Profile endpoints are session-scoped; user updates affect only their own record."""
        alice_headers = self.auth_headers("alice")
        bob_headers = self.auth_headers("bob")

        # Alice updates display_name and about
        resp_alice = self.client.put(
            "/profile/",
            json={"display_name": "Alice Wonderland", "about": "Adventurer"},
            headers=alice_headers,
        )
        self.assertEqual(resp_alice.status_code, 200)

        # Bob updates profile picture
        resp_bob = self.client.put(
            "/profile/picture",
            json={"profile_picture": "https://example.com/bob.jpg"},
            headers=bob_headers,
        )
        self.assertEqual(resp_bob.status_code, 200)

        # Verify in DB: Alice's fields are updated; Bob's display_name/about are unaffected
        self.db.refresh(self.alice)
        self.db.refresh(self.bob)

        self.assertEqual(self.alice.display_name, "Alice Wonderland")
        self.assertEqual(self.alice.about, "Adventurer")
        self.assertIsNone(self.alice.profile_picture)

        self.assertEqual(self.bob.display_name, "Bob")
        self.assertIsNone(self.bob.about)
        self.assertEqual(self.bob.profile_picture, "https://example.com/bob.jpg")

    def test_reply_same_conversation_allowed(self):
        """Replying to a message within the same conversation succeeds."""
        parent = chat_service.create_message(self.db, self.alice, self.bob, "Parent message", None)

        # Bob replies to Alice's message in the same conversation
        reply = chat_service.create_message(
            self.db,
            self.bob,
            self.alice,
            "Reply message",
            None,
            reply_to_message_id=parent.id,
        )
        self.assertEqual(reply.reply_to_message_id, parent.id)

    def test_reply_cross_conversation_rejected(self):
        """Replying to a message from a different conversation must be rejected."""
        # Charlie sends message to Bob (Charlie-Bob conversation)
        parent_cb = chat_service.create_message(self.db, self.charlie, self.bob, "CB message", None)

        # Alice attempts to reply to Charlie-Bob message in Alice-Bob conversation
        with self.assertRaises(BadRequestError) as ctx:
            chat_service.create_message(
                self.db,
                self.alice,
                self.bob,
                "Cross-convo reply attempt",
                None,
                reply_to_message_id=parent_cb.id,
            )
        self.assertEqual(str(ctx.exception), "Reply target does not belong to this conversation")

    def test_reply_nonexistent_target_rejected(self):
        """Replying to a non-existent message ID must be rejected by service validation."""
        with self.assertRaises(BadRequestError) as ctx:
            chat_service.create_message(
                self.db,
                self.alice,
                self.bob,
                "Reply to nothing",
                None,
                reply_to_message_id=999999,
            )
        self.assertEqual(str(ctx.exception), "Reply target message not found")

    def test_reply_database_fk_integrity(self):
        """Direct DB insert with an invalid reply FK must be rejected by SQLite FK constraints."""
        bad_reply = Message(
            sender_id=self.alice.id,
            receiver_id=self.bob.id,
            content="Bypassing service validation",
            timestamp=datetime.now(timezone.utc),
            reply_to_message_id=888888,
        )
        self.db.add(bad_reply)
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()

    def test_friend_request_ownership_authorization(self):
        """Only the intended recipient can accept a friend request."""
        dave = self.create_user("dave")

        # Dave sends friend request to Charlie
        res = service_create_friend_request(self.db, dave.id, "charlie")
        self.assertEqual(res.get("msg"), "Friend request sent")

        # Retrieve the pending request
        pending = (
            self.db.query(Friend)
            .filter(
                Friend.user_id == dave.id,
                Friend.friend_id == self.charlie.id,
                Friend.status == "pending",
            )
            .first()
        )
        self.assertIsNotNone(pending)
        req_id = pending.id

        # 1. Alice attempts to accept Charlie's friend request -> 404 Request not found
        alice_headers = self.auth_headers("alice")
        resp_alice = self.client.post(f"/friends/accept/{req_id}", headers=alice_headers)
        self.assertEqual(resp_alice.status_code, 404)
        self.assertEqual(resp_alice.json().get("detail"), "Request not found")

        # Verify request status in DB remains pending for Charlie
        self.db.refresh(pending)
        self.assertEqual(pending.status, "pending")

        # 2. Charlie (the intended recipient) accepts the friend request -> 200
        charlie_headers = self.auth_headers("charlie")
        resp_charlie = self.client.post(f"/friends/accept/{req_id}", headers=charlie_headers)
        self.assertEqual(resp_charlie.status_code, 200)
        self.assertEqual(resp_charlie.json().get("msg"), "Friend request accepted")

        # Verify in DB that request is accepted and mutual friendship exists
        self.db.refresh(pending)
        self.assertEqual(pending.status, "accepted")

        reverse_friendship = (
            self.db.query(Friend)
            .filter(
                Friend.user_id == self.charlie.id,
                Friend.friend_id == dave.id,
                Friend.status == "accepted",
            )
            .first()
        )
        self.assertIsNotNone(reverse_friendship)


# ==============================================================================
# Dependency Overrides Safety Verification
# ==============================================================================
class TestDependencyOverrideSafety(unittest.TestCase):
    """Verify that no test leaves app.dependency_overrides populated."""

    def test_dependency_overrides_clean_lifecycle(self):
        """Ensure get_db override is cleared and does not leak across test cases."""
        self.assertNotIn(get_db, app.dependency_overrides)
        self.assertEqual(len(app.dependency_overrides), 0)

    def test_teardown_cleans_overrides_on_simulated_error(self):
        """Verify that AuthEndpointTestCase cleans overrides even when errors occur."""
        case = AuthEndpointTestCase()
        case.setUp()
        self.assertIn(get_db, app.dependency_overrides)
        try:
            # Simulate test execution that would raise an exception
            raise ValueError("Simulated unexpected test failure")
        except ValueError:
            pass
        finally:
            case.tearDown()

        self.assertNotIn(get_db, app.dependency_overrides)


if __name__ == "__main__":
    unittest.main()
