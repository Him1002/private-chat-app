"""Focused automated tests for ChatSpic WebSocket reliability and real-time messaging.

Verifies the complete WebSocket lifecycle:
WebSocket connection
-> authentication
-> connection lifecycle
-> message handling
-> delivery/read events
-> typing events
-> disconnect/reconnect behavior
-> error handling
-> connection cleanup

All tests run against an isolated in-memory SQLite database via FastAPI
dependency overrides. No test connects to or modifies the development chat.db.
"""
import asyncio
import json
import unittest
from datetime import datetime, timedelta, timezone

from jose import jwt

from main import app
from backend.core.config import settings
from backend.core.security import create_access_token
from backend.db.database import get_db
from backend.db.models import Friend, Message, MessageReaction, User
from backend.realtime import websocket as ws_module
from backend.services import chat_service
from backend.services.friend_service import get_friends_list
from tests.base import BaseTestCase


# ==============================================================================
# Zero-Dependency ASGI WebSocket Test Client
# ==============================================================================
class WebSocketTestClient:
    """Minimal zero-dependency ASGI WebSocket test client for FastAPI."""

    def __init__(self, asgi_app):
        self.app = asgi_app
        self.client_to_app = asyncio.Queue()
        self.app_to_client = asyncio.Queue()
        self.task = None
        self.accepted = False
        self.close_code = None

    async def connect(self, path: str = "/ws", token: str = None, query_string: str = None, timeout: float = 2.0) -> bool:
        if query_string is None:
            query_string = f"token={token}" if token is not None else ""

        scope = {
            "type": "websocket",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "scheme": "ws",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": query_string.encode("ascii"),
            "headers": [(b"host", b"testserver")],
            "client": ("127.0.0.1", 12345),
            "server": ("127.0.0.1", 80),
            "subprotocols": [],
        }

        async def receive():
            return await self.client_to_app.get()

        async def send(message):
            await self.app_to_client.put(message)

        self.task = asyncio.create_task(self.app(scope, receive, send))
        await self.client_to_app.put({"type": "websocket.connect"})

        # Wait for initial response from the server (accept or close)
        connect_fut = asyncio.create_task(self.app_to_client.get())
        done, _ = await asyncio.wait(
            [connect_fut, self.task],
            return_when=asyncio.FIRST_COMPLETED,
            timeout=timeout,
        )

        if connect_fut in done:
            resp = connect_fut.result()
            if resp["type"] == "websocket.accept":
                # Check if immediately followed by websocket.close (e.g. auth rejection 1008)
                try:
                    second_msg = await asyncio.wait_for(self.app_to_client.get(), timeout=0.05)
                    if second_msg["type"] == "websocket.close":
                        self.accepted = False
                        self.close_code = second_msg.get("code")
                        return False
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    pass
                self.accepted = True
                return True
            elif resp["type"] == "websocket.close":
                self.accepted = False
                self.close_code = resp.get("code")
                return False

        if not connect_fut.done():
            connect_fut.cancel()

        self.accepted = False
        return False

    async def send_text(self, text: str):
        await self.client_to_app.put({"type": "websocket.receive", "text": text})

    async def send_json(self, data):
        await self.send_text(json.dumps(data))

    async def receive_json(self, timeout: float = 2.0) -> dict:
        msg = await asyncio.wait_for(self.app_to_client.get(), timeout=timeout)
        if msg["type"] == "websocket.close":
            self.close_code = msg.get("code")
            raise ConnectionResetError(f"WebSocket closed with code {self.close_code}")
        if msg["type"] == "websocket.send":
            return json.loads(msg["text"])
        raise RuntimeError(f"Unexpected ASGI message: {msg}")

    async def disconnect(self, code: int = 1000):
        if self.task and not self.task.done():
            await self.client_to_app.put({"type": "websocket.disconnect", "code": code})
            try:
                await asyncio.wait_for(self.task, timeout=2.0)
            except Exception:
                pass
        self.task = None


# ==============================================================================
# Base Test Case for WebSocket Reliability
# ==============================================================================
class WebSocketReliabilityTestCase(BaseTestCase):
    """Base test case providing isolated database wiring and WebSocket test fixtures."""

    def setUp(self):
        super().setUp()
        self.active_clients = []

        def _override_get_db():
            try:
                yield self.db
            finally:
                pass

        self.addCleanup(self._cleanup_test_state)
        app.dependency_overrides[get_db] = _override_get_db
        self._reset_ws_globals()

    def _cleanup_test_state(self):
        app.dependency_overrides.pop(get_db, None)
        self._reset_ws_globals()

    def _reset_ws_globals(self):
        ws_module.online_users.clear()
        ws_module.rooms.clear()

    async def create_ws_client(self, user: User = None, token: str = None, auto_connect: bool = True) -> WebSocketTestClient:
        if token is None and user is not None:
            token = create_access_token({"sub": user.username}, timedelta(minutes=30))
        client = WebSocketTestClient(app)
        self.active_clients.append(client)
        if auto_connect:
            await client.connect(token=token)
        return client

    def tearDown(self):
        try:
            async def drain_all():
                for c in self.active_clients:
                    try:
                        await c.disconnect()
                    except Exception:
                        pass
            if self.active_clients:
                asyncio.run(drain_all())
        finally:
            self._cleanup_test_state()
            super().tearDown()


# ==============================================================================
# 1. WebSocket Authentication Tests
# ==============================================================================
class TestWebSocketAuthentication(WebSocketReliabilityTestCase):
    """Verify WebSocket authentication contract, token validation, and rejected connection isolation."""

    def test_valid_token_allows_connection(self):
        """Valid JWT token connects, accepted by server, and registers user in online_users."""
        async def run():
            token = create_access_token({"sub": "alice"}, timedelta(minutes=15))
            client = await self.create_ws_client(token=token)
            self.assertTrue(client.accepted)
            self.assertEqual(ws_module.online_users.get(self.alice.id), 1)
            await client.disconnect()
        asyncio.run(run())

    def test_malformed_token_rejected(self):
        """Malformed token is rejected with WS code 1008 and does not register in online_users."""
        async def run():
            client = await self.create_ws_client(token="not-a-valid-jwt-token")
            self.assertFalse(client.accepted)
            self.assertEqual(client.close_code, 1008)
            self.assertNotIn(self.alice.id, ws_module.online_users)
            self.assertEqual(len(ws_module.online_users), 0)
        asyncio.run(run())

    def test_invalid_signature_rejected(self):
        """Token signed with wrong secret key is rejected with code 1008."""
        async def run():
            bad_token = jwt.encode(
                {"sub": "alice", "exp": datetime.utcnow() + timedelta(minutes=15)},
                "wrong-secret-key-12345",
                algorithm="HS256",
            )
            client = await self.create_ws_client(token=bad_token)
            self.assertFalse(client.accepted)
            self.assertEqual(client.close_code, 1008)
            self.assertEqual(len(ws_module.online_users), 0)
        asyncio.run(run())

    def test_expired_token_rejected(self):
        """Expired JWT token is rejected with code 1008."""
        async def run():
            expired_token = create_access_token({"sub": "alice"}, timedelta(minutes=-10))
            client = await self.create_ws_client(token=expired_token)
            self.assertFalse(client.accepted)
            self.assertEqual(client.close_code, 1008)
            self.assertEqual(len(ws_module.online_users), 0)
        asyncio.run(run())

    def test_nonexistent_user_token_rejected(self):
        """Token for nonexistent user is rejected with code 1008."""
        async def run():
            token = create_access_token({"sub": "ghost_user"}, timedelta(minutes=15))
            client = await self.create_ws_client(token=token)
            self.assertFalse(client.accepted)
            self.assertEqual(client.close_code, 1008)
            self.assertEqual(len(ws_module.online_users), 0)
        asyncio.run(run())

    def test_missing_token_rejected(self):
        """Missing token parameter is rejected by route validation without updating online_users."""
        async def run():
            client = await self.create_ws_client(token=None, auto_connect=False)
            connected = await client.connect(query_string="")
            self.assertFalse(connected)
            self.assertEqual(len(ws_module.online_users), 0)
        asyncio.run(run())

    def test_empty_token_rejected(self):
        """Empty token parameter is rejected with code 1008."""
        async def run():
            client = await self.create_ws_client(token="")
            self.assertFalse(client.accepted)
            self.assertEqual(client.close_code, 1008)
            self.assertEqual(len(ws_module.online_users), 0)
        asyncio.run(run())


# ==============================================================================
# 2. Connection Lifecycle Tests
# ==============================================================================
class TestConnectionLifecycle(WebSocketReliabilityTestCase):
    """Verify connection establishment, disconnect cleanup, and presence state updates."""

    def test_successful_connection_and_presence(self):
        """Connecting registers user with connection count 1 in online_users."""
        async def run():
            client = await self.create_ws_client(user=self.alice)
            self.assertTrue(client.accepted)
            self.assertEqual(ws_module.online_users[self.alice.id], 1)
            await client.disconnect()
        asyncio.run(run())

    def test_normal_disconnect_removes_user(self):
        """Normal clean disconnect removes user from online_users when no connections remain."""
        async def run():
            client = await self.create_ws_client(user=self.alice)
            self.assertIn(self.alice.id, ws_module.online_users)
            await client.disconnect(code=1000)
            self.assertNotIn(self.alice.id, ws_module.online_users)
            self.assertEqual(len(ws_module.online_users), 0)
        asyncio.run(run())

    def test_repeated_connect_disconnect_preserves_state(self):
        """Repeated connect and disconnect cycles do not corrupt online_users state."""
        async def run():
            for _ in range(3):
                client = await self.create_ws_client(user=self.alice)
                self.assertEqual(ws_module.online_users.get(self.alice.id), 1)
                await client.disconnect(code=1000)
                self.assertNotIn(self.alice.id, ws_module.online_users)
            self.assertEqual(len(ws_module.online_users), 0)
        asyncio.run(run())

    def test_disconnect_updates_last_seen_in_db(self):
        """Disconnecting the final active connection updates the user's last_seen timestamp in the database."""
        async def run():
            before_connect = datetime.now(timezone.utc)
            client = await self.create_ws_client(user=self.alice)
            await client.disconnect(code=1000)

            self.db.refresh(self.alice)
            self.assertIsNotNone(self.alice.last_seen)
            last_seen_utc = self.alice.last_seen.replace(tzinfo=timezone.utc) if self.alice.last_seen.tzinfo is None else self.alice.last_seen
            self.assertGreaterEqual(last_seen_utc, before_connect - timedelta(seconds=2))
        asyncio.run(run())


# ==============================================================================
# 3. Multiple Connections / Tabs Tests
# ==============================================================================
class TestMultipleConnections(WebSocketReliabilityTestCase):
    """Verify multi-tab connection counting, partial disconnects, and final disconnect handling."""

    def test_multi_tab_connection_counting(self):
        """Opening multiple tabs increments connection count, and closing one tab keeps user online."""
        async def run():
            # First connection
            tab1 = await self.create_ws_client(user=self.alice)
            self.assertEqual(ws_module.online_users.get(self.alice.id), 1)

            # Second connection (same user, new tab)
            tab2 = await self.create_ws_client(user=self.alice)
            self.assertEqual(ws_module.online_users.get(self.alice.id), 2)

            # Closing tab 1 decrements count but keeps user online
            await tab1.disconnect()
            self.assertEqual(ws_module.online_users.get(self.alice.id), 1)

            # Closing tab 2 removes user from online_users completely
            await tab2.disconnect()
            self.assertNotIn(self.alice.id, ws_module.online_users)
            self.assertEqual(len(ws_module.online_users), 0)
        asyncio.run(run())

    def test_reconnect_after_all_closed_restores_online(self):
        """Reconnecting after all tabs closed cleanly restores online state."""
        async def run():
            tab1 = await self.create_ws_client(user=self.alice)
            await tab1.disconnect()
            self.assertNotIn(self.alice.id, ws_module.online_users)

            tab2 = await self.create_ws_client(user=self.alice)
            self.assertEqual(ws_module.online_users.get(self.alice.id), 1)
            await tab2.disconnect()
            self.assertNotIn(self.alice.id, ws_module.online_users)
        asyncio.run(run())


# ==============================================================================
# 4. Message Delivery Tests
# ==============================================================================
class TestMessageDelivery(WebSocketReliabilityTestCase):
    """Verify end-to-end WebSocket message transmission, payload contract, and persistence."""

    def test_send_and_receive_message_between_friends(self):
        """Alice sends message to Bob; Bob receives chat event with complete serialized metadata."""
        async def run():
            alice_client = await self.create_ws_client(user=self.alice)
            bob_client = await self.create_ws_client(user=self.bob)

            # Both join the shared DM room
            await alice_client.send_json({"type": "join", "room": "bob"})
            await bob_client.send_json({"type": "join", "room": "alice"})
            await asyncio.sleep(0.05)

            # Alice sends a message
            await alice_client.send_json({
                "type": "chat",
                "room": "bob",
                "text": "Hello Bob from Alice!",
            })

            # Bob receives the chat message
            bob_event = await bob_client.receive_json()
            self.assertEqual(bob_event["type"], "chat")
            self.assertEqual(bob_event["sender"], "alice")
            self.assertEqual(bob_event["sender_display_name"], "Alice")
            self.assertEqual(bob_event["text"], "Hello Bob from Alice!")
            self.assertIsNotNone(bob_event["id"])
            self.assertIsNotNone(bob_event["timestamp"])

            # Alice receives echo and delivered status event
            alice_echo = await alice_client.receive_json()
            self.assertEqual(alice_echo["type"], "chat")
            self.assertEqual(alice_echo["text"], "Hello Bob from Alice!")

            alice_status = await alice_client.receive_json()
            self.assertEqual(alice_status["type"], "message_status")
            self.assertEqual(alice_status["status"], "delivered")
            self.assertEqual(alice_status["message_id"], bob_event["id"])

            await alice_client.disconnect()
            await bob_client.disconnect()
        asyncio.run(run())

    def test_message_persists_in_database(self):
        """WebSocket message is persisted in SQLite with valid foreign keys and fields."""
        async def run():
            client = await self.create_ws_client(user=self.alice)
            await client.send_json({
                "type": "chat",
                "room": "bob",
                "text": "Database persistence check",
            })
            resp = await client.receive_json()
            msg_id = resp["id"]

            msg = self.db.query(Message).filter(Message.id == msg_id).first()
            self.assertIsNotNone(msg)
            self.assertEqual(msg.sender_id, self.alice.id)
            self.assertEqual(msg.receiver_id, self.bob.id)
            self.assertEqual(msg.content, "Database persistence check")
            self.assertFalse(msg.is_read)
            self.assertIsNone(msg.read_at)
            await client.disconnect()
        asyncio.run(run())


# ==============================================================================
# 5. Delivery Status Tests
# ==============================================================================
class TestDeliveryStatus(WebSocketReliabilityTestCase):
    """Verify delivery status notifications and disconnected recipient handling."""

    def test_disconnected_recipient_does_not_trigger_delivered_event(self):
        """When recipient is not connected, sender receives message echo but NOT delivered status event."""
        async def run():
            alice_client = await self.create_ws_client(user=self.alice)
            await alice_client.send_json({
                "type": "chat",
                "room": "bob",
                "text": "Message to offline Bob",
            })

            echo = await alice_client.receive_json()
            self.assertEqual(echo["type"], "chat")
            self.assertEqual(echo["text"], "Message to offline Bob")

            # Verify no delivered event is queued
            with self.assertRaises(asyncio.TimeoutError):
                await alice_client.receive_json(timeout=0.3)

            # In DB, message remains sent and unread
            msg = self.db.query(Message).filter(Message.id == echo["id"]).first()
            self.assertFalse(msg.is_read)
            self.assertIsNone(msg.read_at)

            await alice_client.disconnect()
        asyncio.run(run())


# ==============================================================================
# 6. Read Receipts Tests
# ==============================================================================
class TestReadReceipts(WebSocketReliabilityTestCase):
    """Verify read receipts flow via room joining, DB mutation, and read notifications."""

    def test_join_room_marks_messages_read_and_notifies_sender(self):
        """Recipient joining conversation room marks messages read and emits messages_read to sender."""
        async def run():
            alice_client = await self.create_ws_client(user=self.alice)
            await alice_client.send_json({"type": "join", "room": "bob"})

            # Alice sends message while Bob is offline
            await alice_client.send_json({
                "type": "chat",
                "room": "bob",
                "text": "Read receipt test message",
            })
            echo = await alice_client.receive_json()
            msg_id = echo["id"]

            # Bob connects and joins the room with Alice
            bob_client = await self.create_ws_client(user=self.bob)
            await bob_client.send_json({"type": "join", "room": "alice"})

            # Bob receives message from chat history
            history_msg = await bob_client.receive_json()
            self.assertEqual(history_msg["id"], msg_id)

            # Alice receives messages_read event
            read_event = await alice_client.receive_json()
            self.assertEqual(read_event["type"], "messages_read")
            self.assertIn(msg_id, read_event["message_ids"])
            self.assertEqual(read_event["reader"], "bob")
            self.assertIsNotNone(read_event["read_at"])

            # Verify DB state updated
            self.db.expire_all()
            db_msg = self.db.query(Message).filter(Message.id == msg_id).first()
            self.assertTrue(db_msg.is_read)
            self.assertIsNotNone(db_msg.read_at)

            await alice_client.disconnect()
            await bob_client.disconnect()
        asyncio.run(run())

    def test_receiving_chat_message_does_not_automatically_mark_read(self):
        """Merely receiving a real-time message does not automatically mark it read in the database."""
        async def run():
            alice_client = await self.create_ws_client(user=self.alice)
            bob_client = await self.create_ws_client(user=self.bob)

            await alice_client.send_json({"type": "join", "room": "bob"})
            await bob_client.send_json({"type": "join", "room": "alice"})
            await asyncio.sleep(0.05)

            # Drain join history/events
            await alice_client.send_json({"type": "chat", "room": "bob", "text": "Unread on receipt check"})
            bob_msg = await bob_client.receive_json()
            msg_id = bob_msg["id"]

            # Verify message remains is_read=False in database
            self.db.expire_all()
            db_msg = self.db.query(Message).filter(Message.id == msg_id).first()
            self.assertFalse(db_msg.is_read)

            await alice_client.disconnect()
            await bob_client.disconnect()
        asyncio.run(run())


# ==============================================================================
# 7. Typing Events Tests
# ==============================================================================
class TestTypingEvents(WebSocketReliabilityTestCase):
    """Verify typing indicator transmission, sender exclusion, and conversation isolation."""

    def test_typing_forwarded_to_friend_and_not_self(self):
        """Typing event is delivered to friend in the room and never echoed back to sender."""
        async def run():
            alice_client = await self.create_ws_client(user=self.alice)
            bob_client = await self.create_ws_client(user=self.bob)

            await alice_client.send_json({"type": "join", "room": "bob"})
            await bob_client.send_json({"type": "join", "room": "alice"})
            await asyncio.sleep(0.05)

            # Alice sends typing indicator
            await alice_client.send_json({"type": "typing", "room": "bob"})

            # Bob receives typing event
            typing_event = await bob_client.receive_json()
            self.assertEqual(typing_event["type"], "typing")
            self.assertEqual(typing_event["sender"], "alice")

            # Alice does not receive typing event
            with self.assertRaises(asyncio.TimeoutError):
                await alice_client.receive_json(timeout=0.3)

            await alice_client.disconnect()
            await bob_client.disconnect()
        asyncio.run(run())

    def test_typing_does_not_modify_database_or_force_presence(self):
        """Typing events do not create messages or prevent clean disconnect."""
        async def run():
            msg_count_before = self.db.query(Message).count()
            alice_client = await self.create_ws_client(user=self.alice)
            await alice_client.send_json({"type": "typing", "room": "bob"})

            self.assertEqual(self.db.query(Message).count(), msg_count_before)
            await alice_client.disconnect()
            self.assertNotIn(self.alice.id, ws_module.online_users)
        asyncio.run(run())

    def test_typing_does_not_leak_to_unrelated_users(self):
        """Typing event for Bob is not delivered to Charlie in a different room."""
        async def run():
            alice_client = await self.create_ws_client(user=self.alice)
            charlie_client = await self.create_ws_client(user=self.charlie)

            await alice_client.send_json({"type": "join", "room": "bob"})
            await charlie_client.send_json({"type": "join", "room": "alice"})

            await alice_client.send_json({"type": "typing", "room": "bob"})

            with self.assertRaises(asyncio.TimeoutError):
                await charlie_client.receive_json(timeout=0.3)

            await alice_client.disconnect()
            await charlie_client.disconnect()
        asyncio.run(run())


# ==============================================================================
# 8. Presence Interaction Tests
# ==============================================================================
class TestPresenceInteraction(WebSocketReliabilityTestCase):
    """Verify WebSocket connection lifecycle integration with friends presence queries."""

    def test_presence_reflection_in_friends_service(self):
        """Connected user reflects is_online=True in friends list query; disconnect reflects is_online=False."""
        async def run():
            # Initially Bob is offline
            friends_before = get_friends_list(self.db, self.alice.id, set(ws_module.online_users.keys()))
            bob_entry = next(f for f in friends_before if f["username"] == "bob")
            self.assertFalse(bob_entry["is_online"])

            # Bob connects
            bob_client = await self.create_ws_client(user=self.bob)
            friends_during = get_friends_list(self.db, self.alice.id, set(ws_module.online_users.keys()))
            bob_entry = next(f for f in friends_during if f["username"] == "bob")
            self.assertTrue(bob_entry["is_online"])

            # Bob disconnects
            await bob_client.disconnect()
            friends_after = get_friends_list(self.db, self.alice.id, set(ws_module.online_users.keys()))
            bob_entry = next(f for f in friends_after if f["username"] == "bob")
            self.assertFalse(bob_entry["is_online"])
            self.assertIsNotNone(bob_entry["last_seen"])
        asyncio.run(run())


# ==============================================================================
# 9. Reconnect Behavior Tests
# ==============================================================================
class TestReconnectBehavior(WebSocketReliabilityTestCase):
    """Verify reconnect handling, room re-registration, and messaging continuity."""

    def test_disconnect_and_reconnect_lifecycle(self):
        """User disconnects and reconnects; new connection can successfully send and receive."""
        async def run():
            # First session
            client1 = await self.create_ws_client(user=self.alice)
            await client1.disconnect()

            # Reconnect session
            client2 = await self.create_ws_client(user=self.alice)
            self.assertEqual(ws_module.online_users[self.alice.id], 1)

            # Send message in new session
            await client2.send_json({
                "type": "chat",
                "room": "bob",
                "text": "Message after reconnect",
            })
            resp = await client2.receive_json()
            self.assertEqual(resp["type"], "chat")
            self.assertEqual(resp["text"], "Message after reconnect")

            await client2.disconnect()
            self.assertNotIn(self.alice.id, ws_module.online_users)
        asyncio.run(run())


# ==============================================================================
# 10. Error Handling Tests
# ==============================================================================
class TestErrorHandling(WebSocketReliabilityTestCase):
    """Verify server boundary error handling, input validation, and connection preservation."""

    def test_malformed_json_returns_error_and_preserves_connection(self):
        """Malformed JSON string returns error message without dropping the WebSocket connection."""
        async def run():
            client = await self.create_ws_client(user=self.alice)
            await client.send_text("this is { not valid json")

            err = await client.receive_json()
            self.assertEqual(err["type"], "error")
            self.assertEqual(err["message"], "Invalid JSON payload")

            # Connection remains open and functional
            await client.send_json({"type": "chat", "room": "bob", "text": "Still alive!"})
            echo = await client.receive_json()
            self.assertEqual(echo["text"], "Still alive!")

            await client.disconnect()
            self.assertNotIn(self.alice.id, ws_module.online_users)
        asyncio.run(run())

    def test_json_primitives_and_lists_rejected(self):
        """Non-dict JSON payloads (primitives, lists) return Invalid JSON payload error."""
        async def run():
            client = await self.create_ws_client(user=self.alice)

            for payload in ['"a string"', '42', 'true', '[1, 2, 3]']:
                await client.send_text(payload)
                err = await client.receive_json()
                self.assertEqual(err["type"], "error")
                self.assertEqual(err["message"], "Invalid JSON payload")

            await client.disconnect()
            self.assertNotIn(self.alice.id, ws_module.online_users)
        asyncio.run(run())

    def test_unknown_event_type_ignored(self):
        """Unknown event type does not crash the server and leaves connection active."""
        async def run():
            client = await self.create_ws_client(user=self.alice)
            await client.send_json({"type": "unknown_dummy_type"})

            # Verify connection remains alive
            await client.send_json({"type": "chat", "room": "bob", "text": "Post unknown event"})
            echo = await client.receive_json()
            self.assertEqual(echo["text"], "Post unknown event")

            await client.disconnect()
        asyncio.run(run())

    def test_missing_message_body_rejected(self):
        """Sending chat message without text or image returns validation error."""
        async def run():
            client = await self.create_ws_client(user=self.alice)
            await client.send_json({"type": "chat", "room": "bob"})

            err = await client.receive_json()
            self.assertEqual(err["type"], "error")
            self.assertEqual(err["message"], "Message body cannot be empty")

            await client.disconnect()
        asyncio.run(run())

    def test_invalid_reply_to_id_rejected(self):
        """Non-integer reply_to_message_id returns error."""
        async def run():
            client = await self.create_ws_client(user=self.alice)
            await client.send_json({
                "type": "chat",
                "room": "bob",
                "text": "Replying with bad id",
                "reply_to_message_id": "not-an-int",
            })

            err = await client.receive_json()
            self.assertEqual(err["type"], "error")
            self.assertEqual(err["message"], "Invalid reply_to_message_id")

            await client.disconnect()
        asyncio.run(run())

    def test_nonexistent_reply_target_rejected(self):
        """Replying to nonexistent message ID returns error."""
        async def run():
            client = await self.create_ws_client(user=self.alice)
            await client.send_json({
                "type": "chat",
                "room": "bob",
                "text": "Replying to ghost",
                "reply_to_message_id": 99999,
            })

            err = await client.receive_json()
            self.assertEqual(err["type"], "error")
            self.assertEqual(err["message"], "Reply target message not found")

            await client.disconnect()
        asyncio.run(run())

    def test_invalid_reaction_payload_rejected(self):
        """Invalid reaction parameters (bad ID or unsupported emoji) return errors."""
        async def run():
            client = await self.create_ws_client(user=self.alice)

            # Invalid ID format
            await client.send_json({"type": "reaction_add", "message_id": "bad", "emoji": "👍"})
            err1 = await client.receive_json()
            self.assertEqual(err1["type"], "error")
            self.assertEqual(err1["message"], "Invalid message id")

            # Nonexistent message ID
            await client.send_json({"type": "reaction_add", "message_id": 99999, "emoji": "👍"})
            err2 = await client.receive_json()
            self.assertEqual(err2["type"], "error")
            self.assertEqual(err2["message"], "Message not found")

            await client.disconnect()
        asyncio.run(run())


# ==============================================================================
# 11. Authorization Boundaries Tests
# ==============================================================================
class TestAuthorizationBoundaries(WebSocketReliabilityTestCase):
    """Verify authorization and friendship conversation boundaries across WebSocket actions."""

    def test_join_non_friend_rejected(self):
        """Joining room with non-friend user returns You are not friends error."""
        async def run():
            # Bob and Charlie are not friends
            client = await self.create_ws_client(user=self.bob)
            await client.send_json({"type": "join", "room": "charlie"})

            err = await client.receive_json()
            self.assertEqual(err["type"], "error")
            self.assertEqual(err["message"], "You are not friends")

            await client.disconnect()
        asyncio.run(run())

    def test_join_nonexistent_user_rejected(self):
        """Joining room with nonexistent username returns User does not exist error."""
        async def run():
            client = await self.create_ws_client(user=self.alice)
            await client.send_json({"type": "join", "room": "nonexistent_ghost"})

            err = await client.receive_json()
            self.assertEqual(err["type"], "error")
            self.assertEqual(err["message"], "User does not exist")

            await client.disconnect()
        asyncio.run(run())

    def test_cross_conversation_reply_rejected(self):
        """Replying to a message from a different conversation is rejected."""
        async def run():
            # Alice sends message to Charlie
            msg_to_charlie = Message(
                sender_id=self.alice.id,
                receiver_id=self.charlie.id,
                content="Secret Alice-Charlie message",
                timestamp=datetime.now(timezone.utc),
            )
            self.db.add(msg_to_charlie)
            self.db.commit()

            # Alice tries to reply to that message in Bob's room
            client = await self.create_ws_client(user=self.alice)
            await client.send_json({
                "type": "chat",
                "room": "bob",
                "text": "Cross-conversation leak attempt",
                "reply_to_message_id": msg_to_charlie.id,
            })

            err = await client.receive_json()
            self.assertEqual(err["type"], "error")
            self.assertEqual(err["message"], "Reply target does not belong to this conversation")

            await client.disconnect()
        asyncio.run(run())

    def test_delete_another_users_message_rejected(self):
        """Deleting a message sent by another user returns Forbidden error."""
        async def run():
            # Bob sent message to Alice
            msg = Message(
                sender_id=self.bob.id,
                receiver_id=self.alice.id,
                content="Bob's original message",
                timestamp=datetime.now(timezone.utc),
            )
            self.db.add(msg)
            self.db.commit()

            # Alice tries to delete Bob's message
            client = await self.create_ws_client(user=self.alice)
            await client.send_json({"type": "message_delete", "message_id": msg.id})

            err = await client.receive_json()
            self.assertEqual(err["type"], "error")
            self.assertIn("You can only delete your own messages", err["message"])

            await client.disconnect()
        asyncio.run(run())

    def test_edit_another_users_message_rejected(self):
        """Editing a message sent by another user returns Forbidden error."""
        async def run():
            msg = Message(
                sender_id=self.bob.id,
                receiver_id=self.alice.id,
                content="Bob's message to edit",
                timestamp=datetime.now(timezone.utc),
            )
            self.db.add(msg)
            self.db.commit()

            # Alice tries to edit Bob's message
            client = await self.create_ws_client(user=self.alice)
            await client.send_json({
                "type": "message_edit",
                "message_id": msg.id,
                "text": "Malicious edit attempt",
            })

            err = await client.receive_json()
            self.assertEqual(err["type"], "error")
            self.assertIn("You can only edit your own messages", err["message"])

            await client.disconnect()
        asyncio.run(run())


# ==============================================================================
# 12. Database Integrity Tests
# ==============================================================================
class TestDatabaseIntegrity(WebSocketReliabilityTestCase):
    """Verify database consistency, edit/delete persistence, and failure isolation."""

    def test_edit_message_persists_in_database(self):
        """Editing a message via WebSocket updates content and populates edited_at in the database."""
        async def run():
            client = await self.create_ws_client(user=self.alice)
            await client.send_json({"type": "chat", "room": "bob", "text": "Original text"})
            resp = await client.receive_json()
            msg_id = resp["id"]

            await client.send_json({
                "type": "message_edit",
                "message_id": msg_id,
                "text": "Edited text content",
            })
            edit_resp = await client.receive_json()
            self.assertEqual(edit_resp["type"], "message_updated")
            self.assertEqual(edit_resp["text"], "Edited text content")

            self.db.expire_all()
            msg = self.db.query(Message).filter(Message.id == msg_id).first()
            self.assertEqual(msg.content, "Edited text content")
            self.assertIsNotNone(msg.edited_at)

            await client.disconnect()
        asyncio.run(run())

    def test_delete_message_soft_deletes_in_database(self):
        """Deleting a message via WebSocket marks is_deleted=True and preserves the database row."""
        async def run():
            client = await self.create_ws_client(user=self.alice)
            await client.send_json({"type": "chat", "room": "bob", "text": "To be deleted"})
            resp = await client.receive_json()
            msg_id = resp["id"]

            await client.send_json({"type": "message_delete", "message_id": msg_id})
            del_resp = await client.receive_json()
            self.assertEqual(del_resp["type"], "message_deleted")

            self.db.expire_all()
            msg = self.db.query(Message).filter(Message.id == msg_id).first()
            self.assertIsNotNone(msg)
            self.assertTrue(msg.is_deleted)
            self.assertIsNotNone(msg.deleted_at)

            await client.disconnect()
        asyncio.run(run())

    def test_reactions_persist_and_remove_in_database(self):
        """Adding and removing reactions via WebSocket correctly mutates MessageReaction table."""
        async def run():
            client = await self.create_ws_client(user=self.alice)
            await client.send_json({"type": "chat", "room": "bob", "text": "Reaction target"})
            resp = await client.receive_json()
            msg_id = resp["id"]

            # Add reaction
            await client.send_json({"type": "reaction_add", "message_id": msg_id, "emoji": "🔥"})
            add_resp = await client.receive_json()
            self.assertEqual(add_resp["type"], "reaction_update")

            self.db.expire_all()
            r = self.db.query(MessageReaction).filter(
                MessageReaction.message_id == msg_id,
                MessageReaction.user_id == self.alice.id,
            ).first()
            self.assertIsNotNone(r)
            self.assertEqual(r.emoji, "🔥")

            # Remove reaction
            await client.send_json({"type": "reaction_remove", "message_id": msg_id, "emoji": "🔥"})
            rem_resp = await client.receive_json()
            self.assertEqual(rem_resp["type"], "reaction_update")

            self.db.expire_all()
            r = self.db.query(MessageReaction).filter(
                MessageReaction.message_id == msg_id,
                MessageReaction.user_id == self.alice.id,
            ).first()
            self.assertIsNone(r)

            await client.disconnect()
        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
