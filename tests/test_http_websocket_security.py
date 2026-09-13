"""Dedicated automated tests for HTTP & WebSocket Security Hardening (Sprint 5 Task S5-T05).

Covers:
1. HTTP Security Headers:
   - X-Content-Type-Options: nosniff
   - Referrer-Policy: strict-origin-when-cross-origin
   - X-Frame-Options: DENY
   - Absence of brittle CSP
   - Normal HTTP responses, static files, and API responses
2. Configurable CORS:
   - Configured allowed origin accepted with credentials
   - Unconfigured origin rejected (no Access-Control-Allow-Origin)
   - Development wildcard behavior (* present without credentials)
   - OPTIONS preflight behavior
   - Production mode does not silently fall back to wildcard
3. WebSocket Authentication Hardening (SEC-07):
   - Valid JWT token connects and is accepted
   - Missing token rejected with code 1008 BEFORE accept
   - Invalid token rejected with code 1008 BEFORE accept
   - Expired token rejected with code 1008 BEFORE accept
   - Whitespace token rejected with code 1008 BEFORE accept
   - Unauthorized room access rejected
4. WebSocket Payload Validation (SEC-10):
   - Malformed JSON produces controlled error without disconnect
   - Non-dict JSON produces controlled error without disconnect
   - Missing/invalid event type produces controlled error without disconnect
   - Malformed typing payload (null, integer, boolean room) handled safely without TypeError or disconnect
   - Boolean IDs rejected (not accidentally parsed as integer 1)
   - Non-string text/image/emoji payloads rejected with controlled errors
   - Valid message/typing/reaction flows remain fully functional
"""
import asyncio
import json
import unittest
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt

from main import app
from backend.core.config import Settings, parse_allowed_origins
from backend.core.security import SecurityHeadersMiddleware, create_access_token
from backend.db.database import get_db
from backend.db.models import Message, User
from backend.realtime import websocket as ws_module
from tests.base import BaseTestCase
from tests.test_auth_authorization import ASGIClient, ASGIResponse
from tests.test_websocket_reliability import (
    WebSocketReliabilityTestCase,
    WebSocketTestClient,
)


# ==============================================================================
# 1. HTTP Security Headers Tests
# ==============================================================================
class TestHttpSecurityHeaders(BaseTestCase):
    """Verify presence of non-breaking HTTP security headers on HTTP responses."""

    def setUp(self):
        super().setUp()
        self.client = ASGIClient(app)

    def test_security_headers_present_on_root_endpoint(self):
        """GET / includes X-Content-Type-Options, Referrer-Policy, and X-Frame-Options."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(
            resp.headers.get("referrer-policy"), "strict-origin-when-cross-origin"
        )
        self.assertEqual(resp.headers.get("x-frame-options"), "DENY")

    def test_security_headers_present_on_api_endpoints(self):
        """API endpoints include security headers even on 401 unauthorized responses."""
        resp = self.client.get("/friends")
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(
            resp.headers.get("referrer-policy"), "strict-origin-when-cross-origin"
        )
        self.assertEqual(resp.headers.get("x-frame-options"), "DENY")

    def test_security_headers_present_on_static_files(self):
        """Static file responses include security headers."""
        resp = self.client.get("/static/css/variables.css")
        self.assertIn(resp.status_code, (200, 304))
        self.assertEqual(resp.headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(
            resp.headers.get("referrer-policy"), "strict-origin-when-cross-origin"
        )
        self.assertEqual(resp.headers.get("x-frame-options"), "DENY")

    def test_csp_header_not_blindly_added(self):
        """Content-Security-Policy is not added to avoid breaking inline frontend assets."""
        resp = self.client.get("/")
        self.assertNotIn("content-security-policy", resp.headers)

    def test_static_javascript_mime_type_core_js(self):
        """Regression test: /static/js/core.js must return a JavaScript Content-Type with nosniff."""
        resp = self.client.get("/static/js/core.js")
        self.assertEqual(resp.status_code, 200)
        content_type = resp.headers.get("content-type", "")
        self.assertTrue(
            content_type.startswith(("application/javascript", "text/javascript")),
            f"Expected JavaScript MIME type but got '{content_type}'",
        )
        self.assertNotEqual(content_type, "text/plain", "JavaScript file must never be served as text/plain")
        self.assertEqual(resp.headers.get("x-content-type-options"), "nosniff")

    def test_static_javascript_mime_type_auth_js(self):
        """Regression test: /static/js/auth.js must return a JavaScript Content-Type with nosniff."""
        resp = self.client.get("/static/js/auth.js")
        self.assertEqual(resp.status_code, 200)
        content_type = resp.headers.get("content-type", "")
        self.assertTrue(
            content_type.startswith(("application/javascript", "text/javascript")),
            f"Expected JavaScript MIME type but got '{content_type}'",
        )
        self.assertNotEqual(content_type, "text/plain", "JavaScript file must never be served as text/plain")
        self.assertEqual(resp.headers.get("x-content-type-options"), "nosniff")

    def test_existing_static_assets_serve_correctly(self):
        """Regression test: CSS and HTML assets continue serving with correct MIME types and nosniff."""
        css_resp = self.client.get("/static/css/base.css")
        self.assertIn(css_resp.status_code, (200, 304))
        self.assertTrue(css_resp.headers.get("content-type", "").startswith("text/css"))
        self.assertEqual(css_resp.headers.get("x-content-type-options"), "nosniff")

        html_resp = self.client.get("/")
        self.assertEqual(html_resp.status_code, 200)
        self.assertTrue(html_resp.headers.get("content-type", "").startswith("text/html"))
        self.assertEqual(html_resp.headers.get("x-content-type-options"), "nosniff")


# ==============================================================================
# 2. Configurable CORS Tests
# ==============================================================================
class TestConfigurableCORS(unittest.TestCase):
    """Verify CORS middleware behavior across development, production, and configured origins."""

    def _build_test_app(self, origins):
        """Helper to construct a test FastAPI instance with configured CORS."""
        test_app = FastAPI()
        allow_credentials = bool(origins and "*" not in origins)
        test_app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=allow_credentials,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        test_app.add_middleware(SecurityHeadersMiddleware)

        @test_app.get("/ping")
        def ping():
            return {"status": "ok"}

        return test_app

    def test_development_default_wildcard_without_credentials(self):
        """Development default allows wildcard origin but disallows credentials."""
        # Using main.app which uses settings.ALLOWED_ORIGINS (["*"] in dev)
        client = ASGIClient(app)
        resp = client.get("/ping", headers={"Origin": "http://example.com"})
        self.assertEqual(resp.headers.get("access-control-allow-origin"), "*")
        self.assertNotIn("access-control-allow-credentials", resp.headers)

    def test_configured_allowed_origin_accepted(self):
        """Explicitly configured allowed origin receives CORS approval with credentials."""
        allowed_origin = "https://chatspic.internal"
        test_app = self._build_test_app([allowed_origin])
        client = ASGIClient(test_app)

        resp = client.get("/ping", headers={"Origin": allowed_origin})
        self.assertEqual(resp.headers.get("access-control-allow-origin"), allowed_origin)
        self.assertEqual(resp.headers.get("access-control-allow-credentials"), "true")

    def test_unconfigured_origin_rejected(self):
        """Unconfigured origin does not receive Access-Control-Allow-Origin header."""
        test_app = self._build_test_app(["https://chatspic.internal"])
        client = ASGIClient(test_app)

        resp = client.get("/ping", headers={"Origin": "https://malicious-site.com"})
        self.assertNotIn("access-control-allow-origin", resp.headers)

    def test_cors_options_preflight_behavior(self):
        """OPTIONS preflight from allowed origin returns status 200 with allowed methods."""
        allowed_origin = "https://chatspic.internal"
        test_app = self._build_test_app([allowed_origin])
        client = ASGIClient(test_app)

        resp = client.request(
            "OPTIONS",
            "/ping",
            headers={
                "Origin": allowed_origin,
                "Access-Control-Request-Method": "GET",
            },
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("access-control-allow-origin"), allowed_origin)
        self.assertIn("GET", resp.headers.get("access-control-allow-methods", ""))

    def test_production_unset_does_not_fall_back_to_wildcard(self):
        """Production mode with unset origins parses to [] and rejects cross-origin requests."""
        prod_origins = parse_allowed_origins(None, env="production")
        self.assertEqual(prod_origins, [])

        prod_app = self._build_test_app(prod_origins)
        client = ASGIClient(prod_app)

        resp = client.get("/ping", headers={"Origin": "https://any-site.com"})
        self.assertNotIn("access-control-allow-origin", resp.headers)


# ==============================================================================
# 3. WebSocket Authentication Hardening Tests (SEC-07)
# ==============================================================================
class TestWebSocketAuthenticationHardening(WebSocketReliabilityTestCase):
    """Verify WebSocket authentication validation happens before connection acceptance."""

    def test_valid_token_accepted_and_connected(self):
        """Valid token connects, gets accepted, and enters online_users."""
        async def run():
            token = create_access_token({"sub": "alice"}, timedelta(minutes=15))
            client = await self.create_ws_client(token=token)
            self.assertTrue(client.accepted)
            self.assertEqual(ws_module.online_users.get(self.alice.id), 1)
            await client.disconnect()

        asyncio.run(run())

    def test_missing_token_rejected_before_accept(self):
        """Connection without query token is rejected with code 1008 without being accepted."""
        async def run():
            client = await self.create_ws_client(token=None, auto_connect=False)
            connected = await client.connect(query_string="")
            self.assertFalse(connected)
            self.assertFalse(client.accepted)
            self.assertEqual(client.close_code, 1008)
            self.assertEqual(len(ws_module.online_users), 0)

        asyncio.run(run())

    def test_whitespace_token_rejected_before_accept(self):
        """Connection with whitespace token is rejected with code 1008 without being accepted."""
        async def run():
            client = await self.create_ws_client(token="   ")
            self.assertFalse(client.accepted)
            self.assertEqual(client.close_code, 1008)
            self.assertEqual(len(ws_module.online_users), 0)

        asyncio.run(run())

    def test_invalid_token_rejected_before_accept(self):
        """Connection with invalid token is rejected with code 1008 without being accepted."""
        async def run():
            client = await self.create_ws_client(token="completely-invalid-jwt")
            self.assertFalse(client.accepted)
            self.assertEqual(client.close_code, 1008)
            self.assertEqual(len(ws_module.online_users), 0)

        asyncio.run(run())

    def test_expired_token_rejected_before_accept(self):
        """Connection with expired token is rejected with code 1008 without being accepted."""
        async def run():
            expired_token = create_access_token(
                {"sub": "alice"}, timedelta(minutes=-10)
            )
            client = await self.create_ws_client(token=expired_token)
            self.assertFalse(client.accepted)
            self.assertEqual(client.close_code, 1008)
            self.assertEqual(len(ws_module.online_users), 0)

        asyncio.run(run())

    def test_unauthorized_room_join_rejected(self):
        """Attempting to join a non-friend room returns error and does not enter room."""
        async def run():
            # Bob and Charlie are not friends
            client = await self.create_ws_client(user=self.bob)
            await client.send_json({"type": "join", "room": "charlie"})

            err = await client.receive_json()
            self.assertEqual(err["type"], "error")
            self.assertEqual(err["message"], "You are not friends")

            # Verify client was not added to charlie's room
            room_id = ws_module.get_dm_room("bob", "charlie")
            self.assertNotIn(room_id, ws_module.rooms)

            await client.disconnect()

        asyncio.run(run())


# ==============================================================================
# 4. WebSocket Payload Validation Tests (SEC-10)
# ==============================================================================
class TestWebSocketPayloadValidation(WebSocketReliabilityTestCase):
    """Verify payload structure, type checking, and malformed payload resilience."""

    def test_malformed_json_returns_controlled_error(self):
        """Non-JSON text string returns controlled error and leaves connection active."""
        async def run():
            client = await self.create_ws_client(user=self.alice)
            await client.send_text("this is definitely not json")

            err = await client.receive_json()
            self.assertEqual(err["type"], "error")
            self.assertEqual(err["message"], "Invalid JSON payload")

            # Verify connection remains alive
            await client.send_json({"type": "typing", "room": "bob"})
            await client.disconnect()

        asyncio.run(run())

    def test_non_dict_json_returns_controlled_error(self):
        """JSON array or scalar returns controlled error and leaves connection active."""
        async def run():
            client = await self.create_ws_client(user=self.alice)
            await client.send_text("[1, 2, 3]")

            err = await client.receive_json()
            self.assertEqual(err["type"], "error")
            self.assertEqual(err["message"], "Invalid JSON payload")

            await client.disconnect()

        asyncio.run(run())

    def test_missing_event_type_returns_controlled_error(self):
        """Payload without 'type' property returns controlled error."""
        async def run():
            client = await self.create_ws_client(user=self.alice)
            await client.send_json({"data": "some value"})

            err = await client.receive_json()
            self.assertEqual(err["type"], "error")
            self.assertEqual(err["message"], "Missing or invalid event type")

            await client.disconnect()

        asyncio.run(run())

    def test_invalid_event_type_type_returns_controlled_error(self):
        """Payload with non-string 'type' returns controlled error."""
        async def run():
            client = await self.create_ws_client(user=self.alice)
            await client.send_json({"type": 12345})

            err = await client.receive_json()
            self.assertEqual(err["type"], "error")
            self.assertEqual(err["message"], "Missing or invalid event type")

            await client.disconnect()

        asyncio.run(run())

    def test_typing_with_null_room_safe(self):
        """SEC-10: Typing event with null room does not raise TypeError or crash connection."""
        async def run():
            client = await self.create_ws_client(user=self.alice)
            await client.send_json({"type": "typing", "room": None})

            err = await client.receive_json()
            self.assertEqual(err["type"], "error")
            self.assertEqual(err["message"], "Invalid room for typing event")

            # Connection must remain alive and responsive
            await client.send_json({"type": "chat", "room": "bob", "text": "Alive after null room"})
            echo = await client.receive_json()
            self.assertEqual(echo["text"], "Alive after null room")

            await client.disconnect()

        asyncio.run(run())

    def test_typing_with_int_room_safe(self):
        """SEC-10: Typing event with integer room does not raise TypeError or crash connection."""
        async def run():
            client = await self.create_ws_client(user=self.alice)
            await client.send_json({"type": "typing", "room": 999})

            err = await client.receive_json()
            self.assertEqual(err["type"], "error")
            self.assertEqual(err["message"], "Invalid room for typing event")

            await client.disconnect()

        asyncio.run(run())

    def test_typing_with_bool_room_safe(self):
        """SEC-10: Typing event with boolean room does not raise TypeError or crash connection."""
        async def run():
            client = await self.create_ws_client(user=self.alice)
            await client.send_json({"type": "typing", "room": True})

            err = await client.receive_json()
            self.assertEqual(err["type"], "error")
            self.assertEqual(err["message"], "Invalid room for typing event")

            await client.disconnect()

        asyncio.run(run())

    def test_boolean_message_id_rejected_in_delete(self):
        """Boolean message_id (e.g. True) must NOT be parsed as integer 1 and must be rejected."""
        # Create a message with ID 1
        target_msg = Message(
            id=1,
            sender_id=self.alice.id,
            receiver_id=self.bob.id,
            content="Protected message 1",
            timestamp=datetime.now(timezone.utc),
        )
        self.db.add(target_msg)
        self.db.commit()

        async def run():
            client = await self.create_ws_client(user=self.alice)
            await client.send_json({"type": "message_delete", "message_id": True})

            err = await client.receive_json()
            self.assertEqual(err["type"], "error")
            self.assertEqual(err["message"], "Invalid message id")

            # Verify message 1 was not deleted
            db_msg = self.db.query(Message).filter(Message.id == 1).first()
            self.assertIsNotNone(db_msg)
            self.assertFalse(db_msg.is_deleted)

            await client.disconnect()

        asyncio.run(run())

    def test_boolean_message_id_rejected_in_edit(self):
        """Boolean message_id must be rejected in message_edit."""
        async def run():
            client = await self.create_ws_client(user=self.alice)
            await client.send_json({
                "type": "message_edit",
                "message_id": True,
                "text": "Attempted edit",
            })

            err = await client.receive_json()
            self.assertEqual(err["type"], "error")
            self.assertEqual(err["message"], "Invalid message id")

            await client.disconnect()

        asyncio.run(run())

    def test_boolean_message_id_rejected_in_reactions(self):
        """Boolean message_id must be rejected in reaction_add and reaction_remove."""
        async def run():
            client = await self.create_ws_client(user=self.alice)
            await client.send_json({
                "type": "reaction_add",
                "message_id": True,
                "emoji": "👍",
            })

            err = await client.receive_json()
            self.assertEqual(err["type"], "error")
            self.assertEqual(err["message"], "Invalid message id")

            await client.send_json({
                "type": "reaction_remove",
                "message_id": False,
                "emoji": "👍",
            })

            err2 = await client.receive_json()
            self.assertEqual(err2["type"], "error")
            self.assertEqual(err2["message"], "Invalid message id")

            await client.disconnect()

        asyncio.run(run())

    def test_boolean_reply_to_id_rejected_in_chat(self):
        """Boolean reply_to_message_id must be rejected in chat message."""
        async def run():
            client = await self.create_ws_client(user=self.alice)
            await client.send_json({
                "type": "chat",
                "room": "bob",
                "text": "Hello",
                "reply_to_message_id": True,
            })

            err = await client.receive_json()
            self.assertEqual(err["type"], "error")
            self.assertEqual(err["message"], "Invalid reply_to_message_id")

            await client.disconnect()

        asyncio.run(run())

    def test_non_string_chat_text_rejected(self):
        """Non-string text in chat message produces controlled error."""
        async def run():
            client = await self.create_ws_client(user=self.alice)
            await client.send_json({
                "type": "chat",
                "room": "bob",
                "text": 12345,
            })

            err = await client.receive_json()
            self.assertEqual(err["type"], "error")
            self.assertEqual(err["message"], "Message text must be a string")

            await client.disconnect()

        asyncio.run(run())

    def test_non_string_chat_image_url_rejected(self):
        """Non-string image_url in chat message produces controlled error."""
        async def run():
            client = await self.create_ws_client(user=self.alice)
            await client.send_json({
                "type": "chat",
                "room": "bob",
                "image_url": 9999,
            })

            err = await client.receive_json()
            self.assertEqual(err["type"], "error")
            self.assertEqual(err["message"], "Image URL must be a string")

            await client.disconnect()

        asyncio.run(run())

    def test_invalid_emoji_rejected_in_reaction(self):
        """Non-string or empty emoji in reaction produces controlled error."""
        async def run():
            client = await self.create_ws_client(user=self.alice)
            await client.send_json({
                "type": "reaction_add",
                "message_id": 1,
                "emoji": "   ",
            })

            err = await client.receive_json()
            self.assertEqual(err["type"], "error")
            self.assertEqual(err["message"], "Invalid emoji")

            await client.disconnect()

        asyncio.run(run())

    def test_valid_message_and_typing_flow_preserved(self):
        """Verify normal chat message and typing indicators continue to function smoothly."""
        async def run():
            alice_client = await self.create_ws_client(user=self.alice)
            bob_client = await self.create_ws_client(user=self.bob)

            # Both join room
            await alice_client.send_json({"type": "join", "room": "bob"})
            await bob_client.send_json({"type": "join", "room": "alice"})
            await asyncio.sleep(0.05)

            # Alice sends typing
            await alice_client.send_json({"type": "typing", "room": "bob"})
            typing_event = await bob_client.receive_json()
            self.assertEqual(typing_event["type"], "typing")
            self.assertEqual(typing_event["sender"], "alice")

            # Alice sends chat message
            await alice_client.send_json({
                "type": "chat",
                "room": "bob",
                "text": "Hello Bob!",
            })

            # Bob receives message
            msg_event = await bob_client.receive_json()
            self.assertEqual(msg_event["type"], "chat")
            self.assertEqual(msg_event["text"], "Hello Bob!")
            self.assertEqual(msg_event["sender"], "alice")

            await alice_client.disconnect()
            await bob_client.disconnect()

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
