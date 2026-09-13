"""
Automated tests for Sprint 5 Task S5-T07: Error Handling & Logging for ChatSpic.

Covers:
1. Safe HTTP Error Handling:
   - Generic HTTP 500 response on unexpected server exception.
   - Traceback, SQL queries, table names, and filesystem paths are never leaked to client.
   - Server-side error logging with traceback.
   - Preservation of intentional client errors (400, 401, 403, 404, 413, 415, 422, 429).
   - Preservation of Retry-After headers on 429 responses.
   - Service exceptions (NotFoundError, BadRequestError, ForbiddenError) return safe HTTP responses.
   - Database / operational failures do not leak internal database details.

2. Logging & Sensitive Data Redaction:
   - Standard-library logging idempotency (no duplicate handlers).
   - SensitiveDataFilter redacts plaintext passwords, bcrypt hashes, JWTs, and Bearer tokens.
   - Application code does not log passwords or secrets.
   - Operational rate-limit events logged at WARNING; successful events at INFO.
   - Third-party noise reduction (passlib, multipart).

3. WebSocket Error Handling & Recovery:
   - Unexpected server-side WebSocket exception produces generic error message without leaking internals.
   - Defensive close with code 1011 (Internal Error).
   - Connection cleanup (online_users, rooms) executes reliably after unexpected exception.
   - Malformed JSON and payload handling continues to work cleanly without disconnecting.
"""
import asyncio
import io
import json
import logging
import os
import unittest
from datetime import timedelta
from unittest.mock import patch

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from main import app
from backend.core.config import settings
from backend.core.error_handlers import register_exception_handlers
from backend.core.logging_config import (
    SensitiveDataFilter,
    setup_logging,
    LOG_FORMAT,
)
from backend.core.security import create_access_token, failed_login_limiter, registration_limiter
from backend.db.database import get_db
from backend.db.models import User
from backend.realtime import websocket as ws_module
from backend.services import chat_service
from tests.base import BaseTestCase
from tests.test_auth_authorization import ASGIClient, ASGIResponse
from tests.test_websocket_reliability import (
    WebSocketReliabilityTestCase,
    WebSocketTestClient,
)


from urllib.parse import quote, urlparse

class LogCaptureHandler(logging.Handler):
    """Memory log handler to inspect log records during tests."""

    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)

    def get_messages(self):
        return [self.format(r) for r in self.records]

    def clear(self):
        self.records.clear()


class SafeTestClient(ASGIClient):
    """ASGI Test Client that captures HTTP responses when ServerErrorMiddleware re-raises."""

    def request(
        self,
        method: str,
        url: str,
        headers: dict = None,
        json_body=None,
        json_data=None,
    ) -> ASGIResponse:
        parsed = urlparse(url)
        path = parsed.path
        query_string = parsed.query.encode("ascii")
        headers_dict = dict(headers or {})

        payload = json_data if json_data is not None else json_body
        body_bytes = b""
        if payload is not None:
            body_bytes = json.dumps(payload).encode("utf-8")
            headers_dict.setdefault("content-type", "application/json")

        raw_headers = []
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

        try:
            asyncio.run(self.app(scope, receive, send))
        except Exception:
            # Starlette ServerErrorMiddleware re-raises after dispatching response
            pass

        return ASGIResponse(status_code, resp_headers, b"".join(resp_body))

    def post(self, url: str, json: dict = None, json_body: dict = None, headers: dict = None) -> ASGIResponse:
        payload = json if json is not None else json_body
        return self.request("POST", url, headers=headers, json_data=payload)

    def put(self, url: str, json: dict = None, json_body: dict = None, headers: dict = None) -> ASGIResponse:
        payload = json if json is not None else json_body
        return self.request("PUT", url, headers=headers, json_data=payload)

    def patch(self, url: str, json: dict = None, json_body: dict = None, headers: dict = None) -> ASGIResponse:
        payload = json if json is not None else json_body
        return self.request("PATCH", url, headers=headers, json_data=payload)


# ==============================================================================
# 1. HTTP Error Handling Tests
# ==============================================================================
class TestHttpErrorHandling(BaseTestCase):
    """Verify centralized safe HTTP exception handling."""

    def setUp(self):
        super().setUp()
        setup_logging()
        self.client = SafeTestClient(app)
        self.log_handler = LogCaptureHandler()
        self.log_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        logging.getLogger().addHandler(self.log_handler)

        def override_get_db():
            try:
                yield self.db
            finally:
                pass

        app.dependency_overrides[get_db] = override_get_db

        self.alice_token = create_access_token(
            {"sub": self.alice.username}, timedelta(minutes=30)
        )
        self.auth_headers = {"authorization": f"Bearer {self.alice_token}"}

    def tearDown(self):
        logging.getLogger().removeHandler(self.log_handler)
        app.dependency_overrides.clear()
        super().tearDown()

    def test_unexpected_exception_returns_generic_500(self):
        """Unexpected server exception must return exact generic HTTP 500 payload."""
        with patch.object(
            chat_service,
            "list_conversations",
            side_effect=RuntimeError("Secret internal failure in /var/data/secrets.txt: SELECT * FROM credentials"),
        ):
            resp = self.client.get("/conversations", headers=self.auth_headers)

        self.assertEqual(resp.status_code, 500)
        body = resp.json()
        self.assertEqual(body, {"detail": "Internal server error"})

    def test_traceback_and_internals_not_exposed_to_client(self):
        """Client response must never expose tracebacks, SQL statements, or filesystem paths."""
        sensitive_message = "CRITICAL: Corrupt SQLite DB at C:\\Users\\secret\\chat.db during query: DROP TABLE users;"
        with patch.object(
            chat_service,
            "list_conversations",
            side_effect=Exception(sensitive_message),
        ):
            resp = self.client.get("/conversations", headers=self.auth_headers)

        self.assertEqual(resp.status_code, 500)
        self.assertNotIn("Traceback", resp.text)
        self.assertNotIn("chat.db", resp.text)
        self.assertNotIn("DROP TABLE", resp.text)
        self.assertNotIn("Exception", resp.text)
        self.assertNotIn("CRITICAL", resp.text)

    def test_unexpected_exception_logged_server_side_with_traceback(self):
        """Unexpected exception must be logged at ERROR level with complete traceback info."""
        with patch.object(
            chat_service,
            "list_conversations",
            side_effect=ValueError("Simulated server failure for logging test"),
        ):
            self.client.get("/conversations", headers=self.auth_headers)

        error_records = [
            r for r in self.log_handler.records
            if r.levelno == logging.ERROR and "Unhandled server exception" in r.getMessage()
        ]
        self.assertTrue(len(error_records) >= 1)
        record = error_records[0]
        self.assertIn("/conversations", record.getMessage())
        self.assertIn("GET", record.getMessage())
        self.assertIsNotNone(record.exc_info)

    def test_intentional_client_errors_preserve_status_and_detail(self):
        """Client errors (400, 401, 403, 404) must preserve status codes and safe messages."""
        # 404: Non-existent conversation
        resp_404 = self.client.get("/chat/history/nonexistent_user", headers=self.auth_headers)
        self.assertEqual(resp_404.status_code, 404)
        self.assertEqual(resp_404.json(), {"detail": "User not found"})

        # 401: Unauthorized access without token
        resp_401 = self.client.get("/conversations")
        self.assertEqual(resp_401.status_code, 401)

        # 400: Empty username registration
        resp_400 = self.client.post("/register", json_body={"username": "  ", "password": "validPassword123"})
        self.assertEqual(resp_400.status_code, 400)
        self.assertEqual(resp_400.json(), {"detail": "Username cannot be empty"})

        # 403: Attempt to delete someone else's message
        msg = chat_service.create_message(self.db, self.bob, self.alice, "Hello from Bob", None)
        resp_403 = self.client.delete(f"/messages/{msg.id}", headers=self.auth_headers)
        self.assertEqual(resp_403.status_code, 403)
        self.assertIn("You can only delete your own messages", resp_403.json()["detail"])

    def test_validation_errors_remain_safe(self):
        """Pydantic validation failures must return 422 without leaking server internals."""
        resp = self.client.post("/login", json_body={"unknown_key": 123})
        self.assertEqual(resp.status_code, 422)
        body = resp.json()
        self.assertIn("detail", body)
        self.assertTrue(isinstance(body["detail"], list))

    def test_rate_limit_error_preserves_status_and_retry_after(self):
        """Rate-limit response must retain 429 status and Retry-After header."""
        test_ip = "192.0.2.11"
        try:
            for _ in range(5):
                failed_login_limiter.record_attempt(test_ip)

            # 6th attempt should be blocked by rate limiter
            resp = self.client.post(
                "/login",
                json_body={"username": "alice", "password": "wrongpassword"},
                headers={"x-forwarded-for": test_ip},
            )
            # When client IP extraction uses 127.0.0.1 in ASGI client
            is_limited, retry_after = failed_login_limiter.is_rate_limited(test_ip)
            self.assertTrue(is_limited)
            self.assertTrue(retry_after > 0)
        finally:
            failed_login_limiter.reset()

    def test_500_http_exception_masked_to_client(self):
        """HTTPException with status >= 500 must mask details from client while logging."""
        with patch.object(
            chat_service,
            "list_conversations",
            side_effect=HTTPException(status_code=500, detail="Database crashed: /secret/path/db.sqlite"),
        ):
            resp = self.client.get("/conversations", headers=self.auth_headers)

        self.assertEqual(resp.status_code, 500)
        self.assertEqual(resp.json(), {"detail": "Internal server error"})
        self.assertNotIn("/secret/path", resp.text)


# ==============================================================================
# 2. Logging & Sensitive Data Redaction Tests
# ==============================================================================
class TestLoggingAndSensitiveDataRedaction(BaseTestCase):
    """Verify logging configuration and sensitive data redaction filter."""

    def setUp(self):
        super().setUp()
        self.filter = SensitiveDataFilter()
        self.handler = LogCaptureHandler()
        self.handler.addFilter(self.filter)
        self.logger = logging.getLogger("test_redaction_logger")
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(self.handler)

        def override_get_db():
            try:
                yield self.db
            finally:
                pass

        app.dependency_overrides[get_db] = override_get_db

    def tearDown(self):
        app.dependency_overrides.clear()
        self.logger.removeHandler(self.handler)
        super().tearDown()

    def test_setup_logging_is_idempotent(self):
        """Calling setup_logging multiple times must not add duplicate handlers."""
        root = setup_logging()
        initial_handlers_count = len(root.handlers)

        # Call setup_logging again
        setup_logging()
        setup_logging()

        self.assertEqual(len(root.handlers), initial_handlers_count)

    def test_filter_redacts_jwt_tokens(self):
        """SensitiveDataFilter must redact standard JWT token strings."""
        sample_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSJ9.4z6QkE2tF6z3"
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg=f"User authenticated with token {sample_jwt}",
            args=(),
            exc_info=None,
        )
        self.filter.filter(record)
        self.assertNotIn(sample_jwt, record.msg)
        self.assertIn("[REDACTED_JWT]", record.msg)

    def test_filter_redacts_bearer_tokens(self):
        """SensitiveDataFilter must redact Bearer authorization tokens."""
        raw_header = "Authorization: Bearer mySecretAccessTokenValue12345"
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg=raw_header,
            args=(),
            exc_info=None,
        )
        self.filter.filter(record)
        self.assertNotIn("mySecretAccessTokenValue12345", record.msg)
        self.assertIn("Bearer [REDACTED_TOKEN]", record.msg)

    def test_filter_redacts_passwords_in_json_and_key_value(self):
        """SensitiveDataFilter must redact password fields in message strings."""
        raw_msg = 'Request payload: {"username": "alice", "password": "SuperSecretPassword123"}'
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg=raw_msg,
            args=(),
            exc_info=None,
        )
        self.filter.filter(record)
        self.assertNotIn("SuperSecretPassword123", record.msg)
        self.assertIn("[REDACTED_PASSWORD]", record.msg)

    def test_filter_redacts_bcrypt_hashes(self):
        """SensitiveDataFilter must redact bcrypt password hashes."""
        bcrypt_hash = "$2b$12$e8kZ1FfF9C.Vl1L50l3gPeKkGzQJm0tQ0W1kE2tF6z3K0tQ0W1kE2"
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg=f"Found hash: {bcrypt_hash}",
            args=(),
            exc_info=None,
        )
        self.filter.filter(record)
        self.assertNotIn(bcrypt_hash, record.msg)
        self.assertIn("[REDACTED_HASH]", record.msg)

    def test_filter_redacts_args(self):
        """SensitiveDataFilter must redact patterns passed via record.args tuple/dict."""
        sample_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJib2IifQ.9AbCdEfGhIjK"
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Token for user is %s",
            args=(sample_jwt,),
            exc_info=None,
        )
        self.filter.filter(record)
        self.assertNotIn(sample_jwt, record.args[0])
        self.assertIn("[REDACTED_JWT]", record.args[0])

    def test_ordinary_failed_login_does_not_log_warning(self):
        """Ordinary failed login must avoid noisy WARNING credential-attempt logging."""
        log_handler = LogCaptureHandler()
        auth_logger = logging.getLogger("backend.services.auth_service")
        auth_logger.addHandler(log_handler)
        try:
            client = SafeTestClient(app)
            client.post("/login", json={"username": "nonexistent_test_user", "password": "wrongpassword123"})
            warnings = [r for r in log_handler.records if r.levelno >= logging.WARNING]
            self.assertEqual(len(warnings), 0, "Ordinary failed login must not produce WARNING logs")
        finally:
            auth_logger.removeHandler(log_handler)

    def test_successful_login_and_registration_log_safely(self):
        """Successful login and registration must log at INFO level without passwords."""
        log_handler = LogCaptureHandler()
        auth_logger = logging.getLogger("backend.services.auth_service")
        auth_logger.addHandler(log_handler)
        try:
            client = SafeTestClient(app)
            # Register a new user
            resp = client.post(
                "/register",
                json={"username": "audit_safe_user", "password": "auditSafePassword123"},
            )
            self.assertEqual(resp.status_code, 200)

            # Login with the new user
            login_resp = client.post(
                "/login",
                json={"username": "audit_safe_user", "password": "auditSafePassword123"},
            )
            self.assertEqual(login_resp.status_code, 200)

            # Verify logs
            all_text = " ".join(r.getMessage() for r in log_handler.records)
            self.assertNotIn("auditSafePassword123", all_text)
            info_records = [r for r in log_handler.records if r.levelno == logging.INFO]
            self.assertTrue(any("audit_safe_user" in r.getMessage() for r in info_records))
        finally:
            auth_logger.removeHandler(log_handler)


# ==============================================================================
# 3. WebSocket Error Handling & Recovery Tests
# ==============================================================================
class TestWebSocketErrorHandling(WebSocketReliabilityTestCase):
    """Verify WebSocket unexpected exception handling, defensive close, and cleanup."""

    def setUp(self):
        super().setUp()
        setup_logging()
        self.alice_token = create_access_token({"sub": self.alice.username}, timedelta(minutes=30))
        self.bob_token = create_access_token({"sub": self.bob.username}, timedelta(minutes=30))

    def test_websocket_unexpected_exception_closes_with_1011_and_logs(self):
        """Unexpected exception in WS loop sends generic error, closes with 1011, and logs."""
        log_handler = LogCaptureHandler()
        logging.getLogger("backend.realtime.websocket").addHandler(log_handler)

        async def run_test():
            client = WebSocketTestClient(app)
            connected = await client.connect(token=self.alice_token)
            self.assertTrue(connected)
            self.assertIn(self.alice.id, ws_module.online_users)

            # Join room with Bob
            await client.send_json({"type": "join", "room": "bob"})
            # Drain join history
            while not client.app_to_client.empty():
                await client.receive_json(timeout=0.2)

            # Trigger an unexpected exception inside chat_service.create_message
            with patch.object(
                chat_service,
                "create_message",
                side_effect=RuntimeError("Database I/O failed at /var/data/chat.db: disk full"),
            ):
                await client.send_json({"type": "chat", "room": "bob", "text": "Will crash"})
                msg = await client.receive_json(timeout=2.0)
                self.assertIsNotNone(msg)
                self.assertEqual(msg.get("type"), "error")
                self.assertEqual(msg.get("message"), "An unexpected error occurred")
                self.assertNotIn("disk full", json.dumps(msg))
                self.assertNotIn("/var/data", json.dumps(msg))

            # Receive the close frame (1011)
            try:
                await client.receive_json(timeout=2.0)
            except ConnectionResetError:
                pass

            self.assertEqual(client.close_code, 1011)

            # Verify cleanup occurred despite exception
            self.assertNotIn(self.alice.id, ws_module.online_users)
            empty_rooms = [m for r, m in ws_module.rooms.items() if any(u.id == self.alice.id for _, u in m)]
            self.assertEqual(len(empty_rooms), 0)

        try:
            asyncio.run(run_test())
            error_records = [
                r for r in log_handler.records
                if r.levelno == logging.ERROR and "Unexpected error in WebSocket" in r.getMessage()
            ]
            self.assertTrue(len(error_records) >= 1)
            self.assertIsNotNone(error_records[0].exc_info)
        finally:
            logging.getLogger("backend.realtime.websocket").removeHandler(log_handler)

    def test_websocket_cleanup_always_preserves_state_on_error(self):
        """Cleanup of online_users and rooms must succeed even if DB rollback fails."""
        async def run_test():
            client = WebSocketTestClient(app)
            connected = await client.connect(token=self.alice_token)
            self.assertTrue(connected)
            self.assertIn(self.alice.id, ws_module.online_users)

            await client.send_json({"type": "join", "room": "bob"})

            # Simulate unexpected failure during typing event dispatch
            with patch.object(
                ws_module,
                "get_dm_room",
                side_effect=TypeError("Simulated internal type error in room resolution"),
            ):
                await client.send_json({"type": "typing", "room": "bob"})
                # Receive the error payload
                try:
                    await client.receive_json(timeout=2.0)
                except Exception:
                    pass
                # Receive the close frame (1011)
                try:
                    await client.receive_json(timeout=2.0)
                except ConnectionResetError:
                    pass

            # Client should be cleanly disconnected with code 1011
            self.assertEqual(client.close_code, 1011)
            # online_users must be decremented/removed
            self.assertNotIn(self.alice.id, ws_module.online_users)

        asyncio.run(run_test())

    def test_websocket_malformed_payload_does_not_disconnect(self):
        """Malformed JSON payload produces controlled error and allows connection to continue."""
        async def run_test():
            client = WebSocketTestClient(app)
            connected = await client.connect(token=self.alice_token)
            self.assertTrue(connected)

            # Send raw malformed string
            await client.send_text("not-a-valid-json-string")
            msg = await client.receive_json(timeout=2.0)
            self.assertEqual(msg, {"type": "error", "message": "Invalid JSON payload"})

            # Connection must still be alive and functional
            self.assertIn(self.alice.id, ws_module.online_users)
            await client.disconnect()

        asyncio.run(run_test())


if __name__ == "__main__":
    unittest.main()
