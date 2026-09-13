"""
Focused Security Regression and Hardening Tests for Sprint 5 Task S5-T10.

Covers:
1. Uvicorn formatted access-log credential redaction:
   - Formatted output does not expose WebSocket query-string JWT.
   - Non-sensitive query parameters (room, client, version, etc.) are preserved.
   - Arbitrary/non-JWT secret tokens in query strings are redacted.
   - Uvicorn error logger redacts credentials.
   - setup_logging idempotency on uvicorn loggers without duplicate filters.
2. Production configuration hardening:
   - Production mode rejects in-memory SQLite database (:memory:, sqlite:///:memory:).
   - Development and test modes preserve in-memory database support.
3. WebSocket runtime integration:
   - WebSocket authentication and connection acceptance still work with valid token.
   - Pre-accept rejection (1008) remains enforced for missing or invalid tokens.
"""

import io
import logging
import re
import unittest
from unittest.mock import patch

from datetime import timedelta
from uvicorn.logging import AccessFormatter, DefaultFormatter

from backend.core.config import Settings
from backend.core.logging_config import SensitiveDataFilter, setup_logging
from backend.core.security import create_access_token, hash_password
from backend.db.database import get_db
from backend.db.models import User
from main import app
from tests.base import BaseTestCase


class TestUvicornAccessLogRedaction(unittest.TestCase):
    """Verify that Uvicorn formatted access log output never exposes credentials."""

    def setUp(self):
        # Initialize logging as performed at startup
        setup_logging()
        self.uv_access = logging.getLogger("uvicorn.access")
        self.uv_error = logging.getLogger("uvicorn.error")

        # Capture formatted log output with Uvicorn's actual AccessFormatter
        self.log_stream = io.StringIO()
        self.access_handler = logging.StreamHandler(self.log_stream)
        self.access_handler.setFormatter(AccessFormatter(fmt='%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s', use_colors=False))
        self.uv_access.addHandler(self.access_handler)

        # Capture formatted error output with Uvicorn's actual DefaultFormatter
        self.error_stream = io.StringIO()
        self.error_handler = logging.StreamHandler(self.error_stream)
        self.error_handler.setFormatter(DefaultFormatter(fmt="%(levelprefix)s %(message)s", use_colors=False))
        self.uv_error.addHandler(self.error_handler)

        self.sample_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsImV4cCI6MTk5OTk5OTk5OX0.abc123def456_sig_value"

    def tearDown(self):
        self.uv_access.removeHandler(self.access_handler)
        self.uv_error.removeHandler(self.error_handler)

    def test_websocket_jwt_query_param_redacted_in_formatted_access_log(self):
        """A /ws?token=<JWT> request must not emit the JWT in formatted Uvicorn access log output."""
        self.uv_access.info(
            '%s - "%s %s HTTP/%s" %d',
            "127.0.0.1:54321",
            "GET",
            f"/ws?token={self.sample_jwt}",
            "1.1",
            101,
        )
        output = self.log_stream.getvalue()

        # The raw JWT token must NEVER appear anywhere in the output
        self.assertNotIn(self.sample_jwt, output)
        self.assertNotIn("abc123def456_sig_value", output)

        # Redaction indicator must be present
        self.assertTrue(
            "[REDACTED_TOKEN]" in output or "[REDACTED_JWT]" in output,
            f"Expected redaction marker in log output: {output!r}",
        )

        # Non-sensitive request info must be preserved
        self.assertIn("127.0.0.1:54321", output)
        self.assertIn("GET", output)
        self.assertIn("/ws?token=", output)
        self.assertIn("HTTP/1.1", output)
        self.assertIn("101", output)

    def test_multiple_query_params_preserves_nonsensitive_data(self):
        """Token query param is redacted while sibling query params are fully preserved."""
        self.uv_access.info(
            '%s - "%s %s HTTP/%s" %d',
            "192.168.1.42:50000",
            "GET",
            f"/ws?room=general&token={self.sample_jwt}&client=desktop&version=2.1",
            "1.1",
            101,
        )
        output = self.log_stream.getvalue()

        # Secret token must not be in log
        self.assertNotIn(self.sample_jwt, output)

        # Non-sensitive parameters and context must remain intact
        self.assertIn("192.168.1.42:50000", output)
        self.assertIn("room=general", output)
        self.assertIn("token=[REDACTED_TOKEN]", output)
        self.assertIn("client=desktop", output)
        self.assertIn("version=2.1", output)
        self.assertIn("101", output)

    def test_non_jwt_arbitrary_token_redacted(self):
        """Arbitrary, non-JWT token parameters in query string are also redacted."""
        arbitrary_token = "my_custom_secret_key_99887766"
        self.uv_access.info(
            '%s - "%s %s HTTP/%s" %d',
            "10.0.0.1:8080",
            "GET",
            f"/api/resource?token={arbitrary_token}&format=json",
            "1.1",
            200,
        )
        output = self.log_stream.getvalue()

        self.assertNotIn(arbitrary_token, output)
        self.assertIn("token=[REDACTED_TOKEN]", output)
        self.assertIn("format=json", output)
        self.assertIn("200", output)

    def test_uvicorn_error_logger_redaction(self):
        """Uvicorn error logger sanitizes credentials logged during errors."""
        self.uv_error.error(
            "Connection failed for token: %s and password: password='supersecret'",
            self.sample_jwt,
        )
        output = self.error_stream.getvalue()

        self.assertNotIn(self.sample_jwt, output)
        self.assertNotIn("supersecret", output)
        self.assertTrue("[REDACTED_JWT]" in output or "[REDACTED_TOKEN]" in output)
        self.assertIn("[REDACTED_PASSWORD]", output)

    def test_setup_logging_idempotency_no_duplicate_filters(self):
        """Repeated calls to setup_logging do not stack duplicate filters on uvicorn loggers."""
        for _ in range(3):
            setup_logging()

        for name in ("uvicorn.access", "uvicorn.error", "uvicorn"):
            logger = logging.getLogger(name)
            sensitive_filters = [f for f in logger.filters if isinstance(f, SensitiveDataFilter)]
            self.assertEqual(
                len(sensitive_filters),
                1,
                f"Logger {name} has {len(sensitive_filters)} SensitiveDataFilter instances, expected 1",
            )


class TestProductionInMemoryDatabaseRejection(unittest.TestCase):
    """Verify production configuration rejects in-memory SQLite databases."""

    VALID_PROD_SECRET = "a" * 32

    def test_production_rejects_colon_memory(self):
        """Production mode raises RuntimeError when DATABASE_URL is ':memory:'."""
        with self.assertRaises(RuntimeError) as ctx:
            Settings(
                ENVIRONMENT="production",
                SECRET_KEY=self.VALID_PROD_SECRET,
                DATABASE_URL=":memory:",
            )
        self.assertIn("In-memory SQLite database is not permitted in production mode", str(ctx.exception))

    def test_production_rejects_sqlite_memory_url(self):
        """Production mode raises RuntimeError when DATABASE_URL is 'sqlite:///:memory:'."""
        with self.assertRaises(RuntimeError) as ctx:
            Settings(
                ENVIRONMENT="production",
                SECRET_KEY=self.VALID_PROD_SECRET,
                DATABASE_URL="sqlite:///:memory:",
            )
        self.assertIn("In-memory SQLite database is not permitted in production mode", str(ctx.exception))

    def test_production_rejects_shared_memory_url(self):
        """Production mode raises RuntimeError when DATABASE_URL uses shared in-memory SQLite."""
        with self.assertRaises(RuntimeError) as ctx:
            Settings(
                ENVIRONMENT="production",
                SECRET_KEY=self.VALID_PROD_SECRET,
                DATABASE_URL="sqlite:///:memory:?cache=shared",
            )
        self.assertIn("In-memory SQLite database is not permitted in production mode", str(ctx.exception))

    def test_development_and_test_allow_in_memory_database(self):
        """Non-production environments (development, test) continue to support in-memory SQLite."""
        dev_settings = Settings(ENVIRONMENT="development", DATABASE_URL="sqlite:///:memory:")
        self.assertEqual(dev_settings.DATABASE_URL, "sqlite:///:memory:")

        test_settings = Settings(ENVIRONMENT="test", DATABASE_URL="sqlite:///:memory:")
        self.assertEqual(test_settings.DATABASE_URL, "sqlite:///:memory:")


import asyncio
from tests.test_websocket_reliability import WebSocketReliabilityTestCase


class TestWebSocketSecurityRegressionIntegration(WebSocketReliabilityTestCase):
    """Verify WebSocket security integration, authentication, and pre-accept rejection."""

    def test_websocket_accepts_valid_token(self):
        """WebSocket accepts connection with valid authentication token."""
        async def run():
            token = create_access_token(data={"sub": "alice"}, expires_delta=timedelta(minutes=30))
            client = await self.create_ws_client(token=token)
            self.assertTrue(client.accepted)
            self.assertIsNone(client.close_code)
            await client.disconnect()
        asyncio.run(run())

    def test_websocket_rejects_missing_token_before_accept(self):
        """WebSocket rejects connection without token (closes code 1008)."""
        async def run():
            client = await self.create_ws_client(token="")
            self.assertFalse(client.accepted)
            self.assertEqual(client.close_code, 1008)
        asyncio.run(run())

    def test_websocket_rejects_invalid_token_before_accept(self):
        """WebSocket rejects connection with malformed/invalid token (closes code 1008)."""
        async def run():
            client = await self.create_ws_client(token="invalid_malformed_token")
            self.assertFalse(client.accepted)
            self.assertEqual(client.close_code, 1008)
        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
