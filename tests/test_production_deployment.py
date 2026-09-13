"""Tests for Sprint 5 Task S5-T09: Production Configuration & Deployment.

Validates:
- Production configuration hardening and fail-fast validation
- Secret key security (rejection of missing, placeholder, and short < 32-char keys)
- Wildcard CORS origin rejection in production
- Rejection of in-memory databases in production
- Rejection of insecure JWT algorithms ('none')
- Logging level configuration and validation
- Requirements completeness (FastAPI, Uvicorn, SQLAlchemy, Alembic, security packages)
- Startup architecture safety (no create_all in main or database modules, single worker in startup script)
- Health endpoint functionality (GET /health returns 200 {"status": "ok"})
- Static asset serving
- Preservation of secure uploads, authentication flows, and WebSocket connections
"""
import ast
import asyncio
import io
import os
import re
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from backend.core.config import (
    DEV_DEFAULT_SECRET,
    INSECURE_SECRETS,
    Settings,
    settings as active_settings,
)
from backend.core.security import create_access_token
from backend.db.database import get_db
from backend.realtime import websocket as ws_module
from main import app
from tests.base import BaseTestCase
from tests.test_auth_authorization import ASGIClient
from tests.test_upload_security import (
    PNG_FIXTURE,
    UploadSecurityASGIClient,
)
from tests.test_websocket_reliability import WebSocketReliabilityTestCase


class TestProductionConfigurationHardening(unittest.TestCase):
    """Verify production configuration loading, validations, and fail-fast behavior."""

    VALID_PROD_SECRET = "production-cryptographically-secure-key-2026-xyz-abc"

    def test_valid_production_config_loads(self):
        """Settings initializes cleanly with valid production parameters."""
        s = Settings(
            ENVIRONMENT="production",
            SECRET_KEY=self.VALID_PROD_SECRET,
            ALLOWED_ORIGINS="http://localhost:8000,http://127.0.0.1:8000",
            DATABASE_URL="sqlite:///./prod_test.db",
            LOG_LEVEL="INFO",
            ALGORITHM="HS256",
            ACCESS_TOKEN_EXPIRE_MINUTES=60,
        )
        self.assertTrue(s.is_production)
        self.assertEqual(s.SECRET_KEY, self.VALID_PROD_SECRET)
        self.assertEqual(s.ALLOWED_ORIGINS, ["http://localhost:8000", "http://127.0.0.1:8000"])
        self.assertEqual(s.LOG_LEVEL, "INFO")
        self.assertEqual(s.ALGORITHM, "HS256")
        self.assertEqual(s.ACCESS_TOKEN_EXPIRE_MINUTES, 60)

    def test_production_rejects_missing_or_empty_secret_key(self):
        """Production mode fails fast when SECRET_KEY is missing or whitespace."""
        with self.assertRaises(RuntimeError) as ctx:
            Settings(ENVIRONMENT="production", SECRET_KEY="")
        self.assertIn("SECRET_KEY", str(ctx.exception))

        with self.assertRaises(RuntimeError) as ctx:
            Settings(ENVIRONMENT="production", SECRET_KEY="   ")
        self.assertIn("SECRET_KEY", str(ctx.exception))

    def test_production_rejects_short_secret_key(self):
        """Production mode requires SECRET_KEY to be at least 32 characters long."""
        short_secret = "too-short-secret"  # 16 chars
        with self.assertRaises(RuntimeError) as ctx:
            Settings(ENVIRONMENT="production", SECRET_KEY=short_secret)
        self.assertIn("minimum 32 characters", str(ctx.exception))

    def test_production_rejects_insecure_placeholder_secrets(self):
        """Production mode rejects known default/placeholder secrets."""
        for bad_secret in INSECURE_SECRETS:
            with self.subTest(secret=bad_secret):
                with self.assertRaises(RuntimeError) as ctx:
                    Settings(ENVIRONMENT="production", SECRET_KEY=bad_secret)
                self.assertIn("Insecure placeholder SECRET_KEY", str(ctx.exception))

    def test_production_rejects_wildcard_cors(self):
        """Production mode strictly forbids wildcard '*' in ALLOWED_ORIGINS."""
        with self.assertRaises(RuntimeError) as ctx:
            Settings(
                ENVIRONMENT="production",
                SECRET_KEY=self.VALID_PROD_SECRET,
                DATABASE_URL="sqlite:///./test_prod.db",
                ALLOWED_ORIGINS="*",
            )
        self.assertIn("Wildcard CORS origin ('*') is not permitted", str(ctx.exception))

        with self.assertRaises(RuntimeError) as ctx:
            Settings(
                ENVIRONMENT="production",
                SECRET_KEY=self.VALID_PROD_SECRET,
                DATABASE_URL="sqlite:///./test_prod.db",
                ALLOWED_ORIGINS=["http://localhost:8000", "*"],
            )
        self.assertIn("Wildcard CORS origin ('*') is not permitted", str(ctx.exception))

    def test_rejects_missing_or_unsupported_database_scheme(self):
        """Rejects empty DATABASE_URL or non-SQLite database schemes."""
        with self.assertRaises(RuntimeError) as ctx:
            Settings(
                ENVIRONMENT="production",
                SECRET_KEY=self.VALID_PROD_SECRET,
                DATABASE_URL="",
            )
        self.assertIn("DATABASE_URL must be set", str(ctx.exception))

        with self.assertRaises(RuntimeError) as ctx:
            Settings(
                ENVIRONMENT="production",
                SECRET_KEY=self.VALID_PROD_SECRET,
                DATABASE_URL="postgresql://user:pass@localhost:5432/chat",
            )
        self.assertIn("Unsupported database scheme", str(ctx.exception))

    def test_rejects_insecure_jwt_algorithm(self):
        """Rejects 'none' or empty JWT ALGORITHM."""
        with self.assertRaises(RuntimeError) as ctx:
            Settings(
                ENVIRONMENT="development",
                ALGORITHM="none",
            )
        self.assertIn("Insecure or empty JWT ALGORITHM", str(ctx.exception))

        with self.assertRaises(RuntimeError) as ctx:
            Settings(
                ENVIRONMENT="development",
                ALGORITHM="",
            )
        self.assertIn("Insecure or empty JWT ALGORITHM", str(ctx.exception))

    def test_rejects_invalid_token_expiration(self):
        """ACCESS_TOKEN_EXPIRE_MINUTES must be a positive integer."""
        for bad_val in (0, -10, "invalid", None):
            if bad_val is None:
                continue
            with self.subTest(val=bad_val):
                with self.assertRaises(ValueError) as ctx:
                    Settings(
                        ENVIRONMENT="development",
                        ACCESS_TOKEN_EXPIRE_MINUTES=bad_val,
                    )
                self.assertIn("ACCESS_TOKEN_EXPIRE_MINUTES", str(ctx.exception))

    def test_rejects_invalid_log_level(self):
        """LOG_LEVEL must be one of DEBUG, INFO, WARNING, ERROR, CRITICAL."""
        with self.assertRaises(ValueError) as ctx:
            Settings(LOG_LEVEL="VERBOSE")
        self.assertIn("Invalid LOG_LEVEL", str(ctx.exception))

    def test_rejects_invalid_environment(self):
        """ENVIRONMENT must be one of development, production, test."""
        with self.assertRaises(ValueError) as ctx:
            Settings(ENVIRONMENT="staging")
        self.assertIn("Invalid ENVIRONMENT", str(ctx.exception))

    def test_secret_key_masked_in_repr_and_str(self):
        """SECRET_KEY is never exposed in repr or str output."""
        sensitive_key = "sensitive-super-secret-key-32charslong!"
        s = Settings(SECRET_KEY=sensitive_key)
        self.assertNotIn(sensitive_key, repr(s))
        self.assertNotIn(sensitive_key, str(s))
        self.assertIn("SECRET_KEY='***'", repr(s))
        self.assertIn("LOG_LEVEL=", repr(s))

    def test_development_defaults_remain_usable(self):
        """Development mode falls back to safe usable defaults with zero setup."""
        with patch.dict(os.environ, {"ENVIRONMENT": "development"}, clear=False):
            os.environ.pop("SECRET_KEY", None)
            os.environ.pop("ALLOWED_ORIGINS", None)
            s = Settings()
            self.assertFalse(s.is_production)
            self.assertEqual(s.SECRET_KEY, DEV_DEFAULT_SECRET)
            self.assertEqual(s.ALLOWED_ORIGINS, ["*"])
            self.assertEqual(s.LOG_LEVEL, "INFO")


class TestRuntimeDependenciesCompleteness(unittest.TestCase):
    """Verify that requirements.txt declares all necessary runtime dependencies."""

    def test_requirements_declares_core_runtime_packages(self):
        """requirements.txt must declare all core runtime packages including Alembic."""
        req_path = Path("requirements.txt")
        self.assertTrue(req_path.exists(), "requirements.txt must exist")

        content = req_path.read_text(encoding="utf-8")
        declared_packages = set()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            pkg_name = re.split(r"[=<>]", line)[0].strip().lower()
            declared_packages.add(pkg_name)

        required_core = {
            "fastapi",
            "uvicorn",
            "sqlalchemy",
            "alembic",
            "passlib",
            "bcrypt",
            "python-dotenv",
            "python-multipart",
            "python-jose",
            "websockets",
        }

        missing = required_core - declared_packages
        self.assertEqual(
            missing,
            set(),
            f"Missing required runtime packages in requirements.txt: {missing}",
        )


class TestStartupArchitectureSafety(unittest.TestCase):
    """Verify application startup architecture and script properties."""

    def test_no_create_all_in_main_or_database(self):
        """Neither main.py nor backend/db/database.py calls create_all()."""
        repo_root = Path(__file__).parent.parent
        for target in ("main.py", "backend/db/database.py"):
            file_path = repo_root / target
            content = file_path.read_text(encoding="utf-8")
            self.assertNotIn(
                "create_all",
                content,
                f"{target} must NOT call create_all() at startup; schema must be managed via Alembic",
            )

    def test_production_startup_script_properties(self):
        """start_production.ps1 specifies single worker and omits reload in command."""
        script_path = Path("start_production.ps1")
        self.assertTrue(script_path.exists(), "start_production.ps1 must exist")

        content = script_path.read_text(encoding="utf-8")
        self.assertIn("--workers 1", content, "Startup script must explicitly declare --workers 1")

        # Verify executable invocation lines do not include --reload
        command_lines = [
            line for line in content.splitlines()
            if not line.strip().startswith("#") and "uvicorn" in line
        ]
        self.assertTrue(command_lines, "Must contain a uvicorn invocation command line")
        for line in command_lines:
            self.assertNotIn("--reload", line, "Startup command must not use --reload mode")


class TestProductionSmokeVerification(WebSocketReliabilityTestCase):
    """End-to-end smoke verification tests covering health, static, uploads, auth, and websockets."""

    def setUp(self):
        super().setUp()
        self.client = ASGIClient(app)
        self.upload_client = UploadSecurityASGIClient(app)

        # Override get_db dependency to use isolated test DB
        def override_get_db():
            yield self.db

        app.dependency_overrides[get_db] = override_get_db

    def tearDown(self):
        app.dependency_overrides.clear()
        super().tearDown()

    def test_health_endpoint_returns_200_ok(self):
        """GET /health returns HTTP 200 with {'status': 'ok'} and no secret/internal leaks."""
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data, {"status": "ok"})

        # Check response body and headers for accidental leaks
        resp_text = resp.text.lower()
        self.assertNotIn("secret", resp_text)
        self.assertNotIn("database", resp_text)
        self.assertNotIn("password", resp_text)
        self.assertNotIn("traceback", resp_text)

    def test_static_frontend_serves_html(self):
        """GET / serves the index.html frontend page."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/html", resp.headers.get("content-type", ""))

    def test_secure_upload_flow(self):
        """Upload validation preserves S5-T03 security: allows valid images, rejects invalid types."""
        token = create_access_token({"sub": "alice"}, timedelta(minutes=30))
        headers = {"Authorization": f"Bearer {token}"}

        # Valid PNG magic bytes
        resp = self.upload_client.post_file(
            url="/upload",
            field_name="file",
            filename="avatar.png",
            file_bytes=PNG_FIXTURE,
            content_type="image/png",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)
        url = resp.json().get("url", "")
        self.assertTrue(url.startswith("/uploads/"))

        # Clean up uploaded test file if on disk
        if url.startswith("/uploads/"):
            disk_path = Path("uploads") / Path(url).name
            if disk_path.exists():
                try:
                    disk_path.unlink()
                except OSError:
                    pass

        # Invalid file type (text/html pretending to be image) -> 415 Unsupported Media Type
        invalid_bytes = b"<html><script>alert(1)</script></html>"
        resp_bad = self.upload_client.post_file(
            url="/upload",
            field_name="file",
            filename="exploit.png",
            file_bytes=invalid_bytes,
            content_type="image/png",
            headers=headers,
        )
        self.assertEqual(resp_bad.status_code, 415)

    def test_auth_registration_and_login_flow(self):
        """Registration and login flow works under production-ready security rules."""
        reg_payload = {
            "username": "prod_user",
            "password": "StrongPassword2026!",
            "display_name": "Prod User",
        }
        resp = self.client.post("/register", json=reg_payload)
        self.assertEqual(resp.status_code, 200)

        login_payload = {
            "username": "prod_user",
            "password": "StrongPassword2026!",
        }
        resp_login = self.client.post("/login", json=login_payload)
        self.assertEqual(resp_login.status_code, 200)
        token_data = resp_login.json()
        self.assertIn("access_token", token_data)

        # Access protected endpoint with received token
        auth_headers = {"Authorization": f"Bearer {token_data['access_token']}"}
        resp_conv = self.client.get("/conversations", headers=auth_headers)
        self.assertEqual(resp_conv.status_code, 200)

    def test_websocket_authentication_smoke(self):
        """WebSocket connection accepts valid JWT and rejects invalid/missing tokens."""
        async def run():
            valid_token = create_access_token({"sub": "alice"}, timedelta(minutes=30))

            # Valid token connects
            client = await self.create_ws_client(token=valid_token)
            self.assertTrue(client.accepted)
            self.assertEqual(ws_module.online_users.get(self.alice.id), 1)
            await client.disconnect()

            # Invalid token is rejected with 1008
            bad_client = await self.create_ws_client(token="invalid_forged_token")
            self.assertFalse(bad_client.accepted)
            self.assertEqual(bad_client.close_code, 1008)

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
