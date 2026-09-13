"""Tests for configuration security, environment overrides, and secrets hardening.

Covers Sprint 5 Task S5-T02 (SEC-01 and SEC-04):
- SECRET_KEY loaded from environment
- Production rejects missing SECRET_KEY
- Production rejects known insecure placeholders
- Production error messages never expose secret values
- Development fallback preserves developer usability
- Masking of secret values in repr, str, and serialization
- Configured DATABASE_URL, UPLOADS_DIR, and STATIC_DIR are respected
- ALLOWED_ORIGINS parsing: unset in dev, comma-separated, JSON array, empty
- Environment variable precedence over .env
- Preservation of test database isolation
"""
import os
import tempfile
import unittest
from unittest.mock import patch

from backend.core.config import (
    DEV_DEFAULT_SECRET,
    INSECURE_SECRETS,
    Settings,
    parse_allowed_origins,
    settings as global_settings,
)
import backend.db.database as db_module


class TestSecretKeySecurity(unittest.TestCase):
    """Verify SECRET_KEY loading, production validation, and error safety."""

    def test_secret_key_loaded_from_environment(self):
        """SECRET_KEY provided via environment variable is respected."""
        test_secret = "custom-env-secret-key-xyz-789"
        with patch.dict(os.environ, {"SECRET_KEY": test_secret, "ENVIRONMENT": "development"}):
            s = Settings()
            self.assertEqual(s.SECRET_KEY, test_secret)

    def test_production_rejects_missing_secret_key(self):
        """Production mode must raise RuntimeError if SECRET_KEY is missing or empty."""
        with patch.dict(os.environ, {"ENVIRONMENT": "production", "SECRET_KEY": ""}, clear=False):
            with self.assertRaises(RuntimeError) as ctx:
                Settings()
            self.assertIn("Production mode requires SECRET_KEY", str(ctx.exception))

        # Explicit constructor argument variant
        with self.assertRaises(RuntimeError) as ctx:
            Settings(ENVIRONMENT="production", SECRET_KEY="")
        self.assertIn("Production mode requires SECRET_KEY", str(ctx.exception))

        with self.assertRaises(RuntimeError) as ctx:
            Settings(ENVIRONMENT="production", SECRET_KEY=None)
        self.assertIn("Production mode requires SECRET_KEY", str(ctx.exception))

    def test_production_rejects_known_placeholder_secrets(self):
        """Production mode must reject known placeholder/default secrets."""
        for bad_secret in INSECURE_SECRETS:
            with self.subTest(secret=bad_secret):
                with self.assertRaises(RuntimeError) as ctx:
                    Settings(ENVIRONMENT="production", SECRET_KEY=bad_secret)
                self.assertIn("Insecure placeholder SECRET_KEY", str(ctx.exception))

    def test_production_error_never_exposes_secret_value(self):
        """Production validation error message must never print or log the actual secret value."""
        sensitive_bad_secret = "super-secret-key-change-later"
        with self.assertRaises(RuntimeError) as ctx:
            Settings(ENVIRONMENT="production", SECRET_KEY=sensitive_bad_secret)
        self.assertNotIn(sensitive_bad_secret, str(ctx.exception))

    def test_production_accepts_valid_secret_key(self):
        """Production mode accepts strong, non-placeholder secrets."""
        valid_prod_secret = "production-cryptographic-strong-secret-key-2026"
        s = Settings(ENVIRONMENT="production", SECRET_KEY=valid_prod_secret)
        self.assertEqual(s.SECRET_KEY, valid_prod_secret)
        self.assertTrue(s.is_production)

    def test_development_uses_dev_default_secret_when_unset(self):
        """Development mode falls back to safe development placeholder if secret is unset."""
        with patch.dict(os.environ, {"ENVIRONMENT": "development"}, clear=False):
            os.environ.pop("SECRET_KEY", None)
            s = Settings()
            self.assertEqual(s.SECRET_KEY, DEV_DEFAULT_SECRET)
            self.assertFalse(s.is_production)


class TestConfigurationExposure(unittest.TestCase):
    """Verify secret masking in repr, str, and diagnostic output."""

    def test_secret_never_exposed_in_repr_or_str(self):
        """SECRET_KEY value must be masked as '***' in repr and str."""
        sensitive_secret = "highly-sensitive-runtime-key-value-999"
        s = Settings(SECRET_KEY=sensitive_secret)

        repr_str = repr(s)
        str_val = str(s)

        self.assertNotIn(sensitive_secret, repr_str)
        self.assertNotIn(sensitive_secret, str_val)
        self.assertIn("SECRET_KEY='***'", repr_str)
        self.assertIn("SECRET_KEY='***'", str_val)


class TestEnvironmentDrivenConfiguration(unittest.TestCase):
    """Verify DATABASE_URL, UPLOADS_DIR, STATIC_DIR, and database module integration."""

    def test_database_url_from_env_and_default(self):
        """Configured DATABASE_URL is respected; default fallback is sqlite:///./chat.db."""
        # Custom configured
        custom_url = "sqlite:///./custom_test_db.db"
        s = Settings(DATABASE_URL=custom_url)
        self.assertEqual(s.DATABASE_URL, custom_url)

        # Default fallback when unset
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DATABASE_URL", None)
            s_default = Settings()
            self.assertEqual(s_default.DATABASE_URL, "sqlite:///./chat.db")

    def test_uploads_dir_from_env_and_default(self):
        """Configured UPLOADS_DIR is respected; default fallback is uploads."""
        custom_uploads = "custom_storage/uploads"
        s = Settings(UPLOADS_DIR=custom_uploads)
        self.assertEqual(s.UPLOADS_DIR, custom_uploads)

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("UPLOADS_DIR", None)
            s_default = Settings()
            self.assertEqual(s_default.UPLOADS_DIR, "uploads")

    def test_static_dir_from_env_and_default(self):
        """Configured STATIC_DIR is respected; default fallback is static."""
        custom_static = "custom_static_dir"
        s = Settings(STATIC_DIR=custom_static)
        self.assertEqual(s.STATIC_DIR, custom_static)

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("STATIC_DIR", None)
            s_default = Settings()
            self.assertEqual(s_default.STATIC_DIR, "static")

    def test_backend_database_module_uses_settings_database_url(self):
        """backend.db.database.DATABASE_URL matches settings.DATABASE_URL."""
        self.assertEqual(db_module.DATABASE_URL, global_settings.DATABASE_URL)


class TestAllowedOriginsConfiguration(unittest.TestCase):
    """Verify ALLOWED_ORIGINS configuration parsing."""

    def test_unset_in_development_defaults_to_wildcard(self):
        """ALLOWED_ORIGINS unset in development mode defaults to ['*']."""
        s = Settings(ENVIRONMENT="development", ALLOWED_ORIGINS=None)
        self.assertEqual(s.ALLOWED_ORIGINS, ["*"])

    def test_comma_separated_origins_split_and_trimmed(self):
        """Comma-separated origins string is split, trimmed, and empty values ignored."""
        origins_input = "  http://localhost:3000 ,  http://127.0.0.1:8000 ,  https://chat.example.com  "
        s = Settings(ALLOWED_ORIGINS=origins_input)
        self.assertEqual(
            s.ALLOWED_ORIGINS,
            ["http://localhost:3000", "http://127.0.0.1:8000", "https://chat.example.com"],
        )

    def test_json_array_origins_parsed(self):
        """JSON array formatted string is parsed into list of origins."""
        origins_json = '["http://localhost:8000", "https://chatspic.internal"]'
        s = Settings(ALLOWED_ORIGINS=origins_json)
        self.assertEqual(
            s.ALLOWED_ORIGINS,
            ["http://localhost:8000", "https://chatspic.internal"],
        )

    def test_explicitly_empty_origins(self):
        """Explicitly empty string results in empty list []."""
        s_empty = Settings(ALLOWED_ORIGINS="")
        self.assertEqual(s_empty.ALLOWED_ORIGINS, [])

        s_whitespace = Settings(ALLOWED_ORIGINS="   ")
        self.assertEqual(s_whitespace.ALLOWED_ORIGINS, [])

    def test_list_origins_preserved(self):
        """Passing a list directly preserves trimmed values."""
        s = Settings(ALLOWED_ORIGINS=["https://alpha.com", " https://beta.com "])
        self.assertEqual(s.ALLOWED_ORIGINS, ["https://alpha.com", "https://beta.com"])

    def test_standalone_parse_allowed_origins_helper(self):
        """parse_allowed_origins helper handles edge cases correctly."""
        self.assertEqual(parse_allowed_origins(None, env="development"), ["*"])
        self.assertEqual(parse_allowed_origins(None, env="production"), [])
        self.assertEqual(parse_allowed_origins("   "), [])
        self.assertEqual(parse_allowed_origins("invalid[json"), ["invalid[json"])


class TestEnvironmentPrecedence(unittest.TestCase):
    """Verify that environment variables take precedence over .env file values."""

    def test_environment_variables_take_precedence_over_dotenv(self):
        """Actual environment variables override values defined in .env."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            temp_env_file = os.path.join(tmp_dir, ".env")
            with open(temp_env_file, "w", encoding="utf-8") as f:
                f.write("SECRET_KEY=from-dotenv-file\n")
                f.write("UPLOADS_DIR=uploads-from-dotenv\n")
                f.write("STATIC_DIR=static-from-dotenv\n")

            # Environment variable takes precedence for SECRET_KEY
            # UPLOADS_DIR is unset in environment, so .env should populate it
            with patch.dict(os.environ, {"SECRET_KEY": "from-actual-env", "ENVIRONMENT": "development"}, clear=False):
                os.environ.pop("UPLOADS_DIR", None)
                os.environ.pop("STATIC_DIR", None)

                s = Settings(_env_file=temp_env_file)

                # Env var wins over .env
                self.assertEqual(s.SECRET_KEY, "from-actual-env")
                # .env provides value when not present in environment
                self.assertEqual(s.UPLOADS_DIR, "uploads-from-dotenv")
                self.assertEqual(s.STATIC_DIR, "static-from-dotenv")

    def test_tests_init_database_url_isolation_preserved(self):
        """Verify tests/__init__.py isolation is active and database URL is preserved against .env."""
        self.assertEqual(os.environ.get("DATABASE_URL"), "sqlite:///:memory:")

        # Verify a .env file cannot override the test isolation DATABASE_URL
        with tempfile.TemporaryDirectory() as tmp_dir:
            temp_env = os.path.join(tmp_dir, ".env")
            with open(temp_env, "w", encoding="utf-8") as f:
                f.write("DATABASE_URL=sqlite:///./should_not_override.db\n")
            s = Settings(_env_file=temp_env)
            # The test DATABASE_URL in os.environ is preserved
            self.assertEqual(os.environ.get("DATABASE_URL"), "sqlite:///:memory:")
            self.assertEqual(s.DATABASE_URL, "sqlite:///:memory:")


if __name__ == "__main__":
    unittest.main()
