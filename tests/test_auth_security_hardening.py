"""
Focused automated tests for Sprint 5 Task S5-T06: Authentication & Password Hardening.

Test coverage includes:
1. Password Policy:
   - Rejects passwords below minimum (8 bytes) on registration with HTTP 400.
   - Accepts valid passwords (8 bytes, 16 bytes, complex passwords).
   - Accepts exactly 72 UTF-8 bytes.
   - Rejects passwords over 72 UTF-8 bytes with HTTP 400 (never silently truncated).
   - Multibyte UTF-8 measured strictly by byte length (not Python character count).
   - Plaintext passwords never stored in DB; password hashing and authentication work properly.
2. Existing User Compatibility:
   - Existing users with legacy weak passwords (e.g. "1234") log in successfully.
   - Logging in never modifies the existing user's password hash in the database.
   - Changing/validating a new password enforces the new policy (weak passwords rejected, compliant accepted).
3. Authentication Rate Limiting:
   - Failed login attempts trigger HTTP 429 with Retry-After header after threshold (5 attempts).
   - Successful logins work normally when not throttled and reset failed login count for client IP.
   - Registration abuse protection triggers HTTP 429 after threshold (10 attempts).
   - Rate limiting keys by client IP (request.client.host) and isolates distinct IPs.
   - Anti-enumeration timing defense: nonexistent username and invalid password return identical 401 responses.
4. Core Security Unit Tests:
   - Direct unit testing of validate_new_password (boundary values, multibyte strings, invalid types).
   - Direct unit testing of InMemoryRateLimiter (sliding window, concurrency, reset).
"""

import asyncio
import json
import threading
import time
import unittest
from datetime import timedelta
from urllib.parse import urlparse

from main import app
from backend.core.config import settings
from backend.core.security import (
    DUMMY_HASH,
    MAX_PASSWORD_BYTES,
    MIN_PASSWORD_BYTES,
    InMemoryRateLimiter,
    PasswordValidationError,
    create_access_token,
    failed_login_limiter,
    get_client_ip,
    hash_password,
    pwd_context,
    registration_limiter,
    reset_auth_rate_limiters,
    validate_new_password,
    verify_password,
)
from backend.db.database import get_db
from backend.db.models import User
from tests.base import BaseTestCase


# ==============================================================================
# Zero-Dependency ASGI Client with Configurable Client IP
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


class HardeningASGIClient:
    """Zero-dependency ASGI test client supporting authoritative client IP simulation."""

    def __init__(self, asgi_app, default_ip: str = "127.0.0.1"):
        self.app = asgi_app
        self.default_ip = default_ip

    def request(
        self,
        method: str,
        url: str,
        headers: dict = None,
        json_body=None,
        client_ip: str = None,
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

        ip = client_ip or self.default_ip
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method.upper(),
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": query_string,
            "headers": raw_headers,
            "client": (ip, 12345),
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

    def get(self, url: str, headers: dict = None, client_ip: str = None) -> ASGIResponse:
        return self.request("GET", url, headers=headers, client_ip=client_ip)

    def post(self, url: str, json: dict = None, headers: dict = None, client_ip: str = None) -> ASGIResponse:
        return self.request("POST", url, headers=headers, json_body=json, client_ip=client_ip)


# ==============================================================================
# Base Endpoint Hardening Test Case
# ==============================================================================
class AuthHardeningTestCase(BaseTestCase):
    """Base class for S5-T06 authentication hardening tests with DB & rate limiter isolation."""

    def setUp(self):
        super().setUp()
        reset_auth_rate_limiters()
        app.dependency_overrides[get_db] = lambda: self.db
        self.client = HardeningASGIClient(app)

    def tearDown(self):
        app.dependency_overrides.clear()
        reset_auth_rate_limiters()
        super().tearDown()


# ==============================================================================
# 1. Password Policy Tests
# ==============================================================================
class TestPasswordPolicy(AuthHardeningTestCase):
    """Tests verifying password policy enforcement during account registration."""

    def test_registration_rejects_password_below_minimum(self):
        """Registration must reject passwords under 8 bytes with HTTP 400."""
        # 7 ASCII characters = 7 bytes (< 8)
        resp = self.client.post("/register", json={"username": "shortpass_user", "password": "1234567"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("at least 8 characters", resp.json().get("detail", ""))

        # Empty password
        resp_empty = self.client.post("/register", json={"username": "emptypass_user", "password": ""})
        self.assertEqual(resp_empty.status_code, 400)

        # 4-character password
        resp_four = self.client.post("/register", json={"username": "fourpass_user", "password": "pass"})
        self.assertEqual(resp_four.status_code, 400)

    def test_registration_accepts_valid_passwords(self):
        """Registration accepts passwords of minimum length and above."""
        # Exactly 8 bytes
        resp_8 = self.client.post("/register", json={"username": "user_eight", "password": "eightchr"})
        self.assertEqual(resp_8.status_code, 200)
        self.assertEqual(resp_8.json(), {"msg": "User created successfully"})

        # 16 bytes
        resp_16 = self.client.post("/register", json={"username": "user_sixteen", "password": "sixteen_chars_!"})
        self.assertEqual(resp_16.status_code, 200)

    def test_registration_accepts_exactly_72_utf8_bytes(self):
        """Registration accepts passwords of exactly 72 UTF-8 bytes (bcrypt limit)."""
        password_72_bytes = "A" * 72
        self.assertEqual(len(password_72_bytes.encode("utf-8")), 72)

        resp = self.client.post("/register", json={"username": "user_72", "password": password_72_bytes})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"msg": "User created successfully"})

        # Verify login works with the 72-byte password
        login_resp = self.client.post("/login", json={"username": "user_72", "password": password_72_bytes})
        self.assertEqual(login_resp.status_code, 200)
        self.assertIn("access_token", login_resp.json())

    def test_registration_rejects_password_over_72_utf8_bytes(self):
        """Registration explicitly rejects passwords exceeding 72 UTF-8 bytes (no truncation)."""
        password_73_bytes = "A" * 73
        self.assertEqual(len(password_73_bytes.encode("utf-8")), 73)

        resp = self.client.post("/register", json={"username": "user_73", "password": password_73_bytes})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("exceeds maximum", resp.json().get("detail", ""))

        # 100-byte password
        password_100 = "B" * 100
        resp_100 = self.client.post("/register", json={"username": "user_100", "password": password_100})
        self.assertEqual(resp_100.status_code, 400)

    def test_multibyte_utf8_measured_by_byte_length(self):
        """Multibyte UTF-8 passwords must be measured by byte length, not Python character count."""
        # Japanese kanji: each character is 3 UTF-8 bytes
        # 2 kanji characters = 2 Python chars, but 6 UTF-8 bytes (< 8 bytes) -> REJECTED
        two_kanji = "日本"
        self.assertEqual(len(two_kanji), 2)
        self.assertEqual(len(two_kanji.encode("utf-8")), 6)

        resp_short_kanji = self.client.post("/register", json={"username": "kanji_short", "password": two_kanji})
        self.assertEqual(resp_short_kanji.status_code, 400)

        # 3 kanji characters = 3 Python chars, but 9 UTF-8 bytes (>= 8 bytes) -> ACCEPTED
        three_kanji = "日本語"
        self.assertEqual(len(three_kanji), 3)
        self.assertEqual(len(three_kanji.encode("utf-8")), 9)

        resp_valid_kanji = self.client.post("/register", json={"username": "kanji_valid", "password": three_kanji})
        self.assertEqual(resp_valid_kanji.status_code, 200)

        # Exactly 24 kanji characters = 24 * 3 = 72 UTF-8 bytes -> ACCEPTED
        kanji_72_bytes = "語" * 24
        self.assertEqual(len(kanji_72_bytes), 24)
        self.assertEqual(len(kanji_72_bytes.encode("utf-8")), 72)

        resp_72_kanji = self.client.post("/register", json={"username": "kanji_72", "password": kanji_72_bytes})
        self.assertEqual(resp_72_kanji.status_code, 200)

        # 25 kanji characters = 25 * 3 = 75 UTF-8 bytes (> 72 bytes) -> REJECTED
        kanji_75_bytes = "語" * 25
        self.assertEqual(len(kanji_75_bytes), 25)
        self.assertEqual(len(kanji_75_bytes.encode("utf-8")), 75)

        resp_75_kanji = self.client.post("/register", json={"username": "kanji_75", "password": kanji_75_bytes})
        self.assertEqual(resp_75_kanji.status_code, 400)

        # Emoji test: '🔒' is 4 UTF-8 bytes
        # 1 emoji = 4 bytes (< 8) -> REJECTED
        resp_1_emoji = self.client.post("/register", json={"username": "emoji_1", "password": "🔒"})
        self.assertEqual(resp_1_emoji.status_code, 400)

        # 2 emojis = 8 bytes (>= 8) -> ACCEPTED
        resp_2_emoji = self.client.post("/register", json={"username": "emoji_2", "password": "🔒🔒"})
        self.assertEqual(resp_2_emoji.status_code, 200)

    def test_password_hashing_and_authentication_integrity(self):
        """Plaintext password must never be stored, and authentication must succeed using bcrypt."""
        plain_pw = "SecureAuthPassword_2026!"
        resp = self.client.post("/register", json={"username": "integrity_user", "password": plain_pw})
        self.assertEqual(resp.status_code, 200)

        # Verify DB entry
        user = self.db.query(User).filter(User.username == "integrity_user").first()
        self.assertIsNotNone(user)
        self.assertNotEqual(user.password_hash, plain_pw)
        self.assertTrue(user.password_hash.startswith("$2b$") or user.password_hash.startswith("$2a$"))
        self.assertTrue(verify_password(plain_pw, user.password_hash))

        # Verify login
        login_resp = self.client.post("/login", json={"username": "integrity_user", "password": plain_pw})
        self.assertEqual(login_resp.status_code, 200)
        token = login_resp.json().get("access_token")
        self.assertIsNotNone(token)

        # Verify token access to protected endpoints
        me_resp = self.client.get("/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(me_resp.status_code, 200)
        prof_resp = self.client.get("/profile/", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(prof_resp.status_code, 200)
        self.assertEqual(prof_resp.json().get("username"), "integrity_user")


# ==============================================================================
# 2. Existing User Backward Compatibility Tests
# ==============================================================================
class TestExistingUserCompatibility(AuthHardeningTestCase):
    """Tests ensuring legacy users with weak passwords remain fully functional."""

    def test_existing_legacy_weak_password_login_succeeds(self):
        """Existing user with a weak legacy password (e.g. '1234') can log in successfully."""
        legacy_password = "1234"
        legacy_hash = pwd_context.hash(legacy_password)
        self.create_user("legacy_dev_user", password_hash=legacy_hash)

        resp = self.client.post("/login", json={"username": "legacy_dev_user", "password": legacy_password})
        self.assertEqual(resp.status_code, 200)
        token = resp.json().get("access_token")
        self.assertIsNotNone(token)

        # Token allows accessing protected endpoints
        me_resp = self.client.get("/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(me_resp.status_code, 200)

    def test_login_does_not_modify_legacy_password_hash(self):
        """Logging in with a legacy weak password must never alter the user's stored hash."""
        legacy_password = "1234"
        initial_hash = pwd_context.hash(legacy_password)
        user = self.create_user("untouched_hash_user", password_hash=initial_hash)

        # Record hash directly from DB before login
        db_user_before = self.db.query(User).filter(User.username == "untouched_hash_user").first()
        stored_hash_before = db_user_before.password_hash
        self.assertEqual(stored_hash_before, initial_hash)

        # Perform login
        resp = self.client.post("/login", json={"username": "untouched_hash_user", "password": legacy_password})
        self.assertEqual(resp.status_code, 200)

        # Re-query user from DB after login
        self.db.expire_all()
        db_user_after = self.db.query(User).filter(User.username == "untouched_hash_user").first()
        stored_hash_after = db_user_after.password_hash

        # Hash must be identical byte-for-byte; no forced rehash or migration
        self.assertEqual(stored_hash_before, stored_hash_after)

    def test_password_policy_enforced_when_validating_candidate_passwords(self):
        """Policy rejects weak passwords when validated as candidate new passwords."""
        # A weak candidate password must fail validation
        with self.assertRaises(PasswordValidationError):
            validate_new_password("1234")

        with self.assertRaises(PasswordValidationError):
            validate_new_password("abc")

        # Compliant candidate password passes validation
        try:
            validate_new_password("NewCompliantPassword_2026!")
        except PasswordValidationError:
            self.fail("validate_new_password unexpectedly raised PasswordValidationError for a compliant password")


# ==============================================================================
# 3. Authentication Rate Limiting Tests
# ==============================================================================
class TestAuthRateLimiting(AuthHardeningTestCase):
    """Tests covering client IP-based rate limiting on authentication endpoints."""

    def test_failed_login_attempts_eventually_return_429(self):
        """Failed login attempts trigger HTTP 429 after threshold (5 attempts)."""
        # Ensure user exists for test
        self.create_user("victim_user", password_hash=pwd_context.hash("CorrectPassword123!"))

        # 5 failed login attempts from client IP
        for i in range(5):
            resp = self.client.post(
                "/login",
                json={"username": "victim_user", "password": f"wrong_password_{i}"},
                client_ip="192.168.10.1",
            )
            self.assertEqual(resp.status_code, 401, f"Attempt {i+1} should return 401")
            self.assertEqual(resp.json().get("detail"), "Invalid credentials")

        # 6th login attempt must be throttled with 429
        resp_throttled = self.client.post(
            "/login",
            json={"username": "victim_user", "password": "any_password"},
            client_ip="192.168.10.1",
        )
        self.assertEqual(resp_throttled.status_code, 429)
        self.assertIn("Too many failed login attempts", resp_throttled.json().get("detail", ""))
        self.assertIn("retry-after", resp_throttled.headers)
        self.assertTrue(int(resp_throttled.headers["retry-after"]) > 0)

    def test_successful_login_works_normally_when_not_throttled(self):
        """Successful login returns 200, is not blocked, and resets failed attempt count."""
        password = "NormalUserPass_123!"
        self.create_user("normal_user", password_hash=pwd_context.hash(password))

        # 3 failed attempts (below limit of 5)
        for i in range(3):
            resp_fail = self.client.post(
                "/login",
                json={"username": "normal_user", "password": "wrong_pass"},
                client_ip="192.168.10.2",
            )
            self.assertEqual(resp_fail.status_code, 401)

        # 4th attempt: correct credentials -> succeeds
        resp_success = self.client.post(
            "/login",
            json={"username": "normal_user", "password": password},
            client_ip="192.168.10.2",
        )
        self.assertEqual(resp_success.status_code, 200)
        self.assertIn("access_token", resp_success.json())

        # Success clears failed attempts, allowing further failures up to 5 without immediate 429
        for i in range(3):
            resp_fail2 = self.client.post(
                "/login",
                json={"username": "normal_user", "password": "wrong_pass"},
                client_ip="192.168.10.2",
            )
            self.assertEqual(resp_fail2.status_code, 401)

    def test_registration_abuse_protection_returns_429(self):
        """Registration returns HTTP 429 when registration threshold (10 attempts) is exceeded."""
        reg_ip = "192.168.20.1"

        # 10 registrations from the same client IP
        for i in range(10):
            resp = self.client.post(
                "/register",
                json={"username": f"bulk_reg_user_{i}", "password": "ValidPassword123!"},
                client_ip=reg_ip,
            )
            self.assertEqual(resp.status_code, 200, f"Registration {i+1} should succeed")

        # 11th registration attempt from the same IP must be throttled with 429
        resp_throttled = self.client.post(
            "/register",
            json={"username": "bulk_reg_user_11", "password": "ValidPassword123!"},
            client_ip=reg_ip,
        )
        self.assertEqual(resp_throttled.status_code, 429)
        self.assertIn("Too many registration attempts", resp_throttled.json().get("detail", ""))
        self.assertIn("retry-after", resp_throttled.headers)

    def test_rate_limiting_does_not_block_unrelated_ips(self):
        """Throttling one client IP must never block authentication for a different client IP."""
        bad_ip = "192.168.99.1"
        good_ip = "192.168.99.2"

        self.create_user("shared_user", password_hash=pwd_context.hash("SharedSecret_123!"))

        # Exhaust failed login limit on bad_ip
        for _ in range(5):
            self.client.post(
                "/login",
                json={"username": "shared_user", "password": "wrong_password"},
                client_ip=bad_ip,
            )

        # Verify bad_ip is throttled
        bad_resp = self.client.post(
            "/login",
            json={"username": "shared_user", "password": "SharedSecret_123!"},
            client_ip=bad_ip,
        )
        self.assertEqual(bad_resp.status_code, 429)

        # good_ip must still be able to log in successfully
        good_resp = self.client.post(
            "/login",
            json={"username": "shared_user", "password": "SharedSecret_123!"},
            client_ip=good_ip,
        )
        self.assertEqual(good_resp.status_code, 200)
        self.assertIn("access_token", good_resp.json())

        # Registration IP isolation
        for i in range(10):
            self.client.post(
                "/register",
                json={"username": f"reg_bad_{i}", "password": "ValidPassword123!"},
                client_ip=bad_ip,
            )
        self.assertEqual(
            self.client.post(
                "/register",
                json={"username": "reg_bad_11", "password": "ValidPassword123!"},
                client_ip=bad_ip,
            ).status_code,
            429,
        )

        # good_ip can still register without being throttled
        good_reg_resp = self.client.post(
            "/register",
            json={"username": "reg_good_user", "password": "ValidPassword123!"},
            client_ip=good_ip,
        )
        self.assertEqual(good_reg_resp.status_code, 200)

    def test_anti_enumeration_timing_defense_and_identical_errors(self):
        """Nonexistent username and incorrect password must return identical 401 responses."""
        self.create_user("known_user", password_hash=pwd_context.hash("KnownUserSecret123!"))

        # Case 1: Existent user, incorrect password
        resp_wrong_pw = self.client.post(
            "/login",
            json={"username": "known_user", "password": "wrong_password_attempt"},
            client_ip="192.168.30.1",
        )
        self.assertEqual(resp_wrong_pw.status_code, 401)
        self.assertEqual(resp_wrong_pw.json(), {"detail": "Invalid credentials"})

        # Case 2: Nonexistent user
        resp_no_user = self.client.post(
            "/login",
            json={"username": "completely_nonexistent_user", "password": "wrong_password_attempt"},
            client_ip="192.168.30.2",
        )
        self.assertEqual(resp_no_user.status_code, 401)
        self.assertEqual(resp_no_user.json(), {"detail": "Invalid credentials"})

        # Error details must be strictly identical
        self.assertEqual(resp_wrong_pw.json(), resp_no_user.json())

        # No password, hash, or secret leaked in responses
        for resp in (resp_wrong_pw, resp_no_user):
            self.assertNotIn("password_hash", resp.text)
            self.assertNotIn("SECRET_KEY", resp.text)
            self.assertNotIn("dummy", resp.text)


# ==============================================================================
# 4. Core Security Layer Unit Tests
# ==============================================================================
class TestCoreSecurityUtilities(unittest.TestCase):
    """Direct unit tests for password validation and in-process rate limiter."""

    def test_validate_new_password_boundaries(self):
        """validate_new_password correctly validates min, max, and edge cases."""
        # Non-string types
        with self.assertRaises(PasswordValidationError):
            validate_new_password(12345678)
        with self.assertRaises(PasswordValidationError):
            validate_new_password(None)

        # Less than 8 bytes
        with self.assertRaises(PasswordValidationError):
            validate_new_password("")
        with self.assertRaises(PasswordValidationError):
            validate_new_password("1234567")

        # Exactly 8 bytes passes
        validate_new_password("12345678")

        # Exactly 72 bytes passes
        validate_new_password("x" * 72)

        # 73 bytes fails
        with self.assertRaises(PasswordValidationError):
            validate_new_password("x" * 73)

    def test_in_memory_rate_limiter_logic(self):
        """InMemoryRateLimiter correctly tracks sliding window and limits."""
        limiter = InMemoryRateLimiter(max_attempts=3, window_seconds=2)
        ip = "10.0.0.1"

        # Initially not limited
        is_lim, _ = limiter.is_rate_limited(ip)
        self.assertFalse(is_lim)

        # 3 attempts
        limiter.record_attempt(ip)
        limiter.record_attempt(ip)
        limiter.record_attempt(ip)

        # Now limited
        is_lim, retry_after = limiter.is_rate_limited(ip)
        self.assertTrue(is_lim)
        self.assertTrue(1 <= retry_after <= 2)

        # Reset key clears limit
        limiter.reset_key(ip)
        is_lim, _ = limiter.is_rate_limited(ip)
        self.assertFalse(is_lim)

    def test_in_memory_rate_limiter_concurrency(self):
        """InMemoryRateLimiter is thread-safe under concurrent recording."""
        limiter = InMemoryRateLimiter(max_attempts=100, window_seconds=60)
        ip = "10.0.0.2"

        def record_batch():
            for _ in range(10):
                limiter.record_attempt(ip)

        threads = [threading.Thread(target=record_batch) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should have recorded 50 attempts
        now = time.monotonic()
        attempts = limiter._clean_window(ip, now)
        self.assertEqual(len(attempts), 50)

    def test_hash_password_utility(self):
        """hash_password produces valid, verifiable bcrypt hashes."""
        plain = "TestPlainPassword123!"
        hashed = hash_password(plain)
        self.assertNotEqual(plain, hashed)
        self.assertTrue(verify_password(plain, hashed))
        self.assertFalse(verify_password("WrongPassword123!", hashed))
