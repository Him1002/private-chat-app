"""Focused automated regression tests for ChatSpic upload security controls (S3-T10).

Verifies the upload security invariants across:
1. Valid file acceptance (JPEG, PNG, GIF87a, GIF89a, WebP)
2. Magic-byte content validation
3. Extension spoofing resistance (.exe, .html, etc.)
4. MIME type spoofing resistance
5. Enforced 5 MB size limit (below, boundary, and above)
6. Oversized upload cleanup (no partial files on disk)
7. Rejected upload cleanup (no invalid artifacts on disk)
8. Filename and path traversal safety (Unix & Windows)
9. Content-type and canonical extension consistency
10. Profile picture integration
11. Chat image integration
12. Unicode and unusual filenames
13. Allowlist regression against unsupported types
14. HTTP boundary and response contracts

All tests use isolated in-memory SQLite and strictly track/clean test-created
upload files, guaranteeing zero mutation to the development chat.db or
pre-existing upload directory assets.
"""
import os
import unittest
import uuid
from datetime import timedelta

from backend.core.config import settings
from backend.core.security import create_access_token
from backend.db.database import get_db
from backend.services.upload_service import (
    ALLOWED_MAGIC_BYTES,
    MAX_UPLOAD_SIZE,
    get_file_ext_from_magic_bytes,
)
from main import app
from tests.base import BaseTestCase
from tests.test_api_integration import IntegrationASGIClient


# ==============================================================================
# Deterministic Test Fixtures (Tiny & Deterministic)
# ==============================================================================
JPEG_FIXTURE = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + b"\x11" * 16
PNG_FIXTURE = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x22" * 16
GIF87A_FIXTURE = b"GIF87a\x01\x00\x01\x00\x80\x00\x00" + b"\x33" * 16
GIF89A_FIXTURE = b"GIF89a\x01\x00\x01\x00\x80\x00\x00" + b"\x44" * 16
WEBP_FIXTURE = b"RIFF\x20\x00\x00\x00WEBPVP8 " + b"\x55" * 16
MP4_FIXTURE = b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom" + b"\x66" * 32
WEBM_FIXTURE = b"\x1a\x45\xdf\xa3\x9f\x42\x86\x81\x01\x42\xf7\x81\x01\x42\xf2\x81\x04\x42\x87\x84webm" + b"\x77" * 32


# ==============================================================================
# Base Upload Security Test Case & Client
# ==============================================================================
class UploadSecurityASGIClient(IntegrationASGIClient):
    """ASGI client subclass supporting UTF-8 multipart/form-data filenames."""

    def post_file(
        self,
        url: str,
        field_name: str,
        filename: str,
        file_bytes: bytes,
        content_type: str = "image/png",
        headers: dict = None,
    ):
        boundary = "----TestFormBoundary" + uuid.uuid4().hex
        header_text = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n"
        )
        body = header_text.encode("utf-8") + file_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

        req_headers = dict(headers or {})
        req_headers["content-type"] = f"multipart/form-data; boundary={boundary}"
        return self.request("POST", url, headers=req_headers, content=body)


class UploadSecurityTestCase(BaseTestCase):
    """Base test case providing database isolation, ASGI client, and upload file tracking."""

    def setUp(self):
        super().setUp()

        def _override_get_db():
            try:
                yield self.db
            finally:
                pass

        app.dependency_overrides[get_db] = _override_get_db
        self.client = UploadSecurityASGIClient(app)
        self._tracked_files = []

        # Snapshot pre-existing files in upload directory before each test
        if os.path.exists(settings.UPLOADS_DIR):
            self._initial_files = set(os.listdir(settings.UPLOADS_DIR))
        else:
            self._initial_files = set()

    def tearDown(self):
        try:
            # 1. Clean up explicitly tracked files
            for path in self._tracked_files:
                try:
                    if os.path.exists(path):
                        os.remove(path)
                except OSError:
                    pass

            # 2. Clean up any new files created during test execution
            if os.path.exists(settings.UPLOADS_DIR):
                current_files = set(os.listdir(settings.UPLOADS_DIR))
                new_files = current_files - self._initial_files
                for filename in new_files:
                    path = os.path.join(settings.UPLOADS_DIR, filename)
                    try:
                        if os.path.exists(path):
                            os.remove(path)
                    except OSError:
                        pass

                # Assert that all test-created files were cleaned and initial files untouched
                remaining_files = set(os.listdir(settings.UPLOADS_DIR))
                self.assertEqual(
                    remaining_files,
                    self._initial_files,
                    f"Upload directory leaked files: {remaining_files - self._initial_files}",
                )
        finally:
            # Clear FastAPI dependency overrides and verify empty
            app.dependency_overrides.pop(get_db, None)
            self.assertEqual(len(app.dependency_overrides), 0, "Dependency overrides must be empty after test")
            super().tearDown()

    def track_file(self, filepath_or_url: str):
        """Track an uploaded file path or URL for safe cleanup after test execution."""
        if filepath_or_url.startswith("/uploads/"):
            filename = filepath_or_url.replace("/uploads/", "")
            path = os.path.join(settings.UPLOADS_DIR, filename)
        elif filepath_or_url.startswith("uploads/"):
            path = filepath_or_url
        else:
            path = os.path.join(settings.UPLOADS_DIR, filepath_or_url)
        self._tracked_files.append(os.path.abspath(path))

    def auth_headers(self, username: str = "alice") -> dict:
        """Generate Bearer authorization headers for the given username."""
        token = create_access_token(
            data={"sub": username},
            expires_delta=timedelta(minutes=30),
        )
        return {"Authorization": f"Bearer {token}"}

    def assert_valid_uuid_filename(self, filename_or_url: str, expected_ext: str):
        """Assert filename has canonical extension and valid UUID prefix."""
        basename = os.path.basename(filename_or_url)
        self.assertIn(".", basename)
        name_part, ext_part = basename.rsplit(".", 1)
        self.assertEqual(ext_part, expected_ext)
        parsed_uuid = uuid.UUID(name_part)
        self.assertEqual(str(parsed_uuid), name_part)


# ==============================================================================
# 1. Valid File Acceptance & Content-Type / Extension Consistency (Areas 1 & 9)
# ==============================================================================
class TestValidUploadsAndConsistency(UploadSecurityTestCase):
    """Tests covering acceptance and extension consistency for all supported image formats."""

    def test_valid_jpeg_acceptance_and_consistency(self):
        """Valid JPEG succeeds, generates UUID filename, and agrees on canonical .jpeg extension."""
        resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="sample_camera.jpg",
            file_bytes=JPEG_FIXTURE,
            content_type="image/jpeg",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("url", data)
        url = data["url"]
        self.track_file(url)

        self.assertTrue(url.startswith("/uploads/"))
        self.assertNotIn("sample_camera", url)
        self.assert_valid_uuid_filename(url, "jpeg")

        # Verify disk file existence and contents
        disk_path = os.path.join(settings.UPLOADS_DIR, os.path.basename(url))
        self.assertTrue(os.path.exists(disk_path))
        with open(disk_path, "rb") as f:
            saved_bytes = f.read()
        self.assertEqual(saved_bytes, JPEG_FIXTURE)

        # Consistency: magic bytes detected ext, URL ext, and disk ext all agree on 'jpeg'
        detected_ext = get_file_ext_from_magic_bytes(saved_bytes[:12])
        self.assertEqual(detected_ext, "jpeg")
        self.assertTrue(url.endswith(".jpeg"))
        self.assertTrue(disk_path.endswith(".jpeg"))

    def test_valid_png_acceptance_and_consistency(self):
        """Valid PNG succeeds, generates UUID filename, and agrees on canonical .png extension."""
        resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="user_avatar.png",
            file_bytes=PNG_FIXTURE,
            content_type="image/png",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        url = data["url"]
        self.track_file(url)

        self.assertTrue(url.startswith("/uploads/"))
        self.assertNotIn("user_avatar", url)
        self.assert_valid_uuid_filename(url, "png")

        disk_path = os.path.join(settings.UPLOADS_DIR, os.path.basename(url))
        self.assertTrue(os.path.exists(disk_path))
        with open(disk_path, "rb") as f:
            saved_bytes = f.read()
        self.assertEqual(saved_bytes, PNG_FIXTURE)

        detected_ext = get_file_ext_from_magic_bytes(saved_bytes[:12])
        self.assertEqual(detected_ext, "png")
        self.assertTrue(url.endswith(".png"))
        self.assertTrue(disk_path.endswith(".png"))

    def test_valid_gif_acceptance_and_consistency(self):
        """Both GIF87a and GIF89a succeed, generate UUID filename, and agree on canonical .gif extension."""
        for label, fixture in [("GIF87a", GIF87A_FIXTURE), ("GIF89a", GIF89A_FIXTURE)]:
            with self.subTest(format=label):
                resp = self.client.post_file(
                    "/upload",
                    field_name="file",
                    filename=f"animation_{label.lower()}.gif",
                    file_bytes=fixture,
                    content_type="image/gif",
                    headers=self.auth_headers("alice"),
                )
                self.assertEqual(resp.status_code, 200)
                url = resp.json()["url"]
                self.track_file(url)

                self.assertTrue(url.startswith("/uploads/"))
                self.assertNotIn("animation", url)
                self.assert_valid_uuid_filename(url, "gif")

                disk_path = os.path.join(settings.UPLOADS_DIR, os.path.basename(url))
                self.assertTrue(os.path.exists(disk_path))
                with open(disk_path, "rb") as f:
                    saved_bytes = f.read()
                self.assertEqual(saved_bytes, fixture)

                detected_ext = get_file_ext_from_magic_bytes(saved_bytes[:12])
                self.assertEqual(detected_ext, "gif")
                self.assertTrue(url.endswith(".gif"))
                self.assertTrue(disk_path.endswith(".gif"))

    def test_valid_webp_acceptance_and_consistency(self):
        """Valid WebP succeeds, generates UUID filename, and agrees on canonical .webp extension."""
        resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="photo_card.webp",
            file_bytes=WEBP_FIXTURE,
            content_type="image/webp",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        url = data["url"]
        self.track_file(url)

        self.assertTrue(url.startswith("/uploads/"))
        self.assertNotIn("photo_card", url)
        self.assert_valid_uuid_filename(url, "webp")

        disk_path = os.path.join(settings.UPLOADS_DIR, os.path.basename(url))
        self.assertTrue(os.path.exists(disk_path))
        with open(disk_path, "rb") as f:
            saved_bytes = f.read()
        self.assertEqual(saved_bytes, WEBP_FIXTURE)

        detected_ext = get_file_ext_from_magic_bytes(saved_bytes[:12])
        self.assertEqual(detected_ext, "webp")
        self.assertTrue(url.endswith(".webp"))
        self.assertTrue(disk_path.endswith(".webp"))


# ==============================================================================
# 2. Magic-Byte Validation & MIME Spoofing (Areas 2 & 4)
# ==============================================================================
class TestMagicByteAndMimeValidation(UploadSecurityTestCase):
    """Tests verifying content magic bytes determine file handling over client metadata."""

    def test_magic_bytes_determine_extension_over_misleading_filename(self):
        """Genuine content signature determines the extension despite misleading client filename."""
        # Valid PNG with .jpg filename
        resp_png = self.client.post_file(
            "/upload",
            field_name="file",
            filename="deceptive_photo.jpg",
            file_bytes=PNG_FIXTURE,
            content_type="image/jpeg",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp_png.status_code, 200)
        url_png = resp_png.json()["url"]
        self.track_file(url_png)
        self.assertTrue(url_png.endswith(".png"), "Valid PNG must receive .png extension")
        self.assertFalse(url_png.endswith(".jpg"))

        # Valid JPEG with .png filename
        resp_jpeg = self.client.post_file(
            "/upload",
            field_name="file",
            filename="deceptive_graphic.png",
            file_bytes=JPEG_FIXTURE,
            content_type="image/png",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp_jpeg.status_code, 200)
        url_jpeg = resp_jpeg.json()["url"]
        self.track_file(url_jpeg)
        self.assertTrue(url_jpeg.endswith(".jpeg"), "Valid JPEG must receive .jpeg extension")
        self.assertFalse(url_jpeg.endswith(".png"))

    def test_content_signature_overrides_client_mime_type(self):
        """Valid image content is accepted regardless of arbitrary or mismatched client MIME types."""
        # Valid PNG sent as application/octet-stream
        resp_octet = self.client.post_file(
            "/upload",
            field_name="file",
            filename="data.bin",
            file_bytes=PNG_FIXTURE,
            content_type="application/octet-stream",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp_octet.status_code, 200)
        self.track_file(resp_octet.json()["url"])
        self.assertTrue(resp_octet.json()["url"].endswith(".png"))

        # Valid JPEG sent as text/plain
        resp_txt = self.client.post_file(
            "/upload",
            field_name="file",
            filename="note.txt",
            file_bytes=JPEG_FIXTURE,
            content_type="text/plain",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp_txt.status_code, 200)
        self.track_file(resp_txt.json()["url"])
        self.assertTrue(resp_txt.json()["url"].endswith(".jpeg"))

    def test_mime_spoofing_with_unsupported_content_rejected(self):
        """Unsupported content pretending to be an image via MIME type is rejected with 415."""
        # Executable binary sent with image/png MIME
        resp_exe = self.client.post_file(
            "/upload",
            field_name="file",
            filename="malware.png",
            file_bytes=b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00",
            content_type="image/png",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp_exe.status_code, 415)
        self.assertEqual(resp_exe.json().get("detail"), "Unsupported or invalid image file type")

        # Plain text sent with image/jpeg MIME
        resp_txt = self.client.post_file(
            "/upload",
            field_name="file",
            filename="spoofed.jpg",
            file_bytes=b"Plain text claiming to be a photograph",
            content_type="image/jpeg",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp_txt.status_code, 415)

        # BMP bytes sent with image/webp MIME
        resp_bmp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="spoofed.webp",
            file_bytes=b"BM\x36\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00\x28\x00",
            content_type="image/webp",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp_bmp.status_code, 415)

        # PHP script tag sent with image/png MIME
        resp_php = self.client.post_file(
            "/upload",
            field_name="file",
            filename="webshell.png",
            file_bytes=b"<?php echo 'malicious code execution'; ?>",
            content_type="image/png",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp_php.status_code, 415)


# ==============================================================================
# 3. Extension Spoofing & Filename / Path Safety (Areas 3 & 8)
# ==============================================================================
class TestExtensionAndPathSafety(UploadSecurityTestCase):
    """Tests verifying dangerous extensions and path traversal filenames cannot compromise storage."""

    def test_executable_and_script_extensions_cannot_persist(self):
        """Original extensions (.exe, .html, .php, .sh) are replaced with validated image extensions."""
        dangerous_cases = [
            ("payload.exe", PNG_FIXTURE, "png"),
            ("exploit.html", JPEG_FIXTURE, "jpeg"),
            ("backdoor.php", GIF89A_FIXTURE, "gif"),
            ("script.sh", WEBP_FIXTURE, "webp"),
        ]
        for filename, fixture, expected_ext in dangerous_cases:
            with self.subTest(filename=filename):
                resp = self.client.post_file(
                    "/upload",
                    field_name="file",
                    filename=filename,
                    file_bytes=fixture,
                    content_type="application/octet-stream",
                    headers=self.auth_headers("alice"),
                )
                self.assertEqual(resp.status_code, 200)
                url = resp.json()["url"]
                self.track_file(url)

                self.assertTrue(url.endswith(f".{expected_ext}"))
                self.assertNotIn(".exe", url)
                self.assertNotIn(".html", url)
                self.assertNotIn(".php", url)
                self.assertNotIn(".sh", url)
                self.assert_valid_uuid_filename(url, expected_ext)

    def test_path_traversal_filenames_cannot_escape_uploads_dir(self):
        """Filenames with Unix and Windows path traversal sequences cannot escape the upload directory."""
        traversal_filenames = [
            "../../evil.png",
            "..\\..\\evil.png",
            "/tmp/evil.png",
            "C:\\temp\\evil.png",
            "../../../../etc/passwd.png",
            "..\\..\\..\\Windows\\System32\\calc.png",
        ]
        uploads_real_dir = os.path.realpath(settings.UPLOADS_DIR)

        for filename in traversal_filenames:
            with self.subTest(filename=filename):
                resp = self.client.post_file(
                    "/upload",
                    field_name="file",
                    filename=filename,
                    file_bytes=PNG_FIXTURE,
                    content_type="image/png",
                    headers=self.auth_headers("alice"),
                )
                self.assertEqual(resp.status_code, 200)
                url = resp.json()["url"]
                self.track_file(url)

                basename = os.path.basename(url)
                disk_path = os.path.join(settings.UPLOADS_DIR, basename)
                real_disk_path = os.path.realpath(disk_path)

                # Storage path must be strictly inside the configured uploads directory
                common = os.path.commonpath([uploads_real_dir, real_disk_path])
                self.assertEqual(common, uploads_real_dir)
                self.assertTrue(os.path.exists(real_disk_path))
                self.assert_valid_uuid_filename(url, "png")


# ==============================================================================
# 4. Size Limits & Oversized Upload Cleanup (Areas 5 & 6)
# ==============================================================================
class TestSizeLimitsAndOversizedCleanup(UploadSecurityTestCase):
    """Tests covering 5 MB upload limits and partial file removal on size violations."""

    def test_size_limit_boundaries_and_rejection(self):
        """Payloads below and at 5 MB succeed; payloads above 5 MB are rejected with 413."""
        # 1. Below limit (64 KB valid PNG)
        small_payload = PNG_FIXTURE + b"\x00" * (64 * 1024)
        resp_small = self.client.post_file(
            "/upload",
            field_name="file",
            filename="small.png",
            file_bytes=small_payload,
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp_small.status_code, 200)
        self.track_file(resp_small.json()["url"])

        # 2. Exact 5 MB boundary (5 * 1024 * 1024 bytes)
        exact_payload = PNG_FIXTURE + b"\x00" * (MAX_UPLOAD_SIZE - len(PNG_FIXTURE))
        self.assertEqual(len(exact_payload), MAX_UPLOAD_SIZE)
        resp_exact = self.client.post_file(
            "/upload",
            field_name="file",
            filename="exact_5mb.png",
            file_bytes=exact_payload,
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp_exact.status_code, 200)
        self.track_file(resp_exact.json()["url"])

        # 3. Above 5 MB boundary (5 MB + 1024 bytes)
        oversized_payload = PNG_FIXTURE + b"\x00" * (MAX_UPLOAD_SIZE - len(PNG_FIXTURE) + 1024)
        resp_over = self.client.post_file(
            "/upload",
            field_name="file",
            filename="oversized.png",
            file_bytes=oversized_payload,
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp_over.status_code, 413)
        self.assertEqual(resp_over.json().get("detail"), "File too large")

    def test_oversized_upload_leaves_no_partial_file(self):
        """When an upload exceeds 5 MB, partial files are removed and no artifacts remain."""
        oversized_payload = PNG_FIXTURE + b"\x00" * (MAX_UPLOAD_SIZE - len(PNG_FIXTURE) + 16 * 1024)

        resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="overflow.png",
            file_bytes=oversized_payload,
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp.status_code, 413)

        # Upload directory must contain no extra or partial files
        current_files = set(os.listdir(settings.UPLOADS_DIR))
        self.assertEqual(
            current_files,
            self._initial_files,
            f"Oversized upload left partial files on disk: {current_files - self._initial_files}",
        )


# ==============================================================================
# 5. Rejected Upload Cleanup (Area 7)
# ==============================================================================
class TestRejectedUploadCleanup(UploadSecurityTestCase):
    """Tests verifying rejected uploads leave zero orphaned files on disk."""

    def test_rejected_uploads_leave_no_artifacts(self):
        """Rejected uploads across various defect types leave no files in the upload directory."""
        rejected_scenarios = [
            ("invalid_text.txt", b"Hello this is not an image", "text/plain", 415),
            ("corrupt_webp.webp", b"RIFF\x20\x00\x00\x00NOTW" + b"\x00" * 16, "image/webp", 415),
            ("empty_file.png", b"", "image/png", 400),
            ("executable.png", b"MZ\x90\x00" + b"\x00" * 32, "image/png", 415),
            ("pdf_doc.png", b"%PDF-1.4\n%header\n", "image/png", 415),
        ]

        for filename, payload, mime, expected_status in rejected_scenarios:
            with self.subTest(scenario=filename):
                resp = self.client.post_file(
                    "/upload",
                    field_name="file",
                    filename=filename,
                    file_bytes=payload,
                    content_type=mime,
                    headers=self.auth_headers("alice"),
                )
                self.assertEqual(resp.status_code, expected_status)

                # Confirm upload directory has zero new files
                current_files = set(os.listdir(settings.UPLOADS_DIR))
                self.assertEqual(
                    current_files,
                    self._initial_files,
                    f"Rejected upload '{filename}' left files: {current_files - self._initial_files}",
                )


# ==============================================================================
# 6. Unicode & Unusual Filenames (Area 12)
# ==============================================================================
class TestUnicodeAndUnusualFilenames(UploadSecurityTestCase):
    """Tests verifying unusual and Unicode filenames are safely accepted and sanitized."""

    def test_unicode_spaces_and_special_character_filenames(self):
        """Filenames with spaces, Unicode characters, multiple dots, and reserved names succeed safely."""
        unusual_names = [
            ("my vacation photo 2026.png", PNG_FIXTURE, "png"),
            ("사진_テスト_🌸.jpeg", JPEG_FIXTURE, "jpeg"),
            ("archive.tar.gz.webp", WEBP_FIXTURE, "webp"),
            ("nul.png", PNG_FIXTURE, "png"),
            ("con.gif", GIF89A_FIXTURE, "gif"),
        ]

        for original_name, fixture, expected_ext in unusual_names:
            with self.subTest(name=original_name):
                resp = self.client.post_file(
                    "/upload",
                    field_name="file",
                    filename=original_name,
                    file_bytes=fixture,
                    headers=self.auth_headers("alice"),
                )
                self.assertEqual(resp.status_code, 200)
                url = resp.json()["url"]
                self.track_file(url)

                self.assertTrue(url.startswith("/uploads/"))
                self.assert_valid_uuid_filename(url, expected_ext)

                disk_path = os.path.join(settings.UPLOADS_DIR, os.path.basename(url))
                self.assertTrue(os.path.exists(disk_path))


# ==============================================================================
# 7. Allowlist Regression (Area 13)
# ==============================================================================
class TestAllowlistRegression(UploadSecurityTestCase):
    """Tests verifying the allowlist strictly admits only JPEG, PNG, GIF, and WebP."""

    def test_allowlist_contents_and_unsupported_formats(self):
        """Allowlist maps strictly to jpeg, png, gif, webp; other formats are rejected with 415."""
        # Verify allowlist mapping integrity
        allowed_extensions = set(ALLOWED_MAGIC_BYTES.values())
        self.assertEqual(allowed_extensions, {"jpeg", "png", "gif", "webp"})

        # Representative unsupported binary headers
        unsupported_formats = [
            ("document.pdf", b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n"),
            ("bitmap.bmp", b"BM\x36\x00\x00\x00\x00\x00\x00\x00\x36\x00"),
            ("tiff_le.tiff", b"II*\x00\x08\x00\x00\x00"),
            ("archive.zip", b"PK\x03\x04\x14\x00\x00\x00\x08\x00"),
            ("binary.elf", b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00"),
        ]

        for filename, payload in unsupported_formats:
            with self.subTest(unsupported=filename):
                resp = self.client.post_file(
                    "/upload",
                    field_name="file",
                    filename=filename,
                    file_bytes=payload,
                    headers=self.auth_headers("alice"),
                )
                self.assertEqual(resp.status_code, 415)
                self.assertEqual(resp.json().get("detail"), "Unsupported or invalid image file type")


# ==============================================================================
# 8. HTTP Boundary & Response Contract (Area 14)
# ==============================================================================
class TestHttpBoundary(UploadSecurityTestCase):
    """Tests covering HTTP boundary status codes, authentication, and error responses."""

    def test_unauthenticated_upload_rejected(self):
        """POST /upload without authorization returns 401 Unauthorized."""
        resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="anon.png",
            file_bytes=PNG_FIXTURE,
        )
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json().get("detail"), "Not authenticated")

    def test_empty_file_rejected(self):
        """POST /upload with zero bytes returns 400 Bad Request."""
        resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="empty.png",
            file_bytes=b"",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json().get("detail"), "Empty file")

    def test_successful_http_upload_response_contract(self):
        """POST /upload with valid image returns exact {'url': '/uploads/<uuid>.<ext>'} contract."""
        resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="pic.png",
            file_bytes=PNG_FIXTURE,
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(list(data.keys()), ["url"])
        url = data["url"]
        self.track_file(url)
        self.assertTrue(url.startswith("/uploads/"))
        self.assertTrue(url.endswith(".png"))

    def test_invalid_type_http_response_contract(self):
        """POST /upload with invalid content returns HTTP 415 contract."""
        resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="bad.png",
            file_bytes=b"invalid non-image bytes",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp.status_code, 415)
        self.assertEqual(resp.json(), {"detail": "Unsupported or invalid image file type"})

    def test_oversized_http_response_contract(self):
        """POST /upload with oversized content returns HTTP 413 contract."""
        oversized = PNG_FIXTURE + b"\x00" * (MAX_UPLOAD_SIZE + 1024)
        resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="big.png",
            file_bytes=oversized,
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp.status_code, 413)
        self.assertEqual(resp.json(), {"detail": "File too large"})


# ==============================================================================
# 9. Profile Picture & Chat Image Integration (Areas 10 & 11)
# ==============================================================================
class TestProfileAndChatIntegration(UploadSecurityTestCase):
    """Tests covering end-to-end media integration with profile and chat history."""

    def test_profile_picture_upload_and_invalid_rejection(self):
        """Valid upload sets profile picture successfully; invalid upload cannot produce a profile picture."""
        # 1. Upload valid PNG
        up_resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="my_face.png",
            file_bytes=PNG_FIXTURE,
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(up_resp.status_code, 200)
        pic_url = up_resp.json()["url"]
        self.track_file(pic_url)

        # 2. Update profile picture via API
        set_resp = self.client.put(
            "/profile/picture",
            json={"profile_picture": pic_url},
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(set_resp.status_code, 200)
        self.assertEqual(set_resp.json().get("profile_picture"), pic_url)

        # 3. Verify retrieved profile reflects the uploaded asset URL
        prof_resp = self.client.get("/profile/", headers=self.auth_headers("alice"))
        self.assertEqual(prof_resp.status_code, 200)
        self.assertEqual(prof_resp.json().get("profile_picture"), pic_url)

        # 4. Attempting to upload invalid file fails and produces no usable asset URL
        bad_resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="exploit.exe",
            file_bytes=b"MZ\x90\x00bad_executable",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(bad_resp.status_code, 415)
        self.assertNotIn("url", bad_resp.json())

    def test_chat_image_upload_and_history_integration(self):
        """Valid image upload integrates with chat messages and history; rejected upload cannot be sent."""
        # 1. Alice uploads valid WebP image
        up_resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="chat_sticker.webp",
            file_bytes=WEBP_FIXTURE,
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(up_resp.status_code, 200)
        img_url = up_resp.json()["url"]
        self.track_file(img_url)

        # 2. Alice sends chat message containing image_url to Bob
        msg_resp = self.client.post(
            "/messages/bob",
            json={"text": "Check this sticker", "image_url": img_url},
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(msg_resp.status_code, 200)
        self.assertEqual(msg_resp.json().get("image_url"), img_url)

        # 3. Bob retrieves chat history with Alice and verifies image_url is persisted
        hist_resp = self.client.get(
            "/chat/history/alice",
            headers=self.auth_headers("bob"),
        )
        self.assertEqual(hist_resp.status_code, 200)
        messages = hist_resp.json()
        self.assertTrue(any(m.get("image_url") == img_url for m in messages))

        # 4. Rejected upload fails with 415, preventing upload-then-send chat flow
        bad_resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="malware.sh",
            file_bytes=b"#!/bin/bash\nrm -rf /",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(bad_resp.status_code, 415)
        self.assertNotIn("url", bad_resp.json())


# ==============================================================================
# 10. Phase R1 Media Authorization & Previews
# ==============================================================================
class TestMediaAuthorizationAndPreviews(UploadSecurityTestCase):
    """Tests covering Phase R1 private media authorization, lifecycle, and preview formatting."""

    def test_authenticated_participants_can_access_chat_image(self):
        """Sender and receiver can access uploaded chat image; unauthenticated and third-party users cannot."""
        # 1. Alice uploads valid PNG
        up_resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="private_snap.png",
            file_bytes=PNG_FIXTURE,
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(up_resp.status_code, 200)
        img_url = up_resp.json()["url"]
        self.track_file(img_url)

        # 2. Alice sends chat message containing image_url to Bob
        msg_resp = self.client.post(
            "/messages/bob",
            json={"text": "For your eyes only", "image_url": img_url},
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(msg_resp.status_code, 200)

        # 3. Alice (sender) can access image
        alice_get = self.client.get(img_url, headers=self.auth_headers("alice"))
        self.assertEqual(alice_get.status_code, 200)
        self.assertEqual(alice_get.content, PNG_FIXTURE)
        self.assertEqual(alice_get.headers.get("content-type"), "image/png")

        # 4. Bob (receiver) can access image
        bob_get = self.client.get(img_url, headers=self.auth_headers("bob"))
        self.assertEqual(bob_get.status_code, 200)
        self.assertEqual(bob_get.content, PNG_FIXTURE)

    def test_unauthenticated_access_rejected(self):
        """Unauthenticated requests to /uploads/{filename} return 401."""
        up_resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="private.png",
            file_bytes=PNG_FIXTURE,
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(up_resp.status_code, 200)
        img_url = up_resp.json()["url"]
        self.track_file(img_url)

        # No auth header -> 401
        anon_get = self.client.get(img_url)
        self.assertEqual(anon_get.status_code, 401)

    def test_third_party_user_rejected_with_403(self):
        """Third party user who is neither sender nor receiver receives 403."""
        # Alice sends to Bob
        up_resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="alice_bob_only.png",
            file_bytes=PNG_FIXTURE,
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(up_resp.status_code, 200)
        img_url = up_resp.json()["url"]
        self.track_file(img_url)

        msg_resp = self.client.post(
            "/messages/bob",
            json={"text": "Secret message", "image_url": img_url},
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(msg_resp.status_code, 200)

        # Charlie tries to access -> 403
        charlie_get = self.client.get(img_url, headers=self.auth_headers("charlie"))
        self.assertEqual(charlie_get.status_code, 403)
        self.assertIn("Not authorized", charlie_get.json().get("detail", ""))

    def test_deleted_image_returns_404(self):
        """Soft-deleted message media immediately returns 404 to all users."""
        up_resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="soon_deleted.png",
            file_bytes=PNG_FIXTURE,
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(up_resp.status_code, 200)
        img_url = up_resp.json()["url"]
        self.track_file(img_url)

        msg_resp = self.client.post(
            "/messages/bob",
            json={"text": "Ephemeral photo", "image_url": img_url},
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(msg_resp.status_code, 200)
        msg_id = msg_resp.json()["id"]

        # Before deletion: accessible
        self.assertEqual(self.client.get(img_url, headers=self.auth_headers("alice")).status_code, 200)

        # Delete message
        del_resp = self.client.delete(f"/messages/{msg_id}", headers=self.auth_headers("alice"))
        self.assertEqual(del_resp.status_code, 200)

        # After deletion: immediately 404 for both participants
        self.assertEqual(self.client.get(img_url, headers=self.auth_headers("alice")).status_code, 404)
        self.assertEqual(self.client.get(img_url, headers=self.auth_headers("bob")).status_code, 404)

    def test_unlinked_media_returns_404(self):
        """Uploaded media not linked to any active message or profile returns 404."""
        up_resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="orphan.png",
            file_bytes=PNG_FIXTURE,
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(up_resp.status_code, 200)
        img_url = up_resp.json()["url"]
        self.track_file(img_url)

        # Alice herself gets 404 because file is not linked to any message or profile
        get_resp = self.client.get(img_url, headers=self.auth_headers("alice"))
        self.assertEqual(get_resp.status_code, 404)

    def test_authenticated_profile_picture_access_works(self):
        """Any authenticated user can view an uploaded profile picture; unauthenticated cannot."""
        up_resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="avatar.png",
            file_bytes=PNG_FIXTURE,
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(up_resp.status_code, 200)
        pic_url = up_resp.json()["url"]
        self.track_file(pic_url)

        set_resp = self.client.put(
            "/profile/picture",
            json={"profile_picture": pic_url},
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(set_resp.status_code, 200)

        # Alice can access
        self.assertEqual(self.client.get(pic_url, headers=self.auth_headers("alice")).status_code, 200)

        # Bob (friend/other authenticated user) can access
        self.assertEqual(self.client.get(pic_url, headers=self.auth_headers("bob")).status_code, 200)

        # Charlie (any authenticated user) can access
        self.assertEqual(self.client.get(pic_url, headers=self.auth_headers("charlie")).status_code, 200)

        # Unauthenticated cannot access
        self.assertEqual(self.client.get(pic_url).status_code, 401)

    def test_image_only_reply_and_conversation_preview_serialization(self):
        """Image-only message serializes as '📷 Photo' in replies and conversation list."""
        up_resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="photo_only.png",
            file_bytes=PNG_FIXTURE,
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(up_resp.status_code, 200)
        img_url = up_resp.json()["url"]
        self.track_file(img_url)

        # Alice sends image-only message (empty text)
        msg_resp = self.client.post(
            "/messages/bob",
            json={"text": "", "image_url": img_url},
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(msg_resp.status_code, 200)
        img_msg_id = msg_resp.json()["id"]

        # 1. Bob checks conversations list -> last_message should be "📷 Photo"
        conv_resp = self.client.get("/conversations", headers=self.auth_headers("bob"))
        self.assertEqual(conv_resp.status_code, 200)
        convs = conv_resp.json()
        alice_conv = next((c for c in convs if c["username"] == "alice"), None)
        self.assertIsNotNone(alice_conv)
        self.assertEqual(alice_conv["last_message"], "📷 Photo")

        # 2. Bob replies to image-only message
        reply_resp = self.client.post(
            "/messages/alice",
            json={"text": "Awesome capture!", "reply_to_message_id": img_msg_id},
            headers=self.auth_headers("bob"),
        )
        self.assertEqual(reply_resp.status_code, 200)
        reply_data = reply_resp.json()
        self.assertIn("reply_to", reply_data)
        self.assertEqual(reply_data["reply_to"]["content"], "📷 Photo")


# ==============================================================================
# 11. Phase R2 Video Messaging Upload Security & Invariants
# ==============================================================================
class TestPhaseR2VideoUploadSecurity(UploadSecurityTestCase):
    """Focused tests covering Phase R2 video upload security, validation, and lifecycle."""

    def test_valid_mp4_upload_accepted(self):
        """Valid MP4 upload returns 200 and URL ending with .mp4."""
        resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="sample.mp4",
            file_bytes=MP4_FIXTURE,
            content_type="video/mp4",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp.status_code, 200)
        url = resp.json().get("url")
        self.assertIsNotNone(url)
        self.assertTrue(url.startswith("/uploads/"))
        self.assertTrue(url.endswith(".mp4"))
        self.track_file(url)

    def test_valid_webm_upload_accepted(self):
        """Valid WebM upload returns 200 and URL ending with .webm."""
        resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="sample.webm",
            file_bytes=WEBM_FIXTURE,
            content_type="video/webm",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp.status_code, 200)
        url = resp.json().get("url")
        self.assertIsNotNone(url)
        self.assertTrue(url.startswith("/uploads/"))
        self.assertTrue(url.endswith(".webm"))
        self.track_file(url)

    def test_invalid_video_magic_bytes_rejected(self):
        """Invalid content spoofing video extension returns 415."""
        resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="fake.mp4",
            file_bytes=b"PLAIN_TEXT_NOT_A_VIDEO_FILE_AT_ALL",
            content_type="video/mp4",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp.status_code, 415)
        self.assertNotIn("url", resp.json())

    def test_oversized_video_rejected_and_cleaned_up(self):
        """Video exceeding MAX_VIDEO_SIZE_BYTES returns 413 and cleans up partial file."""
        from unittest.mock import patch
        from backend.services import upload_service

        # Temporarily mock video size limit to small threshold
        with patch.object(upload_service, "get_file_size_limit", return_value=len(MP4_FIXTURE) + 10):
            oversized_bytes = MP4_FIXTURE + b"\x00" * 100
            resp = self.client.post_file(
                "/upload",
                field_name="file",
                filename="big.mp4",
                file_bytes=oversized_bytes,
                content_type="video/mp4",
                headers=self.auth_headers("alice"),
            )
            self.assertEqual(resp.status_code, 413)

            # Confirm no leftover files created on disk
            current_files = set(os.listdir(settings.UPLOADS_DIR)) if os.path.exists(settings.UPLOADS_DIR) else set()
            new_files = current_files - self._initial_files
            self.assertEqual(len(new_files), 0, f"Leftover files found on disk after 413: {new_files}")

    def test_authenticated_participants_can_access_chat_video(self):
        """Sender and receiver can access video via GET /uploads/{filename}; non-participants cannot."""
        # 1. Alice uploads MP4
        up_resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="private_video.mp4",
            file_bytes=MP4_FIXTURE,
            content_type="video/mp4",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(up_resp.status_code, 200)
        vid_url = up_resp.json()["url"]
        self.track_file(vid_url)

        # 2. Alice sends message with video_url to Bob
        msg_resp = self.client.post(
            "/messages/bob",
            json={"text": "Check this video", "video_url": vid_url},
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(msg_resp.status_code, 200)
        msg_data = msg_resp.json()
        self.assertEqual(msg_data.get("video_url"), vid_url)
        self.assertEqual(msg_data.get("media_type"), "video")

        # 3. Alice (sender) accesses video -> 200
        alice_get = self.client.get(vid_url, headers=self.auth_headers("alice"))
        self.assertEqual(alice_get.status_code, 200)
        self.assertEqual(alice_get.content, MP4_FIXTURE)
        self.assertEqual(alice_get.headers.get("content-type"), "video/mp4")

        # 4. Bob (receiver) accesses video -> 200
        bob_get = self.client.get(vid_url, headers=self.auth_headers("bob"))
        self.assertEqual(bob_get.status_code, 200)
        self.assertEqual(bob_get.content, MP4_FIXTURE)

        # 5. Anonymous request -> 401
        anon_get = self.client.get(vid_url)
        self.assertEqual(anon_get.status_code, 401)

        # 6. Charlie (third-party) -> 403
        charlie_get = self.client.get(vid_url, headers=self.auth_headers("charlie"))
        self.assertEqual(charlie_get.status_code, 403)

    def test_deleted_video_returns_404(self):
        """Soft-deleted message video immediately returns 404 to all users."""
        up_resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="deleted_video.mp4",
            file_bytes=MP4_FIXTURE,
            content_type="video/mp4",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(up_resp.status_code, 200)
        vid_url = up_resp.json()["url"]
        self.track_file(vid_url)

        msg_resp = self.client.post(
            "/messages/bob",
            json={"text": "Temporary clip", "video_url": vid_url},
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(msg_resp.status_code, 200)
        msg_id = msg_resp.json()["id"]

        # Before deletion: accessible
        self.assertEqual(self.client.get(vid_url, headers=self.auth_headers("alice")).status_code, 200)

        # Delete message
        del_resp = self.client.delete(f"/messages/{msg_id}", headers=self.auth_headers("alice"))
        self.assertEqual(del_resp.status_code, 200)

        # After deletion: immediately 404
        self.assertEqual(self.client.get(vid_url, headers=self.auth_headers("alice")).status_code, 404)
        self.assertEqual(self.client.get(vid_url, headers=self.auth_headers("bob")).status_code, 404)

    def test_unlinked_video_returns_404(self):
        """Uploaded video not linked to any active message returns 404."""
        up_resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="orphan_video.mp4",
            file_bytes=MP4_FIXTURE,
            content_type="video/mp4",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(up_resp.status_code, 200)
        vid_url = up_resp.json()["url"]
        self.track_file(vid_url)

        # Not linked to any message -> 404
        self.assertEqual(self.client.get(vid_url, headers=self.auth_headers("alice")).status_code, 404)

    def test_video_reply_and_conversation_preview_serialization(self):
        """Video message serializes as '🎥 Video' in replies and conversation list."""
        up_resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="preview_vid.mp4",
            file_bytes=MP4_FIXTURE,
            content_type="video/mp4",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(up_resp.status_code, 200)
        vid_url = up_resp.json()["url"]
        self.track_file(vid_url)

        # Alice sends video-only message
        msg_resp = self.client.post(
            "/messages/bob",
            json={"text": "", "video_url": vid_url},
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(msg_resp.status_code, 200)
        vid_msg_id = msg_resp.json()["id"]

        # 1. Bob checks conversations list -> last_message should be "🎥 Video"
        conv_resp = self.client.get("/conversations", headers=self.auth_headers("bob"))
        self.assertEqual(conv_resp.status_code, 200)
        convs = conv_resp.json()
        alice_conv = next((c for c in convs if c["username"] == "alice"), None)
        self.assertIsNotNone(alice_conv)
        self.assertEqual(alice_conv["last_message"], "🎥 Video")

        # 2. Bob replies to video message
        reply_resp = self.client.post(
            "/messages/alice",
            json={"text": "Nice video clip!", "reply_to_message_id": vid_msg_id},
            headers=self.auth_headers("bob"),
        )
        self.assertEqual(reply_resp.status_code, 200)
        reply_data = reply_resp.json()
        self.assertIn("reply_to", reply_data)
        self.assertEqual(reply_data["reply_to"]["content"], "🎥 Video")


if __name__ == "__main__":
    unittest.main()
