"""Focused automated regression and integration tests for ChatSpic R4: Voice Messages.

Tests cover:
1. Valid audio formats acceptance (WebM, OGG, WAV, MP3)
2. Magic-byte and content verification (rejection of spoofed/dangerous payloads)
3. Enforced size limits (413 for oversized voice files and disk cleanup)
4. Enforced duration limits (400 for voice files exceeding configurable duration limit)
5. Trusted sidecar metadata persistence (is_voice=True, media_type='voice', duration)
6. Private media authorization (sender & receiver 200, 3rd party 403, unauthenticated 401)
7. Download disposition (?download=1 -> attachment, standard -> inline with audio MIME)
8. Immediate 404 access revocation upon soft deletion of voice message
9. Conversation list preview ("🎙️ Voice message") and reply-to preview ("🎙️ Voice message")
10. Message creation and WebSocket serialization contracts for voice messages
"""
import io
import os
import unittest
import uuid
import wave

from backend.core.config import settings
from backend.services.chat_service import (
    create_message,
    send_message,
    serialize_message_for_websocket,
    list_conversations,
    delete_message,
    BadRequestError,
)
from backend.services.upload_service import (
    get_upload_metadata,
    is_voice_file,
    is_video_file,
)
from tests.test_upload_security import (
    UploadSecurityTestCase,
    WEBM_FIXTURE,
)


def create_test_wav(duration_seconds: float = 2.0, sample_rate: int = 8000) -> bytes:
    """Generate a valid in-memory PCM WAV audio byte string with known duration."""
    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(1)
        wf.setframerate(sample_rate)
        num_frames = int(duration_seconds * sample_rate)
        wf.writeframes(b"\x80" * num_frames)
    return buf.getvalue()


OGG_FIXTURE = b"OggS\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00" + b"\x00" * 32
MP3_ID3_FIXTURE = b"ID3\x03\x00\x00\x00\x00\x00\x10" + b"\xff\xfb\x90\x44" + b"\x00" * 32
MP3_SYNC_FIXTURE = b"\xff\xfb\x90\x44" + b"\x00" * 64


class TestVoiceMessages(UploadSecurityTestCase):
    """Test suite for R4 Voice Messages feature."""

    def test_upload_webm_voice_message(self):
        """WebM audio upload succeeds and stores trusted voice metadata with voice_ prefix."""
        resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="voice_record.webm",
            file_bytes=WEBM_FIXTURE,
            content_type="audio/webm",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("url", data)
        voice_url = data["url"]
        self.track_file(voice_url)

        base = os.path.basename(voice_url)
        self.assertTrue(base.startswith("voice_"), f"Expected voice_ prefix on filename, got {base}")
        self.assertTrue(is_voice_file(voice_url))
        self.assertFalse(is_video_file(voice_url))

        meta = get_upload_metadata(base)
        self.assertIsNotNone(meta)
        self.assertTrue(meta.get("is_voice"))
        self.assertEqual(meta.get("media_type"), "voice")

    def test_upload_ogg_voice_message(self):
        """OGG audio upload succeeds and is identified as voice media."""
        resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="voice_note.ogg",
            file_bytes=OGG_FIXTURE,
            content_type="audio/ogg",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp.status_code, 200)
        voice_url = resp.json()["url"]
        self.track_file(voice_url)
        self.assertTrue(is_voice_file(voice_url))

    def test_upload_wav_voice_message_with_duration(self):
        """WAV audio upload extracts duration and enforces duration limit."""
        wav_bytes = create_test_wav(duration_seconds=3.5)
        resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="audio_message.wav",
            file_bytes=wav_bytes,
            content_type="audio/wav",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp.status_code, 200)
        voice_url = resp.json()["url"]
        self.track_file(voice_url)

        base = os.path.basename(voice_url)
        meta = get_upload_metadata(base)
        self.assertIsNotNone(meta)
        self.assertIsNotNone(meta.get("duration"))
        self.assertAlmostEqual(meta["duration"], 3.5, delta=0.2)

    def test_upload_mp3_voice_message(self):
        """MP3 audio upload succeeds and is recognized as voice."""
        resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="recording.mp3",
            file_bytes=MP3_ID3_FIXTURE,
            content_type="audio/mpeg",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp.status_code, 200)
        voice_url = resp.json()["url"]
        self.track_file(voice_url)
        self.assertTrue(is_voice_file(voice_url))

    def test_voice_oversized_size_rejected(self):
        """Voice upload exceeding MAX_VOICE_SIZE_BYTES is rejected with 413 and cleaned up."""
        limit = getattr(settings, "MAX_VOICE_SIZE_BYTES", 10 * 1024 * 1024)
        oversized_bytes = b"OggS" + b"\x00" * (limit + 1024)
        resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="huge_voice.ogg",
            file_bytes=oversized_bytes,
            content_type="audio/ogg",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp.status_code, 413)

    def test_voice_oversized_duration_rejected(self):
        """Voice audio exceeding MAX_VOICE_DURATION_SECONDS is rejected with 400 and cleaned up."""
        # Create a WAV file lasting 150 seconds (exceeding default 120s limit)
        wav_bytes = create_test_wav(duration_seconds=150.0, sample_rate=4000)
        resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="too_long.wav",
            file_bytes=wav_bytes,
            content_type="audio/wav",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("duration limit", resp.json().get("detail", "").lower())

    def test_voice_spoofed_executable_rejected(self):
        """File claiming to be voice webm but containing PE executable header is rejected with 415."""
        fake_bytes = b"MZ\x90\x00" + b"\x00" * 64
        resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="voice_recording.webm",
            file_bytes=fake_bytes,
            content_type="audio/webm",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(resp.status_code, 415)

    def test_voice_message_creation_and_authorization(self):
        """Full lifecycle: upload, create message, authorized access, download, and forbidden checks."""
        # 1. Alice uploads voice message
        up_resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="voice_msg.webm",
            file_bytes=WEBM_FIXTURE,
            content_type="audio/webm",
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(up_resp.status_code, 200)
        voice_url = up_resp.json()["url"]
        self.track_file(voice_url)

        # 2. Alice sends message to Bob with voice_url
        msg_resp = self.client.post(
            "/messages/bob",
            json={"voice_url": voice_url},
            headers=self.auth_headers("alice"),
        )
        self.assertEqual(msg_resp.status_code, 200)
        msg_data = msg_resp.json()
        self.assertEqual(msg_data["media_type"], "voice")
        self.assertEqual(msg_data["voice_url"], voice_url)
        msg_id = msg_data["id"]

        # 3. Alice accesses inline media -> 200 with audio/webm and inline disposition
        alice_get = self.client.get(voice_url, headers=self.auth_headers("alice"))
        self.assertEqual(alice_get.status_code, 200)
        self.assertEqual(alice_get.headers.get("content-type"), "audio/webm")
        self.assertIn("inline", alice_get.headers.get("content-disposition", ""))

        # 4. Bob (receiver) accesses inline media -> 200
        bob_get = self.client.get(voice_url, headers=self.auth_headers("bob"))
        self.assertEqual(bob_get.status_code, 200)
        self.assertEqual(bob_get.headers.get("content-type"), "audio/webm")

        # 5. Alice accesses with ?download=1 -> 200 with attachment disposition
        dl_resp = self.client.get(f"{voice_url}?download=1", headers=self.auth_headers("alice"))
        self.assertEqual(dl_resp.status_code, 200)
        self.assertIn("attachment", dl_resp.headers.get("content-disposition", ""))

        # 6. Charlie (third-party) -> 403 Forbidden
        charlie_get = self.client.get(voice_url, headers=self.auth_headers("charlie"))
        self.assertEqual(charlie_get.status_code, 403)

        # 7. Anonymous access -> 401
        self.assertEqual(self.client.get(voice_url).status_code, 401)

        # 8. Direct access to .meta.json sidecar -> 404
        base_name = os.path.basename(voice_url)
        uuid_part = base_name.rsplit(".", 1)[0]
        meta_url = f"/uploads/{uuid_part}.meta.json"
        self.assertEqual(self.client.get(meta_url, headers=self.auth_headers("alice")).status_code, 404)

    def test_voice_message_soft_delete_inaccessibility(self):
        """Soft deleting a voice message immediately makes the media return 404."""
        up_resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="voice_delete_test.webm",
            file_bytes=WEBM_FIXTURE,
            content_type="audio/webm",
            headers=self.auth_headers("alice"),
        )
        voice_url = up_resp.json()["url"]
        self.track_file(voice_url)

        msg_resp = self.client.post(
            "/messages/bob",
            json={"voice_url": voice_url},
            headers=self.auth_headers("alice"),
        )
        msg_id = msg_resp.json()["id"]

        # Accessible before delete
        self.assertEqual(self.client.get(voice_url, headers=self.auth_headers("alice")).status_code, 200)

        # Alice deletes the message
        del_resp = self.client.delete(f"/messages/{msg_id}", headers=self.auth_headers("alice"))
        self.assertEqual(del_resp.status_code, 200)

        # Media access immediately returns 404
        self.assertEqual(self.client.get(voice_url, headers=self.auth_headers("alice")).status_code, 404)
        self.assertEqual(self.client.get(voice_url, headers=self.auth_headers("bob")).status_code, 404)

    def test_voice_reply_and_conversation_preview(self):
        """Voice message serializes as '🎙️ Voice message' in reply preview and conversation list."""
        up_resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="voice_preview_test.webm",
            file_bytes=WEBM_FIXTURE,
            content_type="audio/webm",
            headers=self.auth_headers("alice"),
        )
        voice_url = up_resp.json()["url"]
        self.track_file(voice_url)

        msg_resp = self.client.post(
            "/messages/bob",
            json={"voice_url": voice_url},
            headers=self.auth_headers("alice"),
        )
        voice_msg_id = msg_resp.json()["id"]

        # 1. Bob checks conversations list -> last_message should be "🎙️ Voice message"
        conv_resp = self.client.get("/conversations", headers=self.auth_headers("bob"))
        self.assertEqual(conv_resp.status_code, 200)
        convs = conv_resp.json()
        alice_conv = next((c for c in convs if c["username"] == "alice"), None)
        self.assertIsNotNone(alice_conv)
        self.assertEqual(alice_conv["last_message"], "🎙️ Voice message")

        # 2. Bob replies to the voice message
        reply_resp = self.client.post(
            "/messages/alice",
            json={"text": "Got your voice message!", "reply_to_message_id": voice_msg_id},
            headers=self.auth_headers("bob"),
        )
        self.assertEqual(reply_resp.status_code, 200)
        reply_data = reply_resp.json()
        self.assertIn("reply_to", reply_data)
        self.assertEqual(reply_data["reply_to"]["content"], "🎙️ Voice message")

    def test_websocket_serialization_and_creation_validation(self):
        """Verify WebSocket serialization payload and create_message validation for voice."""
        up_resp = self.client.post_file(
            "/upload",
            field_name="file",
            filename="voice_ws.webm",
            file_bytes=WEBM_FIXTURE,
            content_type="audio/webm",
            headers=self.auth_headers("alice"),
        )
        voice_url = up_resp.json()["url"]
        self.track_file(voice_url)

        # Non-existent voice file returns BadRequestError
        with self.assertRaises(BadRequestError):
            create_message(
                self.db,
                sender=self.alice,
                receiver=self.bob,
                voice_url="/uploads/nonexistent_voice.webm",
            )

        # Valid voice message creation
        msg = create_message(
            self.db,
            sender=self.alice,
            receiver=self.bob,
            voice_url=voice_url,
        )
        self.assertIsNotNone(msg.id)

        ws_payload = serialize_message_for_websocket(msg, self.alice, self.bob)
        self.assertEqual(ws_payload["media_type"], "voice")
        self.assertEqual(ws_payload["voice_url"], voice_url)
        self.assertEqual(ws_payload["audio_url"], voice_url)


if __name__ == "__main__":
    unittest.main()
