"""Automated test suite for Web Push Notifications (Task R7).

Validates:
1. Subscription creation/update for authenticated user.
2. Unauthorized subscription access/modification is rejected.
3. User cannot register a subscription belonging to another user.
4. Notification is not generated for sender's own message.
5. Active conversation suppression logic.
6. Background/inactive conversation eligible for notification.
7. Text preview sanitization/truncation.
8. Voice message notification text is "🎙️ Voice message".
9. Invalid/expired push subscriptions are cleaned up.
10. Push delivery failure does not break normal message delivery.
11. Notification click/navigation data contains no JWT/token.
12. Service-worker-related message handling and headers.
13. Existing WebSocket and message behavior remains intact.
"""
import json
import unittest
from datetime import timedelta
from unittest.mock import patch, MagicMock

from main import app
from backend.core.config import settings, Settings
from backend.core.security import create_access_token
from backend.db.database import get_db
from backend.db.models import PushSubscription, User, Message
from backend.realtime import websocket as ws_module
from backend.services import push_service, chat_service
from tests.base import BaseTestCase
from tests.test_auth_authorization import ASGIClient


class TestPushNotifications(BaseTestCase):
    """Focused regression test suite for Web Push Notifications (Task R7)."""

    def setUp(self):
        super().setUp()

        def _override_get_db():
            try:
                yield self.db
            finally:
                pass

        self.addCleanup(self._cleanup_overrides)
        app.dependency_overrides[get_db] = _override_get_db
        self.client = ASGIClient(app)

        # Ensure push_service uses this test case's isolated SessionLocal
        self._orig_session_local = push_service.SessionLocal
        push_service.SessionLocal = self.SessionLocal
        self.addCleanup(self._restore_session_local)

        delta = timedelta(minutes=30)
        self.alice_token = create_access_token(data={"sub": self.alice.username}, expires_delta=delta)
        self.bob_token = create_access_token(data={"sub": self.bob.username}, expires_delta=delta)
        self.alice_headers = {"Authorization": f"Bearer {self.alice_token}"}
        self.bob_headers = {"Authorization": f"Bearer {self.bob_token}"}

        # Clear websocket module in-memory state between tests
        ws_module.connected_sockets.clear()
        ws_module.online_users.clear()
        ws_module.rooms.clear()
        ws_module.active_viewing_room.clear()
        ws_module.socket_visibility.clear()

    def _cleanup_overrides(self):
        app.dependency_overrides.pop(get_db, None)

    def _restore_session_local(self):
        push_service.SessionLocal = self._orig_session_local

    # --------------------------------------------------------------------------
    # 1. Subscription Creation & Update for Authenticated User
    # --------------------------------------------------------------------------
    def test_subscription_creation_and_update_authenticated(self):
        """Authenticated user can register and update a push subscription."""
        payload = {
            "endpoint": "https://fcm.googleapis.com/fcm/send/sub-alice-1",
            "keys": {
                "p256dh": "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QT9t0A4If_ZqV26Pb",
                "auth": "tBHItJI5svbpez7KI4CCXg"
            }
        }
        res = self.client.post("/push/subscribe", json=payload, headers=self.alice_headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json().get("status"), "ok")

        # Verify persisted in database
        sub = self.db.query(PushSubscription).filter(PushSubscription.user_id == self.alice.id).first()
        self.assertIsNotNone(sub)
        self.assertEqual(sub.endpoint, payload["endpoint"])
        self.assertEqual(sub.p256dh, payload["keys"]["p256dh"])
        self.assertEqual(sub.auth, payload["keys"]["auth"])

        # Update subscription (single active device per user)
        updated_payload = {
            "endpoint": "https://fcm.googleapis.com/fcm/send/sub-alice-updated",
            "keys": {
                "p256dh": "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QT9t0A4If_ZqV26Pb_NEW",
                "auth": "tBHItJI5svbpez7KI4CCXg_NEW"
            }
        }
        res2 = self.client.post("/push/subscribe", json=updated_payload, headers=self.alice_headers)
        self.assertEqual(res2.status_code, 200)

        # Ensure no duplicates: exactly 1 subscription for alice
        subs = self.db.query(PushSubscription).filter(PushSubscription.user_id == self.alice.id).all()
        self.assertEqual(len(subs), 1)
        self.assertEqual(subs[0].endpoint, updated_payload["endpoint"])

        # Check status endpoint
        res_status = self.client.get("/push/status", headers=self.alice_headers)
        self.assertEqual(res_status.status_code, 200)
        self.assertTrue(res_status.json().get("subscribed"))

        # Unsubscribe
        res_unsub = self.client.post("/push/unsubscribe", headers=self.alice_headers)
        self.assertEqual(res_unsub.status_code, 200)
        self.assertTrue(res_unsub.json().get("removed"))

        # Verify deleted
        sub_after = self.db.query(PushSubscription).filter(PushSubscription.user_id == self.alice.id).first()
        self.assertIsNone(sub_after)

    # --------------------------------------------------------------------------
    # 2. Unauthorized Subscription Access is Rejected
    # --------------------------------------------------------------------------
    def test_unauthorized_subscription_rejected(self):
        """Unauthenticated requests to all push endpoints return 401 Unauthorized."""
        payload = {
            "endpoint": "https://fcm.googleapis.com/fcm/send/sample",
            "keys": {"p256dh": "key1", "auth": "key2"}
        }
        res_sub = self.client.post("/push/subscribe", json=payload)
        self.assertEqual(res_sub.status_code, 401)

        res_unsub = self.client.post("/push/unsubscribe")
        self.assertEqual(res_unsub.status_code, 401)

        res_status = self.client.get("/push/status")
        self.assertEqual(res_status.status_code, 401)

        res_key = self.client.get("/push/vapid-public-key")
        self.assertEqual(res_key.status_code, 401)

    # --------------------------------------------------------------------------
    # 3. User Cannot Manipulate Another User's Subscription
    # --------------------------------------------------------------------------
    def test_user_cannot_register_subscription_for_another_user(self):
        """A user cannot register or tamper with another user's push subscription."""
        # Alice attempts to inject user_id in the body
        malicious_payload = {
            "endpoint": "https://fcm.googleapis.com/fcm/send/alice-trying-to-affect-bob",
            "user_id": self.bob.id,
            "keys": {"p256dh": "p256dh_key", "auth": "auth_key"}
        }
        res = self.client.post("/push/subscribe", json=malicious_payload, headers=self.alice_headers)
        self.assertEqual(res.status_code, 200)

        # In database, subscription must be assigned to Alice, NOT Bob
        alice_sub = self.db.query(PushSubscription).filter(PushSubscription.user_id == self.alice.id).first()
        bob_sub = self.db.query(PushSubscription).filter(PushSubscription.user_id == self.bob.id).first()

        self.assertIsNotNone(alice_sub)
        self.assertEqual(alice_sub.user_id, self.alice.id)
        self.assertIsNone(bob_sub)

    # --------------------------------------------------------------------------
    # 4. Notification Is Not Generated for Sender's Own Message
    # --------------------------------------------------------------------------
    def test_no_notification_for_senders_own_message(self):
        """Push notification is strictly suppressed when recipient_id == sender_id."""
        self.assertTrue(push_service.should_suppress_push(self.alice.id, self.alice.id))

        with patch("backend.services.push_service.send_webpush") as mock_send:
            push_service.deliver_push_for_message_background(
                sender_id=self.alice.id,
                recipient_id=self.alice.id,
                message_id=999,
            )
            mock_send.assert_not_called()

    # --------------------------------------------------------------------------
    # 5. Active Conversation Suppression Logic
    # --------------------------------------------------------------------------
    def test_active_conversation_suppression_logic(self):
        """Push is suppressed when recipient has a connected visible socket in the room."""
        mock_ws = MagicMock()
        ws_module.connected_sockets[self.bob.id] = [mock_ws]
        ws_module.active_viewing_room[mock_ws] = ws_module.get_dm_room(self.bob.username, self.alice.username)
        ws_module.socket_visibility[mock_ws] = True

        # Use test case SessionLocal for ws_module queries
        with patch.object(ws_module, "SessionLocal", self.SessionLocal):
            is_viewing = ws_module.is_user_actively_viewing(self.bob.id, self.alice.id)
            self.assertTrue(is_viewing)
            self.assertTrue(push_service.should_suppress_push(self.bob.id, self.alice.id))

    # --------------------------------------------------------------------------
    # 6. Background / Inactive Conversation Eligible for Notification
    # --------------------------------------------------------------------------
    def test_background_or_inactive_conversation_eligible_for_notification(self):
        """Push is NOT suppressed when recipient is offline, hidden, or in another room."""
        with patch.object(ws_module, "SessionLocal", self.SessionLocal):
            # Case A: Recipient is offline
            ws_module.connected_sockets.clear()
            self.assertFalse(ws_module.is_user_actively_viewing(self.bob.id, self.alice.id))
            self.assertFalse(push_service.should_suppress_push(self.bob.id, self.alice.id))

            # Case B: Recipient is viewing a different chat
            mock_ws = MagicMock()
            ws_module.connected_sockets[self.bob.id] = [mock_ws]
            ws_module.active_viewing_room[mock_ws] = ws_module.get_dm_room(self.bob.username, self.charlie.username)
            ws_module.socket_visibility[mock_ws] = True

            self.assertFalse(ws_module.is_user_actively_viewing(self.bob.id, self.alice.id))
            self.assertFalse(push_service.should_suppress_push(self.bob.id, self.alice.id))

            # Case C: Recipient is in the same room, but tab is hidden/minimized
            ws_module.active_viewing_room[mock_ws] = ws_module.get_dm_room(self.bob.username, self.alice.username)
            ws_module.socket_visibility[mock_ws] = False  # Tab in background

            self.assertFalse(ws_module.is_user_actively_viewing(self.bob.id, self.alice.id))
            self.assertFalse(push_service.should_suppress_push(self.bob.id, self.alice.id))

    # --------------------------------------------------------------------------
    # 7. Disconnect / Leave Cleans Up Stale Viewing State
    # --------------------------------------------------------------------------
    def test_disconnect_or_leave_cleans_up_stale_viewing_state(self):
        """Leaving a room or disconnecting removes active viewing state completely."""
        mock_ws = MagicMock()
        ws_module.connected_sockets[self.bob.id] = [mock_ws]
        room_name = ws_module.get_dm_room(self.bob.username, self.alice.username)
        ws_module.rooms[room_name] = [(mock_ws, self.bob)]
        ws_module.active_viewing_room[mock_ws] = room_name
        ws_module.socket_visibility[mock_ws] = True

        with patch.object(ws_module, "SessionLocal", self.SessionLocal):
            self.assertTrue(ws_module.is_user_actively_viewing(self.bob.id, self.alice.id))

            # Disconnect / leave cleanup
            ws_module.remove_connection_from_rooms(mock_ws)
            self.assertNotIn(mock_ws, ws_module.active_viewing_room)
            self.assertNotIn(mock_ws, ws_module.socket_visibility)
            self.assertFalse(ws_module.is_user_actively_viewing(self.bob.id, self.alice.id))

    # --------------------------------------------------------------------------
    # 8. Text Preview Sanitization & Truncation
    # --------------------------------------------------------------------------
    def test_text_preview_sanitization_and_truncation(self):
        """Sanitizes HTML, removes control characters, and truncates long previews."""
        # HTML tag stripping
        html_text = "<script>alert('xss')</script>Hello <b>World</b>!"
        clean = push_service.sanitize_preview_text(html_text)
        self.assertEqual(clean, "Hello World!")

        # Control characters and newlines
        ctrl_text = "Line 1\r\n\tLine 2\x00\x07End"
        clean_ctrl = push_service.sanitize_preview_text(ctrl_text)
        self.assertEqual(clean_ctrl, "Line 1 Line 2 End")

        # Long text truncation
        long_text = "A" * 150
        truncated = push_service.sanitize_preview_text(long_text, max_length=50)
        self.assertEqual(len(truncated), 53)  # 50 chars + "..."
        self.assertTrue(truncated.endswith("..."))

        # Empty/None handling
        self.assertEqual(push_service.sanitize_preview_text(None), "")
        self.assertEqual(push_service.sanitize_preview_text(""), "")

    # --------------------------------------------------------------------------
    # 9. Voice Message Notification Text Is Exact String
    # --------------------------------------------------------------------------
    def test_voice_message_notification_text_exact_string(self):
        """Voice messages format body to exactly '🎙️ Voice message'."""
        voice_msg = Message(
            sender_id=self.alice.id,
            receiver_id=self.bob.id,
            content=None,
            image_url="http://testserver/uploads/voice_recording_123.webm",
        )
        payload = push_service.format_push_payload(self.alice, voice_msg)
        self.assertEqual(payload["body"], "🎙️ Voice message")

    # --------------------------------------------------------------------------
    # 10. Invalid / Expired Push Subscriptions Are Cleaned Up
    # --------------------------------------------------------------------------
    def test_invalid_expired_push_subscriptions_cleaned_up(self):
        """When push service returns HTTP 404 or 410, subscription is deleted from DB."""
        sub = push_service.save_subscription(
            self.db,
            self.bob,
            endpoint="https://fcm.googleapis.com/fcm/send/expired-sub",
            p256dh="key1",
            auth="key2",
        )
        sub_id = sub.id

        # Simulate WebPushException with HTTP 410 Gone
        mock_resp = MagicMock()
        mock_resp.status_code = 410
        mock_exc = Exception("Subscription expired")
        mock_exc.response = mock_resp

        with patch("backend.services.push_service.webpush", side_effect=mock_exc):
            with patch.object(settings, "WEB_PUSH_ENABLED", True):
                with patch.object(settings, "VAPID_PUBLIC_KEY", "pubkey"):
                    with patch.object(settings, "VAPID_PRIVATE_KEY", "privkey"):
                        with patch.object(settings, "VAPID_CLAIMS_SUB", "mailto:test@example.com"):
                            success = push_service.send_webpush(
                                subscription_info={"endpoint": sub.endpoint},
                                payload_str="{}",
                                subscription_id=sub_id,
                            )
                            self.assertFalse(success)

        # Verify subscription was cleaned up
        self.db.expire_all()
        cleaned = self.db.query(PushSubscription).filter(PushSubscription.id == sub_id).first()
        self.assertIsNone(cleaned)

    # --------------------------------------------------------------------------
    # 11. Push Delivery Failure Does Not Break Normal Message Delivery
    # --------------------------------------------------------------------------
    def test_push_delivery_failure_does_not_break_message_delivery(self):
        """A failure in push delivery does not raise or impede message creation/delivery."""
        with patch("backend.services.push_service.send_webpush", side_effect=RuntimeError("Push server down")):
            # Message creation succeeds cleanly
            msg = chat_service.create_message(
                self.db,
                sender=self.alice,
                receiver=self.bob,
                text="Hello without push breaking",
            )
            self.assertIsNotNone(msg.id)

            # REST send_message endpoint succeeds cleanly
            res = self.client.post(
                f"/messages/{self.bob.username}",
                json={"text": "Test message"},
                headers=self.alice_headers,
            )
            self.assertEqual(res.status_code, 200)

    # --------------------------------------------------------------------------
    # 12. Notification Click Data Contains No JWT / Tokens
    # --------------------------------------------------------------------------
    def test_notification_click_data_contains_no_jwt_or_tokens(self):
        """Notification payload contains only safe navigation state; no JWTs or secrets."""
        msg = Message(
            id=42,
            sender_id=self.alice.id,
            receiver_id=self.bob.id,
            content="Hello there private message",
        )
        payload = push_service.format_push_payload(self.alice, msg)
        data = payload.get("data", {})

        self.assertEqual(data.get("conversation"), self.alice.username)
        self.assertEqual(data.get("url"), "/")
        self.assertEqual(data.get("message_id"), 42)

        # Verify no token or secret keys anywhere in serialized payload
        serialized = json.dumps(payload)
        self.assertNotIn("token", serialized.lower())
        self.assertNotIn("jwt", serialized.lower())
        self.assertNotIn("password", serialized.lower())
        self.assertNotIn("secret_key", serialized.lower())
        self.assertNotIn("private_key", serialized.lower())

    # --------------------------------------------------------------------------
    # 13. Service Worker Endpoint & Headers
    # --------------------------------------------------------------------------
    def test_service_worker_endpoint_and_headers(self):
        """Root /sw.js is served with application/javascript, no-cache, and Service-Worker-Allowed."""
        res = self.client.get("/sw.js")
        self.assertEqual(res.status_code, 200)
        self.assertIn("application/javascript", res.headers.get("content-type", ""))
        self.assertEqual(res.headers.get("service-worker-allowed"), "/")
        self.assertIn("no-cache", res.headers.get("cache-control", "").lower())

        content = res.text
        self.assertIn("addEventListener('push'", content)
        self.assertIn("addEventListener('notificationclick'", content)
        # Verify no offline asset caching bloat
        self.assertNotIn("caches.open", content)

    # --------------------------------------------------------------------------
    # 14. VAPID Configuration Secrecy and Validation
    # --------------------------------------------------------------------------
    def test_vapid_config_secrecy_and_validation(self):
        """VAPID private key is never exposed via API or Settings __repr__."""
        with patch.object(settings, "VAPID_PUBLIC_KEY", "test_pub_key"):
            with patch.object(settings, "VAPID_PRIVATE_KEY", "super_secret_private_key"):
                with patch.object(settings, "VAPID_CLAIMS_SUB", "mailto:test@example.com"):
                    with patch.object(settings, "WEB_PUSH_ENABLED", True):
                        res = self.client.get("/push/vapid-public-key", headers=self.alice_headers)
                        self.assertEqual(res.status_code, 200)
                        data = res.json()
                        self.assertEqual(data["public_key"], "test_pub_key")
                        self.assertTrue(data["enabled"])
                        self.assertNotIn("super_secret_private_key", res.text)
                        self.assertNotIn("private", res.text.lower())

                        # Settings representation masks private key
                        rep = repr(settings)
                        self.assertNotIn("super_secret_private_key", rep)
                        self.assertIn("VAPID_PRIVATE_KEY='***'", rep)

        # In production mode, missing VAPID keys when enabled raises RuntimeError
        with patch.dict("os.environ", {"VAPID_PUBLIC_KEY": "", "VAPID_PRIVATE_KEY": "", "WEB_PUSH_ENABLED": "true"}, clear=False):
            with self.assertRaises(RuntimeError):
                Settings(
                    ENVIRONMENT="production",
                    SECRET_KEY="a" * 32,
                    WEB_PUSH_ENABLED=True,
                    VAPID_PUBLIC_KEY="",
                    VAPID_PRIVATE_KEY="",
                )

    # --------------------------------------------------------------------------
    # 15. Permission Banner Appears When Notification.permission Is "default"
    #     Even When VAPID Is Currently Unconfigured (Regression Fix)
    # --------------------------------------------------------------------------
    def test_permission_banner_appears_when_vapid_unconfigured(self):
        """In-app permission banner is not gated behind server VAPID configuration.

        When Notification.permission === 'default', the banner is displayed even
        if the server reports Web Push is unconfigured (e.g. localhost development).
        """
        # 1. Verify endpoint response when unconfigured in development
        with patch.object(settings, "WEB_PUSH_ENABLED", False):
            with patch.object(settings, "VAPID_PUBLIC_KEY", None):
                res = self.client.get("/push/vapid-public-key", headers=self.alice_headers)
                self.assertEqual(res.status_code, 200)
                data = res.json()
                self.assertFalse(data["enabled"])
                self.assertIsNone(data["public_key"])

        # 2. Verify static push.js script implementation
        res = self.client.get("/static/js/push.js")
        self.assertEqual(res.status_code, 200)
        js_content = res.text

        # Verify showPushPermissionPrompt is called directly for 'default' permission
        self.assertIn("showPushPermissionPrompt();", js_content)
        # Verify showPushPermissionPrompt does not require a vapidPublicKey parameter
        self.assertIn("function showPushPermissionPrompt()", js_content)
        # Verify banner element ID and class exist
        self.assertIn("push-permission-prompt", js_content)
        self.assertIn("push-permission-banner", js_content)
        # Verify enable button triggers requestPermission and then enableWebPushSubscription
        self.assertIn("enableWebPushSubscription()", js_content)
        # Verify unconfigured server case fails gracefully with user toast and no fabricated keys
        self.assertIn("Web Push is not configured on the server", js_content)

    # --------------------------------------------------------------------------
    # 16. Configured-VAPID Subscription Path Remains Correct
    # --------------------------------------------------------------------------
    def test_configured_vapid_subscription_path_and_sync(self):
        """When VAPID is configured, public key is provided and subscription completes."""
        with patch.object(settings, "VAPID_PUBLIC_KEY", "valid_pub_key"):
            with patch.object(settings, "VAPID_PRIVATE_KEY", "valid_priv_key"):
                with patch.object(settings, "VAPID_CLAIMS_SUB", "mailto:admin@example.com"):
                    with patch.object(settings, "WEB_PUSH_ENABLED", True):
                        # 1. Fetch public key endpoint
                        res = self.client.get("/push/vapid-public-key", headers=self.alice_headers)
                        self.assertEqual(res.status_code, 200)
                        data = res.json()
                        self.assertTrue(data["enabled"])
                        self.assertEqual(data["public_key"], "valid_pub_key")

                        # 2. Subscribe endpoint saves valid subscription
                        sub_payload = {
                            "endpoint": "https://fcm.googleapis.com/fcm/send/alice-fcm-token",
                            "keys": {
                                "p256dh": "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QT9t0A3qc8TegWmszqqFDDsFVuLSmWOnWGFRoxO61ymqff_g",
                                "auth": "tBHItJI5svbpez7KI4CCXg",
                            },
                        }
                        sub_res = self.client.post("/push/subscribe", json=sub_payload, headers=self.alice_headers)
                        self.assertEqual(sub_res.status_code, 200)

                        # 3. Status endpoint reports active subscription
                        status_res = self.client.get("/push/status", headers=self.alice_headers)
                        self.assertEqual(status_res.status_code, 200)
                        self.assertTrue(status_res.json()["enabled"])
                        self.assertTrue(status_res.json()["subscribed"])

                        # 4. Unsubscribe endpoint cleanly removes subscription
                        unsub_res = self.client.post("/push/unsubscribe", headers=self.alice_headers)
                        self.assertEqual(unsub_res.status_code, 200)
                        self.assertTrue(unsub_res.json()["removed"])

                        # 5. Status endpoint reports no subscription
                        status_after = self.client.get("/push/status", headers=self.alice_headers)
                        self.assertFalse(status_after.json()["subscribed"])

    # --------------------------------------------------------------------------
    # 17. Multi-Account Endpoint Disassociation on Same Browser Profile
    # --------------------------------------------------------------------------
    def test_multi_account_endpoint_disassociation_on_same_browser(self):
        """When User Y registers an endpoint previously used by User X, User X's
        association is removed while other users with different endpoints remain untouched.
        """
        shared_endpoint = "https://fcm.googleapis.com/fcm/send/shared-device-token-123"
        other_endpoint = "https://fcm.googleapis.com/fcm/send/charlie-separate-token-456"

        # 1. User X (Alice) registers endpoint E
        alice_sub = push_service.save_subscription(
            self.db,
            user=self.alice,
            endpoint=f"  {shared_endpoint}  ",
            p256dh="alice_p256dh_key",
            auth="alice_auth_key",
        )
        self.assertEqual(alice_sub.endpoint, shared_endpoint)

        # Separate User Z (Charlie) registers a different endpoint E2
        charlie_sub = push_service.save_subscription(
            self.db,
            user=self.charlie,
            endpoint=other_endpoint,
            p256dh="charlie_p256dh_key",
            auth="charlie_auth_key",
        )
        self.assertEqual(charlie_sub.endpoint, other_endpoint)

        # Verify initial database state: Alice and Charlie have active subscriptions
        self.assertIsNotNone(push_service.get_subscription(self.db, self.alice.id))
        self.assertIsNotNone(push_service.get_subscription(self.db, self.charlie.id))
        self.assertIsNone(push_service.get_subscription(self.db, self.bob.id))

        # 2. User Y (Bob) subsequently registers the same endpoint E via API
        bob_payload = {
            "endpoint": f" {shared_endpoint} ",
            "keys": {
                "p256dh": "bob_p256dh_key",
                "auth": "bob_auth_key",
            },
        }
        res_bob = self.client.post("/push/subscribe", json=bob_payload, headers=self.bob_headers)
        self.assertEqual(res_bob.status_code, 200)

        # 3. User X's (Alice) old association is removed
        self.db.expire_all()
        alice_sub_after = push_service.get_subscription(self.db, self.alice.id)
        self.assertIsNone(alice_sub_after, "Alice's old subscription on the shared endpoint must be disassociated")

        # 4. User Y's (Bob) association remains and is properly saved
        bob_sub_after = push_service.get_subscription(self.db, self.bob.id)
        self.assertIsNotNone(bob_sub_after)
        self.assertEqual(bob_sub_after.endpoint, shared_endpoint)
        self.assertEqual(bob_sub_after.p256dh, "bob_p256dh_key")
        self.assertEqual(bob_sub_after.auth, "bob_auth_key")

        # 5. Different endpoints belonging to other users (Charlie) remain untouched
        charlie_sub_after = push_service.get_subscription(self.db, self.charlie.id)
        self.assertIsNotNone(charlie_sub_after, "Charlie's separate endpoint must remain untouched")
        self.assertEqual(charlie_sub_after.endpoint, other_endpoint)
        self.assertEqual(charlie_sub_after.user_id, self.charlie.id)


