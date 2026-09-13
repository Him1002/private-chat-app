"""
Comprehensive tests for ChatSpic V2 Voice & Video Calling (Phase 1: Backend Signaling Foundation).

Validates:
- Connected WebSocket registry and multi-tab delivery
- Room-independent signaling delivery
- Friend-only call authorization and validation
- Active call lifecycle (invite, accept, reject, cancel, end)
- WebRTC offer, answer, and ICE candidate relay
- Error handling for offline users, busy users, invalid calls, and unauthorized participants
- Rejection reason constraints (declined, busy, unavailable)
- Final-socket disconnect cleanup semantics (multi-tab preservation)
- In-memory active call state cleanup on terminal states
- Authenticated /call/config endpoint and strict secret protection
- Unanswered call ring timeout mechanism
"""
import asyncio
import json
import unittest
from datetime import timedelta

from main import app
from backend.core.config import settings
from backend.core.security import create_access_token
from backend.db.database import get_db
from backend.db.models import User
from backend.realtime import websocket as ws_module
from backend.services import call_service
from tests.base import BaseTestCase
from tests.test_auth_authorization import ASGIClient
from tests.test_websocket_reliability import WebSocketTestClient


class CallSignalingTestCase(BaseTestCase):
    """Test suite for backend call signaling and lifecycle state management."""

    def setUp(self):
        super().setUp()
        self.active_clients = []

        def _override_get_db():
            try:
                yield self.db
            finally:
                pass

        app.dependency_overrides[get_db] = _override_get_db
        self.addCleanup(self._cleanup_test_state)
        self._reset_globals()

    def _cleanup_test_state(self):
        app.dependency_overrides.pop(get_db, None)
        self._reset_globals()

    def _reset_globals(self):
        ws_module.online_users.clear()
        ws_module.rooms.clear()
        ws_module.connected_sockets.clear()
        call_service.reset_call_state()

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
            super().tearDown()

    async def create_ws_client(self, user: User, auto_connect: bool = True) -> WebSocketTestClient:
        token = create_access_token({"sub": user.username}, timedelta(minutes=30))
        client = WebSocketTestClient(app)
        self.active_clients.append(client)
        if auto_connect:
            connected = await client.connect(token=token)
            self.assertTrue(connected, f"Failed to connect WebSocket for user {user.username}")
        return client

    # --------------------------------------------------------------------------
    # 1. Successful Call Invite Between Friends
    # --------------------------------------------------------------------------
    def test_call_invite_between_friends_success(self):
        async def run_test():
            alice_ws = await self.create_ws_client(self.alice)
            bob_ws = await self.create_ws_client(self.bob)

            call_id = "call-001"
            await alice_ws.send_json({
                "type": "call.invite",
                "call_id": call_id,
                "to_user_id": self.bob.id,
                "call_type": "voice",
            })

            # Bob should receive the incoming call invitation
            received = await bob_ws.receive_json(timeout=2.0)
            self.assertEqual(received.get("type"), "call.invite")
            self.assertEqual(received.get("call_id"), call_id)
            self.assertEqual(received.get("from_user_id"), self.alice.id)
            self.assertEqual(received.get("from_username"), "alice")
            self.assertEqual(received.get("call_type"), "voice")

            # In-memory call state must exist and be in CALLING state
            call = call_service.get_call(call_id)
            self.assertIsNotNone(call)
            self.assertEqual(call.state, call_service.CallState.CALLING)
            self.assertTrue(call_service.is_user_in_call(self.alice.id))
            self.assertTrue(call_service.is_user_in_call(self.bob.id))

        asyncio.run(run_test())

    # --------------------------------------------------------------------------
    # 2. Call Invite Reaches Target Across Different Chat Rooms
    # --------------------------------------------------------------------------
    def test_call_invite_delivers_across_different_rooms(self):
        async def run_test():
            alice_ws = await self.create_ws_client(self.alice)
            bob_ws = await self.create_ws_client(self.bob)

            # Alice joins room with charlie, Bob does not join any room
            await alice_ws.send_json({"type": "join", "room": "charlie"})
            # Drain join responses for alice
            try:
                while True:
                    await asyncio.wait_for(alice_ws.receive_json(), timeout=0.1)
            except (asyncio.TimeoutError, ConnectionResetError):
                pass

            # Alice calls Bob
            call_id = "call-room-diff"
            await alice_ws.send_json({
                "type": "call.invite",
                "call_id": call_id,
                "to_user_id": self.bob.id,
                "call_type": "video",
            })

            # Bob receives invite despite room differences
            received = await bob_ws.receive_json(timeout=2.0)
            self.assertEqual(received.get("type"), "call.invite")
            self.assertEqual(received.get("call_id"), call_id)
            self.assertEqual(received.get("call_type"), "video")

        asyncio.run(run_test())

    # --------------------------------------------------------------------------
    # 3. Call Invite Broadcasts to Multiple Tabs for Target
    # --------------------------------------------------------------------------
    def test_call_invite_delivers_to_multiple_tabs(self):
        async def run_test():
            alice_ws = await self.create_ws_client(self.alice)
            bob_tab1 = await self.create_ws_client(self.bob)
            bob_tab2 = await self.create_ws_client(self.bob)

            self.assertEqual(len(ws_module.connected_sockets[self.bob.id]), 2)

            call_id = "call-multi-tab"
            await alice_ws.send_json({
                "type": "call.invite",
                "call_id": call_id,
                "to_user_id": self.bob.id,
                "call_type": "voice",
            })

            # Both of Bob's tabs must receive the invite
            recv1 = await bob_tab1.receive_json(timeout=2.0)
            recv2 = await bob_tab2.receive_json(timeout=2.0)

            self.assertEqual(recv1.get("type"), "call.invite")
            self.assertEqual(recv1.get("call_id"), call_id)
            self.assertEqual(recv2.get("type"), "call.invite")
            self.assertEqual(recv2.get("call_id"), call_id)

        asyncio.run(run_test())

    # --------------------------------------------------------------------------
    # 4. Non-Friend Cannot Initiate Call
    # --------------------------------------------------------------------------
    def test_call_invite_rejected_if_not_friends(self):
        async def run_test():
            # Bob and Charlie are not friends
            bob_ws = await self.create_ws_client(self.bob)
            charlie_ws = await self.create_ws_client(self.charlie)

            call_id = "call-not-friends"
            await bob_ws.send_json({
                "type": "call.invite",
                "call_id": call_id,
                "to_user_id": self.charlie.id,
                "call_type": "voice",
            })

            resp = await bob_ws.receive_json(timeout=2.0)
            self.assertEqual(resp.get("type"), "error")
            self.assertIn("not friends", resp.get("message", "").lower())

            # Charlie receives nothing
            with self.assertRaises(asyncio.TimeoutError):
                await charlie_ws.receive_json(timeout=0.3)

            # No call created in memory
            self.assertIsNone(call_service.get_call(call_id))

        asyncio.run(run_test())

    # --------------------------------------------------------------------------
    # 5. Offline Target Cannot Be Called
    # --------------------------------------------------------------------------
    def test_call_invite_rejected_if_target_offline(self):
        async def run_test():
            # Alice is connected, Bob is offline
            alice_ws = await self.create_ws_client(self.alice)

            call_id = "call-offline"
            await alice_ws.send_json({
                "type": "call.invite",
                "call_id": call_id,
                "to_user_id": self.bob.id,
                "call_type": "voice",
            })

            resp = await alice_ws.receive_json(timeout=2.0)
            self.assertEqual(resp.get("type"), "call.reject")
            self.assertEqual(resp.get("call_id"), call_id)
            self.assertEqual(resp.get("reason"), "unavailable")

            self.assertIsNone(call_service.get_call(call_id))
            self.assertFalse(call_service.is_user_in_call(self.alice.id))

        asyncio.run(run_test())

    # --------------------------------------------------------------------------
    # 6. Caller Already in Call Cannot Initiate Another
    # --------------------------------------------------------------------------
    def test_caller_already_in_call_cannot_initiate(self):
        async def run_test():
            alice_ws = await self.create_ws_client(self.alice)
            bob_ws = await self.create_ws_client(self.bob)
            charlie_ws = await self.create_ws_client(self.charlie)

            # Alice calls Bob
            await alice_ws.send_json({
                "type": "call.invite",
                "call_id": "call-first",
                "to_user_id": self.bob.id,
                "call_type": "voice",
            })
            await bob_ws.receive_json(timeout=2.0)

            # Alice tries to call Charlie while already calling Bob
            await alice_ws.send_json({
                "type": "call.invite",
                "call_id": "call-second",
                "to_user_id": self.charlie.id,
                "call_type": "video",
            })

            err = await alice_ws.receive_json(timeout=2.0)
            self.assertEqual(err.get("type"), "error")
            self.assertIn("already in an active call", err.get("message", "").lower())

            # Charlie receives nothing
            with self.assertRaises(asyncio.TimeoutError):
                await charlie_ws.receive_json(timeout=0.3)

        asyncio.run(run_test())

    # --------------------------------------------------------------------------
    # 7. Callee Already in Call Returns Busy
    # --------------------------------------------------------------------------
    def test_callee_already_in_call_returns_busy(self):
        async def run_test():
            alice_ws = await self.create_ws_client(self.alice)
            bob_ws = await self.create_ws_client(self.bob)
            charlie_ws = await self.create_ws_client(self.charlie)

            # Alice calls Bob
            await alice_ws.send_json({
                "type": "call.invite",
                "call_id": "call-first",
                "to_user_id": self.bob.id,
                "call_type": "voice",
            })
            await bob_ws.receive_json(timeout=2.0)

            # Charlie calls Alice (who is currently busy calling Bob)
            await charlie_ws.send_json({
                "type": "call.invite",
                "call_id": "call-charlie-alice",
                "to_user_id": self.alice.id,
                "call_type": "voice",
            })

            resp = await charlie_ws.receive_json(timeout=2.0)
            self.assertEqual(resp.get("type"), "call.reject")
            self.assertEqual(resp.get("call_id"), "call-charlie-alice")
            self.assertEqual(resp.get("reason"), "busy")

        asyncio.run(run_test())

    # --------------------------------------------------------------------------
    # 8. Non-Participant Signaling Rejected
    # --------------------------------------------------------------------------
    def test_non_participant_signaling_rejected(self):
        async def run_test():
            alice_ws = await self.create_ws_client(self.alice)
            bob_ws = await self.create_ws_client(self.bob)
            charlie_ws = await self.create_ws_client(self.charlie)

            call_id = "call-alice-bob"
            await alice_ws.send_json({
                "type": "call.invite",
                "call_id": call_id,
                "to_user_id": self.bob.id,
                "call_type": "voice",
            })
            await bob_ws.receive_json(timeout=2.0)

            # Charlie attempts to send call.accept into Alice-Bob call
            await charlie_ws.send_json({
                "type": "call.accept",
                "call_id": call_id,
            })

            err = await charlie_ws.receive_json(timeout=2.0)
            self.assertEqual(err.get("type"), "error")
            self.assertIn("not authorized", err.get("message", "").lower())

            # Charlie attempts to inject webrtc.offer
            await charlie_ws.send_json({
                "type": "webrtc.offer",
                "call_id": call_id,
                "sdp": "injected-sdp",
            })
            err2 = await charlie_ws.receive_json(timeout=2.0)
            self.assertEqual(err2.get("type"), "error")

            # Neither Alice nor Bob received Charlie's injected payloads
            with self.assertRaises(asyncio.TimeoutError):
                await alice_ws.receive_json(timeout=0.2)
            with self.assertRaises(asyncio.TimeoutError):
                await bob_ws.receive_json(timeout=0.2)

        asyncio.run(run_test())

    # --------------------------------------------------------------------------
    # 9. Call Accept Relayed to Caller and State Updated
    # --------------------------------------------------------------------------
    def test_call_accept_relayed_to_caller(self):
        async def run_test():
            alice_ws = await self.create_ws_client(self.alice)
            bob_ws = await self.create_ws_client(self.bob)

            call_id = "call-accept-test"
            await alice_ws.send_json({
                "type": "call.invite",
                "call_id": call_id,
                "to_user_id": self.bob.id,
                "call_type": "voice",
            })
            await bob_ws.receive_json(timeout=2.0)

            # Bob accepts
            await bob_ws.send_json({
                "type": "call.accept",
                "call_id": call_id,
            })

            # Alice receives accept
            accepted = await alice_ws.receive_json(timeout=2.0)
            self.assertEqual(accepted.get("type"), "call.accept")
            self.assertEqual(accepted.get("call_id"), call_id)

            call = call_service.get_call(call_id)
            self.assertIsNotNone(call)
            self.assertEqual(call.state, call_service.CallState.CONNECTING)

        asyncio.run(run_test())

    # --------------------------------------------------------------------------
    # 10. Call Reject Relayed to Caller and Cleans Up
    # --------------------------------------------------------------------------
    def test_call_reject_relayed_to_caller(self):
        async def run_test():
            alice_ws = await self.create_ws_client(self.alice)
            bob_ws = await self.create_ws_client(self.bob)

            call_id = "call-reject-test"
            await alice_ws.send_json({
                "type": "call.invite",
                "call_id": call_id,
                "to_user_id": self.bob.id,
                "call_type": "video",
            })
            await bob_ws.receive_json(timeout=2.0)

            # Bob declines
            await bob_ws.send_json({
                "type": "call.reject",
                "call_id": call_id,
                "reason": "declined",
            })

            rejected = await alice_ws.receive_json(timeout=2.0)
            self.assertEqual(rejected.get("type"), "call.reject")
            self.assertEqual(rejected.get("call_id"), call_id)
            self.assertEqual(rejected.get("reason"), "declined")

            # Terminal state cleans in-memory active call
            self.assertIsNone(call_service.get_call(call_id))
            self.assertFalse(call_service.is_user_in_call(self.alice.id))
            self.assertFalse(call_service.is_user_in_call(self.bob.id))

        asyncio.run(run_test())

    # --------------------------------------------------------------------------
    # 11. Constraint 2: Rejection Reasons Limited to declined, busy, unavailable
    # --------------------------------------------------------------------------
    def test_call_reject_reasons_strictly_limited(self):
        async def run_test():
            alice_ws = await self.create_ws_client(self.alice)
            bob_ws = await self.create_ws_client(self.bob)

            call_id = "call-reasons-test"
            await alice_ws.send_json({
                "type": "call.invite",
                "call_id": call_id,
                "to_user_id": self.bob.id,
                "call_type": "voice",
            })
            await bob_ws.receive_json(timeout=2.0)

            # Send arbitrary reason; server must normalize to valid reason ('declined')
            await bob_ws.send_json({
                "type": "call.reject",
                "call_id": call_id,
                "reason": "arbitrary_custom_reason",
            })

            resp = await alice_ws.receive_json(timeout=2.0)
            self.assertIn(resp.get("reason"), {"declined", "busy", "unavailable"})
            self.assertEqual(resp.get("reason"), "declined")

        asyncio.run(run_test())

    # --------------------------------------------------------------------------
    # 12. Call Cancel Relayed to Callee
    # --------------------------------------------------------------------------
    def test_call_cancel_relayed_to_callee(self):
        async def run_test():
            alice_ws = await self.create_ws_client(self.alice)
            bob_ws = await self.create_ws_client(self.bob)

            call_id = "call-cancel-test"
            await alice_ws.send_json({
                "type": "call.invite",
                "call_id": call_id,
                "to_user_id": self.bob.id,
                "call_type": "voice",
            })
            await bob_ws.receive_json(timeout=2.0)

            # Caller cancels before callee answers
            await alice_ws.send_json({
                "type": "call.cancel",
                "call_id": call_id,
            })

            cancelled = await bob_ws.receive_json(timeout=2.0)
            self.assertEqual(cancelled.get("type"), "call.cancel")
            self.assertEqual(cancelled.get("call_id"), call_id)

            self.assertIsNone(call_service.get_call(call_id))
            self.assertFalse(call_service.is_user_in_call(self.alice.id))
            self.assertFalse(call_service.is_user_in_call(self.bob.id))

        asyncio.run(run_test())

    # --------------------------------------------------------------------------
    # 13. Call End Relayed to Other Participant
    # --------------------------------------------------------------------------
    def test_call_end_relayed_to_other_participant(self):
        async def run_test():
            alice_ws = await self.create_ws_client(self.alice)
            bob_ws = await self.create_ws_client(self.bob)

            call_id = "call-end-test"
            await alice_ws.send_json({
                "type": "call.invite",
                "call_id": call_id,
                "to_user_id": self.bob.id,
                "call_type": "voice",
            })
            await bob_ws.receive_json(timeout=2.0)

            await bob_ws.send_json({
                "type": "call.accept",
                "call_id": call_id,
            })
            await alice_ws.receive_json(timeout=2.0)

            # Alice ends the call
            await alice_ws.send_json({
                "type": "call.end",
                "call_id": call_id,
            })

            ended = await bob_ws.receive_json(timeout=2.0)
            self.assertEqual(ended.get("type"), "call.end")
            self.assertEqual(ended.get("call_id"), call_id)

            self.assertIsNone(call_service.get_call(call_id))
            self.assertFalse(call_service.is_user_in_call(self.alice.id))
            self.assertFalse(call_service.is_user_in_call(self.bob.id))

        asyncio.run(run_test())

    # --------------------------------------------------------------------------
    # 14. WebRTC Offer, Answer, ICE Candidate Relay
    # --------------------------------------------------------------------------
    def test_webrtc_signaling_relayed_between_participants(self):
        async def run_test():
            alice_ws = await self.create_ws_client(self.alice)
            bob_ws = await self.create_ws_client(self.bob)

            call_id = "call-webrtc-test"
            await alice_ws.send_json({
                "type": "call.invite",
                "call_id": call_id,
                "to_user_id": self.bob.id,
                "call_type": "video",
            })
            await bob_ws.receive_json(timeout=2.0)

            await bob_ws.send_json({
                "type": "call.accept",
                "call_id": call_id,
            })
            await alice_ws.receive_json(timeout=2.0)

            # Alice sends WebRTC offer
            await alice_ws.send_json({
                "type": "webrtc.offer",
                "call_id": call_id,
                "sdp": "v=0\r\no=alice 123456\r\ns=test",
            })
            offer = await bob_ws.receive_json(timeout=2.0)
            self.assertEqual(offer.get("type"), "webrtc.offer")
            self.assertEqual(offer.get("call_id"), call_id)
            self.assertEqual(offer.get("sdp"), "v=0\r\no=alice 123456\r\ns=test")

            # Bob sends WebRTC answer
            await bob_ws.send_json({
                "type": "webrtc.answer",
                "call_id": call_id,
                "sdp": "v=0\r\no=bob 654321\r\ns=test",
            })
            answer = await alice_ws.receive_json(timeout=2.0)
            self.assertEqual(answer.get("type"), "webrtc.answer")
            self.assertEqual(answer.get("call_id"), call_id)
            self.assertEqual(answer.get("sdp"), "v=0\r\no=bob 654321\r\ns=test")

            # Alice sends ICE candidate
            candidate_payload = {"candidate": "candidate:1 1 UDP 2130706431 ...", "sdpMid": "0", "sdpMLineIndex": 0}
            await alice_ws.send_json({
                "type": "webrtc.ice_candidate",
                "call_id": call_id,
                "candidate": candidate_payload,
            })
            cand = await bob_ws.receive_json(timeout=2.0)
            self.assertEqual(cand.get("type"), "webrtc.ice_candidate")
            self.assertEqual(cand.get("call_id"), call_id)
            self.assertEqual(cand.get("candidate"), candidate_payload)

        asyncio.run(run_test())

    # --------------------------------------------------------------------------
    # 15. Unknown/Stale Call ID Handled Safely
    # --------------------------------------------------------------------------
    def test_stale_or_unknown_call_id_rejected_safely(self):
        async def run_test():
            alice_ws = await self.create_ws_client(self.alice)

            for msg_type in ["call.accept", "call.reject", "call.cancel", "call.end", "webrtc.offer"]:
                await alice_ws.send_json({
                    "type": msg_type,
                    "call_id": "nonexistent-call-999",
                })
                resp = await alice_ws.receive_json(timeout=2.0)
                self.assertEqual(resp.get("type"), "error")
                self.assertIn("not found", resp.get("message", "").lower())

        asyncio.run(run_test())

    # --------------------------------------------------------------------------
    # 16. Disconnect Cleans Connected Sockets
    # --------------------------------------------------------------------------
    def test_disconnect_cleans_connected_sockets(self):
        async def run_test():
            bob_ws = await self.create_ws_client(self.bob)
            self.assertIn(self.bob.id, ws_module.connected_sockets)
            self.assertEqual(len(ws_module.connected_sockets[self.bob.id]), 1)

            await bob_ws.disconnect()
            await asyncio.sleep(0.05)

            self.assertNotIn(self.bob.id, ws_module.connected_sockets)

        asyncio.run(run_test())

    # --------------------------------------------------------------------------
    # 17. Constraint 3: Disconnect Multi-Tab Does NOT End Call
    # --------------------------------------------------------------------------
    def test_disconnect_multi_tab_does_not_end_call(self):
        async def run_test():
            alice_tab1 = await self.create_ws_client(self.alice)
            alice_tab2 = await self.create_ws_client(self.alice)
            bob_ws = await self.create_ws_client(self.bob)

            call_id = "call-multi-tab-disconnect"
            await alice_tab1.send_json({
                "type": "call.invite",
                "call_id": call_id,
                "to_user_id": self.bob.id,
                "call_type": "voice",
            })
            await bob_ws.receive_json(timeout=2.0)

            # Alice closes tab 2, but tab 1 is STILL connected
            await alice_tab2.disconnect()
            await asyncio.sleep(0.05)

            # Active call must NOT be terminated
            self.assertTrue(call_service.is_user_in_call(self.alice.id))
            self.assertTrue(call_service.is_user_in_call(self.bob.id))
            self.assertIsNotNone(call_service.get_call(call_id))

            # Bob must NOT have received a call.end
            with self.assertRaises(asyncio.TimeoutError):
                await bob_ws.receive_json(timeout=0.3)

            # Now Alice closes her FINAL tab (tab 1)
            await alice_tab1.disconnect()
            await asyncio.sleep(0.05)

            # Call is now terminated and Bob receives call.end
            end_msg = await bob_ws.receive_json(timeout=2.0)
            self.assertEqual(end_msg.get("type"), "call.end")
            self.assertEqual(end_msg.get("call_id"), call_id)

            self.assertIsNone(call_service.get_call(call_id))
            self.assertFalse(call_service.is_user_in_call(self.alice.id))

        asyncio.run(run_test())

    # --------------------------------------------------------------------------
    # 18. Unanswered Call Ring Timeout Mechanism
    # --------------------------------------------------------------------------
    def test_unanswered_call_timeout_cleans_up(self):
        async def run_test():
            alice_ws = await self.create_ws_client(self.alice)
            bob_ws = await self.create_ws_client(self.bob)

            call_id = "call-timeout-test"
            await alice_ws.send_json({
                "type": "call.invite",
                "call_id": call_id,
                "to_user_id": self.bob.id,
                "call_type": "voice",
            })
            await bob_ws.receive_json(timeout=2.0)

            # Re-schedule with a tiny timeout (0.1s) to test timeout execution quickly
            async def _on_timeout(expired_call: call_service.ActiveCall):
                await ws_module.deliver_to_user(expired_call.caller_id, {
                    "type": "call.reject",
                    "call_id": expired_call.call_id,
                    "reason": "unavailable",
                })
                await ws_module.deliver_to_user(expired_call.callee_id, {
                    "type": "call.cancel",
                    "call_id": expired_call.call_id,
                })

            call_service.schedule_call_timeout(call_id, 0.1, _on_timeout)

            # Alice should receive rejection with unavailable
            alice_resp = await alice_ws.receive_json(timeout=2.0)
            self.assertEqual(alice_resp.get("type"), "call.reject")
            self.assertEqual(alice_resp.get("reason"), "unavailable")

            # Bob should receive cancel
            bob_resp = await bob_ws.receive_json(timeout=2.0)
            self.assertEqual(bob_resp.get("type"), "call.cancel")

            # Call state cleaned up
            self.assertIsNone(call_service.get_call(call_id))
            self.assertFalse(call_service.is_user_in_call(self.alice.id))
            self.assertFalse(call_service.is_user_in_call(self.bob.id))

        asyncio.run(run_test())

    # --------------------------------------------------------------------------
    # 19. GET /call/config Endpoint Authentication & ICE Servers
    # --------------------------------------------------------------------------
    def test_call_config_endpoint_authentication(self):
        client = ASGIClient(app)

        # Unauthenticated request must be rejected with 401/403
        resp_unauth = client.get("/call/config")
        self.assertIn(resp_unauth.status_code, (401, 403))

        # Authenticated request
        token = create_access_token({"sub": self.alice.username}, timedelta(minutes=30))
        headers = {"Authorization": f"Bearer {token}"}
        resp_auth = client.get("/call/config", headers=headers)
        self.assertEqual(resp_auth.status_code, 200)

        data = resp_auth.json()
        self.assertIn("ice_servers", data)
        self.assertIsInstance(data["ice_servers"], list)
        self.assertGreaterEqual(len(data["ice_servers"]), 1)
        self.assertIn("urls", data["ice_servers"][0])

    # --------------------------------------------------------------------------
    # 20. Constraint 1: TURN Credentials Never Exposed Through API or Settings Repr
    # --------------------------------------------------------------------------
    def test_turn_credentials_never_exposed(self):
        client = ASGIClient(app)

        # Ensure TURN credentials are set in settings for this test
        old_cred = settings.TURN_CREDENTIAL
        old_user = settings.TURN_USERNAME
        old_turn = settings.TURN_SERVER_URL
        try:
            settings.TURN_SERVER_URL = "turn:turn.example.com:3478"
            settings.TURN_USERNAME = "webrtc-user"
            settings.TURN_CREDENTIAL = "super-secret-turn-password-999"

            # 1. Repr and str of settings MUST mask credential
            self.assertNotIn("super-secret-turn-password-999", repr(settings))
            self.assertNotIn("super-secret-turn-password-999", str(settings))
            self.assertIn("TURN_CREDENTIAL='***'", repr(settings))

            # 2. GET /call/config MUST NEVER include credential
            token = create_access_token({"sub": self.alice.username}, timedelta(minutes=30))
            headers = {"Authorization": f"Bearer {token}"}
            resp = client.get("/call/config", headers=headers)
            self.assertEqual(resp.status_code, 200)

            # Verifies that TURN_CREDENTIAL, SECRET_KEY, and DATABASE_URL are not leaked
            self.assertNotIn("super-secret-turn-password-999", resp.text)
            self.assertNotIn(settings.SECRET_KEY, resp.text)
            self.assertNotIn(settings.DATABASE_URL, resp.text)

            # Check individual ice_servers entries
            data = resp.json()
            for server in data.get("ice_servers", []):
                self.assertNotIn("credential", server)

        finally:
            settings.TURN_SERVER_URL = old_turn
            settings.TURN_USERNAME = old_user
            settings.TURN_CREDENTIAL = old_cred


if __name__ == "__main__":
    unittest.main()
