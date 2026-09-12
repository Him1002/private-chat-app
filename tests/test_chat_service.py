"""Unit and service-level tests for backend.services.chat_service.

Validates service-level business logic, message lifecycle, serialization,
search, read states, unread counts, replies, reactions integration,
conversation listings, and cross-conversation isolation using BaseTestCase's
isolated SQLite database foundation.
"""
from datetime import datetime, timezone, timedelta
import unittest

from backend.db.models import Message, Friend, User
from backend.services import chat_service, reaction_service
from backend.services.chat_service import (
    NotFoundError,
    BadRequestError,
    ForbiddenError,
)
from tests.base import BaseTestCase


class TestMessageCreation(BaseTestCase):
    """Tests for message creation and persistence (Area 1)."""

    def test_create_message_success_persists_fields(self):
        """Creating a normal message persists sender, receiver, content, timestamps, and default states."""
        before = datetime.now(timezone.utc) - timedelta(seconds=1)
        msg = chat_service.create_message(
            self.db,
            sender=self.alice,
            receiver=self.bob,
            text="Hello Bob!",
            image_url=None,
        )
        after = datetime.now(timezone.utc) + timedelta(seconds=1)

        self.assertIsNotNone(msg.id)
        self.assertEqual(msg.sender_id, self.alice.id)
        self.assertEqual(msg.receiver_id, self.bob.id)
        self.assertEqual(msg.content, "Hello Bob!")
        self.assertIsNone(msg.image_url)
        self.assertFalse(msg.is_read)
        self.assertIsNone(msg.read_at)
        self.assertFalse(msg.is_deleted)
        self.assertIsNone(msg.deleted_at)
        self.assertIsNone(msg.edited_at)
        self.assertIsNone(msg.reply_to_message_id)

        # Timestamp is populated and within expected time bounds
        msg_time = msg.timestamp
        if msg_time.tzinfo is None:
            msg_time = msg_time.replace(tzinfo=timezone.utc)
        self.assertTrue(before <= msg_time <= after)

    def test_create_message_with_image(self):
        """Messages with an image URL or image-only are created successfully."""
        # Image-only message
        img_msg = chat_service.create_message(
            self.db,
            sender=self.alice,
            receiver=self.bob,
            text=None,
            image_url="https://example.com/photo.jpg",
        )
        self.assertIsNone(img_msg.content)
        self.assertEqual(img_msg.image_url, "https://example.com/photo.jpg")

        # Text and image message
        both_msg = chat_service.create_message(
            self.db,
            sender=self.alice,
            receiver=self.bob,
            text="Look at this",
            image_url="https://example.com/photo2.jpg",
        )
        self.assertEqual(both_msg.content, "Look at this")
        self.assertEqual(both_msg.image_url, "https://example.com/photo2.jpg")

    def test_create_message_empty_body_rejected(self):
        """Creating a message with neither text nor image_url raises BadRequestError."""
        with self.assertRaises(BadRequestError) as ctx:
            chat_service.create_message(
                self.db,
                sender=self.alice,
                receiver=self.bob,
                text=None,
                image_url=None,
            )
        self.assertIn("cannot be empty", str(ctx.exception))

        with self.assertRaises(BadRequestError) as ctx:
            chat_service.create_message(
                self.db,
                sender=self.alice,
                receiver=self.bob,
                text="",
                image_url=None,
            )
        self.assertIn("cannot be empty", str(ctx.exception))

    def test_send_message_public_service(self):
        """send_message wrapper looks up friend, creates message, and returns serialized dict."""
        res = chat_service.send_message(
            self.db,
            current_user=self.alice,
            friend_username="bob",
            text="Hey there",
            image_url=None,
        )
        self.assertEqual(res["sender"], "alice")
        self.assertEqual(res["receiver"], "bob")
        self.assertEqual(res["content"], "Hey there")
        self.assertEqual(res["status"], "sent")
        self.assertFalse(res["is_read"])

    def test_send_message_non_friend_or_nonexistent_fails(self):
        """send_message rejects messages to non-friends or non-existent users with NotFoundError."""
        # Non-existent user
        with self.assertRaises(NotFoundError) as ctx:
            chat_service.send_message(
                self.db,
                current_user=self.alice,
                friend_username="nonexistent_user",
                text="Hi",
                image_url=None,
            )
        self.assertEqual(str(ctx.exception), "User not found")

        # Non-friend user (Bob and Charlie are not friends)
        with self.assertRaises(NotFoundError) as ctx:
            chat_service.send_message(
                self.db,
                current_user=self.bob,
                friend_username="charlie",
                text="Hi Charlie",
                image_url=None,
            )
        self.assertEqual(str(ctx.exception), "Friend not found")


class TestMessageSerialization(BaseTestCase):
    """Tests for message serialization contracts (Area 2)."""

    def test_serialize_message_for_api_normal(self):
        """Normal message serialization matches complete API schema and UTC timestamp formatting."""
        msg = chat_service.create_message(
            self.db,
            sender=self.alice,
            receiver=self.bob,
            text="Hello serialization",
            image_url="https://example.com/avatar.png",
        )
        serialized = chat_service.serialize_message_for_api(self.db, self.alice, msg)

        expected_keys = {
            "id", "sender", "sender_display_name", "receiver", "content",
            "image_url", "timestamp", "edited_at", "status", "is_read",
            "read_at", "is_deleted", "deleted_at", "reactions", "reply_to"
        }
        self.assertEqual(set(serialized.keys()), expected_keys)
        self.assertEqual(serialized["id"], msg.id)
        self.assertEqual(serialized["sender"], "alice")
        self.assertEqual(serialized["sender_display_name"], "Alice")
        self.assertEqual(serialized["receiver"], "bob")
        self.assertEqual(serialized["content"], "Hello serialization")
        self.assertEqual(serialized["image_url"], "https://example.com/avatar.png")
        self.assertTrue(serialized["timestamp"].endswith("Z"))
        self.assertIsNone(serialized["edited_at"])
        self.assertEqual(serialized["status"], "sent")
        self.assertFalse(serialized["is_read"])
        self.assertIsNone(serialized["read_at"])
        self.assertFalse(serialized["is_deleted"])
        self.assertIsNone(serialized["deleted_at"])
        self.assertEqual(serialized["reactions"], [])
        self.assertIsNone(serialized["reply_to"])

    def test_serialize_message_for_websocket(self):
        """WebSocket serializer formats payload with event type and uses 'text' field."""
        msg = chat_service.create_message(
            self.db,
            sender=self.alice,
            receiver=self.bob,
            text="WS message",
            image_url=None,
        )
        ws_payload = chat_service.serialize_message_for_websocket(
            message=msg,
            current_user=self.alice,
            friend=self.bob,
            event_type="chat",
            reactions=[{"emoji": "👍", "count": 1}],
        )

        self.assertEqual(ws_payload["type"], "chat")
        self.assertEqual(ws_payload["id"], msg.id)
        self.assertEqual(ws_payload["sender"], "alice")
        self.assertEqual(ws_payload["sender_display_name"], "Alice")
        self.assertEqual(ws_payload["text"], "WS message")
        self.assertNotIn("content", ws_payload)
        self.assertNotIn("receiver", ws_payload)
        self.assertEqual(ws_payload["reactions"], [{"emoji": "👍", "count": 1}])
        self.assertFalse(ws_payload["is_deleted"])

    def test_serialize_message_states(self):
        """Serialization accurately presents read, edited, and soft-deleted states."""
        msg = chat_service.create_message(
            self.db,
            sender=self.alice,
            receiver=self.bob,
            text="Initial text",
            image_url="https://example.com/pic.png",
        )
        # Edit message
        chat_service.edit_message(self.db, self.alice, msg.id, "Edited text")
        # Mark read by Bob
        chat_service.mark_messages_read(self.db, self.bob, msg.id)
        self.db.refresh(msg)

        serialized = chat_service.serialize_message_for_api(self.db, self.alice, msg)
        self.assertEqual(serialized["content"], "Edited text")
        self.assertTrue(serialized["edited_at"].endswith("Z"))
        self.assertEqual(serialized["status"], "read")
        self.assertTrue(serialized["is_read"])
        self.assertTrue(serialized["read_at"].endswith("Z"))

        # Soft delete message
        chat_service.delete_message(self.db, self.alice, msg.id)
        self.db.refresh(msg)

        deleted_serialized = chat_service.serialize_message_for_api(self.db, self.alice, msg)
        self.assertEqual(deleted_serialized["content"], "This message was deleted")
        self.assertIsNone(deleted_serialized["image_url"])
        self.assertTrue(deleted_serialized["is_deleted"])
        self.assertTrue(deleted_serialized["deleted_at"].endswith("Z"))

        # WebSocket serializer also masks deleted text and image
        ws_deleted = chat_service.serialize_message_for_websocket(msg, self.alice, self.bob)
        self.assertEqual(ws_deleted["text"], "This message was deleted")
        self.assertIsNone(ws_deleted["image_url"])
        self.assertTrue(ws_deleted["is_deleted"])

    def test_serialize_reply_with_deleted_and_missing_parent(self):
        """Reply serialization represents deleted and missing parents safely."""
        parent = chat_service.create_message(
            self.db, self.alice, self.bob, text="Parent message", image_url=None
        )
        reply = chat_service.create_message(
            self.db, self.bob, self.alice, text="Reply to parent", image_url=None,
            reply_to_message_id=parent.id
        )

        # Normal reply serialization
        ser_normal = chat_service.serialize_message_for_api(self.db, self.bob, reply)
        self.assertIsNotNone(ser_normal["reply_to"])
        self.assertEqual(ser_normal["reply_to"]["id"], parent.id)
        self.assertEqual(ser_normal["reply_to"]["content"], "Parent message")
        self.assertEqual(ser_normal["reply_to"]["sender"], "alice")
        self.assertEqual(ser_normal["reply_to"]["sender_display_name"], "Alice")

        # Soft-delete parent: reply_to content becomes 'This message was deleted'
        chat_service.delete_message(self.db, self.alice, parent.id)
        self.db.refresh(reply)
        ser_deleted_parent = chat_service.serialize_message_for_api(self.db, self.bob, reply)
        self.assertEqual(ser_deleted_parent["reply_to"]["content"], "This message was deleted")

        # Missing parent (e.g. simulated dangling reference where reply_to relationship is None)
        dummy_reply = Message(
            id=999,
            sender_id=self.alice.id,
            receiver_id=self.bob.id,
            content="Orphan reply",
            reply_to_message_id=888,
        )
        dummy_reply.reply_to = None
        missing_parent_info = chat_service._build_reply_to_info(dummy_reply, self.alice, self.bob)
        self.assertEqual(missing_parent_info["id"], 888)
        self.assertIsNone(missing_parent_info["sender"])
        self.assertEqual(missing_parent_info["content"], "Original message unavailable")


class TestMessageEditing(BaseTestCase):
    """Tests for editing messages (Area 3)."""

    def test_edit_own_message_persists_and_preserves_metadata(self):
        """Sender can edit own message, updating content and edited_at while preserving other metadata."""
        msg = chat_service.create_message(
            self.db, self.alice, self.bob, text="Original text", image_url=None
        )
        original_ts = msg.timestamp
        original_id = msg.id

        updated = chat_service.edit_message(self.db, self.alice, msg.id, "Updated text")
        self.assertEqual(updated.id, original_id)
        self.assertEqual(updated.content, "Updated text")
        self.assertEqual(updated.timestamp, original_ts)
        self.assertIsNotNone(updated.edited_at)
        self.assertFalse(updated.is_read)

    def test_edit_message_validation_errors(self):
        """Edit rejects empty text, soft-deleted messages, and image-only messages without text."""
        msg = chat_service.create_message(
            self.db, self.alice, self.bob, text="Valid text", image_url=None
        )

        # Empty / whitespace text rejected
        with self.assertRaises(BadRequestError) as ctx:
            chat_service.edit_message(self.db, self.alice, msg.id, "   ")
        self.assertEqual(str(ctx.exception), "Message text cannot be empty")

        # Soft-deleted message cannot be edited
        chat_service.delete_message(self.db, self.alice, msg.id)
        with self.assertRaises(BadRequestError) as ctx:
            chat_service.edit_message(self.db, self.alice, msg.id, "New text after delete")
        self.assertEqual(str(ctx.exception), "Deleted messages cannot be edited")

        # Image-only message cannot be edited
        img_msg = chat_service.create_message(
            self.db, self.alice, self.bob, text=None, image_url="https://example.com/pic.jpg"
        )
        with self.assertRaises(BadRequestError) as ctx:
            chat_service.edit_message(self.db, self.alice, img_msg.id, "Text for image")
        self.assertEqual(str(ctx.exception), "Image-only messages cannot be edited")

    def test_edit_message_authorization_and_existence(self):
        """Recipient and unrelated users cannot edit sender's message, and nonexistent IDs are rejected."""
        msg = chat_service.create_message(
            self.db, self.alice, self.bob, text="Alice message", image_url=None
        )

        # Recipient (Bob) forbidden from editing Alice's message
        with self.assertRaises(ForbiddenError) as ctx:
            chat_service.edit_message(self.db, self.bob, msg.id, "Bob try edit")
        self.assertEqual(str(ctx.exception), "You can only edit your own messages")

        # Unrelated user (Charlie) gets NotFoundError (not a participant)
        with self.assertRaises(NotFoundError) as ctx:
            chat_service.edit_message(self.db, self.charlie, msg.id, "Charlie try edit")
        self.assertEqual(str(ctx.exception), "Message not found")

        # Nonexistent message ID
        with self.assertRaises(NotFoundError) as ctx:
            chat_service.edit_message(self.db, self.alice, 99999, "Edit nonexistent")
        self.assertEqual(str(ctx.exception), "Message not found")


class TestSoftDeleteMessage(BaseTestCase):
    """Tests for soft-deleting messages (Area 4)."""

    def test_delete_own_message_soft_deletes_and_preserves_row(self):
        """Deleting an own message soft-deletes the row, populating deleted_at without physical deletion."""
        msg = chat_service.create_message(
            self.db, self.alice, self.bob, text="Message to delete", image_url=None
        )
        msg_id = msg.id

        res = chat_service.delete_message(self.db, self.alice, msg_id)
        self.assertEqual(res["msg"], "Message deleted")
        self.assertEqual(res["message_id"], msg_id)
        self.assertTrue(res["is_deleted"])
        self.assertTrue(res["deleted_at"].endswith("Z"))

        # Row remains in database
        persisted = self.db.query(Message).filter(Message.id == msg_id).first()
        self.assertIsNotNone(persisted)
        self.assertTrue(persisted.is_deleted)
        self.assertIsNotNone(persisted.deleted_at)
        self.assertEqual(persisted.content, "Message to delete")

        # Second delete attempt raises BadRequestError
        with self.assertRaises(BadRequestError) as ctx:
            chat_service.delete_message(self.db, self.alice, msg_id)
        self.assertEqual(str(ctx.exception), "Message already deleted")

    def test_delete_message_authorization_and_existence(self):
        """Recipient and unrelated users cannot delete sender's message, and nonexistent IDs are rejected."""
        msg = chat_service.create_message(
            self.db, self.alice, self.bob, text="Alice message", image_url=None
        )

        # Recipient cannot delete sender's message
        with self.assertRaises(ForbiddenError) as ctx:
            chat_service.delete_message(self.db, self.bob, msg.id)
        self.assertEqual(str(ctx.exception), "You can only delete your own messages")

        # Unrelated user cannot delete message
        with self.assertRaises(NotFoundError) as ctx:
            chat_service.delete_message(self.db, self.charlie, msg.id)
        self.assertEqual(str(ctx.exception), "Message not found")

        # Nonexistent message
        with self.assertRaises(NotFoundError) as ctx:
            chat_service.delete_message(self.db, self.alice, 99999)
        self.assertEqual(str(ctx.exception), "Message not found")


class TestReadState(BaseTestCase):
    """Tests for message read state and read receipts (Area 5)."""

    def test_mark_single_message_read_and_idempotency(self):
        """Recipient marks a single message as read; repeated calls are safe and preserve read_at."""
        msg = chat_service.create_message(
            self.db, self.alice, self.bob, text="Read me", image_url=None
        )
        self.assertFalse(msg.is_read)

        # Recipient (Bob) marks as read
        res = chat_service.mark_messages_read(self.db, self.bob, msg.id)
        self.assertEqual(res["msg"], "Message marked as read")
        self.assertTrue(res["is_read"])
        self.assertEqual(res["status"], "read")
        initial_read_at = res["read_at"]
        self.assertIsNotNone(initial_read_at)

        # Idempotent: second call preserves read_at
        res_repeat = chat_service.mark_messages_read(self.db, self.bob, msg.id)
        self.assertTrue(res_repeat["is_read"])
        self.assertEqual(res_repeat["read_at"], initial_read_at)

    def test_mark_messages_read_authorization(self):
        """Sender and unrelated users cannot mark messages as read."""
        msg = chat_service.create_message(
            self.db, self.alice, self.bob, text="Secret", image_url=None
        )

        # Sender (Alice) cannot mark own sent message as read
        with self.assertRaises(NotFoundError) as ctx:
            chat_service.mark_messages_read(self.db, self.alice, msg.id)
        self.assertEqual(str(ctx.exception), "Message not found")

        # Unrelated user (Charlie) cannot mark as read
        with self.assertRaises(NotFoundError) as ctx:
            chat_service.mark_messages_read(self.db, self.charlie, msg.id)
        self.assertEqual(str(ctx.exception), "Message not found")

    def test_mark_conversation_messages_read_bulk(self):
        """mark_conversation_messages_read marks all unread incoming messages from friend in bulk."""
        # Alice sends 2 messages to Bob
        m1 = chat_service.create_message(self.db, self.alice, self.bob, text="M1", image_url=None)
        m2 = chat_service.create_message(self.db, self.alice, self.bob, text="M2", image_url=None)
        # Bob sends 1 message to Alice
        m3 = chat_service.create_message(self.db, self.bob, self.alice, text="M3", image_url=None)

        # Bob opens conversation with Alice: only incoming messages from Alice (m1, m2) are marked read
        read_msgs = chat_service.mark_conversation_messages_read(self.db, self.bob, self.alice)
        read_ids = {m.id for m in read_msgs}
        self.assertEqual(read_ids, {m1.id, m2.id})

        self.db.refresh(m1)
        self.db.refresh(m2)
        self.db.refresh(m3)
        self.assertTrue(m1.is_read)
        self.assertTrue(m2.is_read)
        # Bob's own message to Alice is untouched
        self.assertFalse(m3.is_read)

        # Idempotent: subsequent bulk mark returns empty list
        subsequent = chat_service.mark_conversation_messages_read(self.db, self.bob, self.alice)
        self.assertEqual(subsequent, [])


class TestUnreadCounts(BaseTestCase):
    """Tests for conversation unread counts (Area 6)."""

    def test_unread_count_rules_and_exclusion(self):
        """Unread counts count unread incoming messages and exclude sent, read, and deleted messages."""
        # Starts at 0
        self.assertEqual(chat_service.get_unread_count(self.db, self.bob.id, self.alice.id), 0)

        # Alice sends 2 messages
        m1 = chat_service.create_message(self.db, self.alice, self.bob, text="A1", image_url=None)
        m2 = chat_service.create_message(self.db, self.alice, self.bob, text="A2", image_url=None)
        self.assertEqual(chat_service.get_unread_count(self.db, self.bob.id, self.alice.id), 2)

        # Bob's own sent messages are not counted in Bob's unread count
        chat_service.create_message(self.db, self.bob, self.alice, text="B1", image_url=None)
        self.assertEqual(chat_service.get_unread_count(self.db, self.bob.id, self.alice.id), 2)
        # But Alice's unread count from Bob is 1
        self.assertEqual(chat_service.get_unread_count(self.db, self.alice.id, self.bob.id), 1)

        # Marking m1 as read reduces Bob's unread count
        chat_service.mark_messages_read(self.db, self.bob, m1.id)
        self.assertEqual(chat_service.get_unread_count(self.db, self.bob.id, self.alice.id), 1)

        # Soft-deleting m2 excludes it from unread count
        chat_service.delete_message(self.db, self.alice, m2.id)
        self.assertEqual(chat_service.get_unread_count(self.db, self.bob.id, self.alice.id), 0)


class TestConversationSearch(BaseTestCase):
    """Tests for conversation message search (Area 7)."""

    def test_search_conversation_messages_matching_and_scoping(self):
        """Search performs case-insensitive partial match strictly within conversation and on current text."""
        m1 = chat_service.create_message(
            self.db, self.alice, self.bob, text="Special Elephant in room", image_url=None
        )
        m2 = chat_service.create_message(
            self.db, self.bob, self.alice, text="Completely different topic", image_url=None
        )
        # Message in different conversation (Alice and Charlie)
        m_cross = chat_service.create_message(
            self.db, self.alice, self.charlie, text="Special Elephant cross convo", image_url=None
        )

        # Case-insensitive partial matching
        results = chat_service.search_conversation_messages(self.db, self.alice, "bob", "elephant")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], m1.id)

        # Matches Bob's message as well if matched
        results_diff = chat_service.search_conversation_messages(self.db, self.alice, "bob", "DIFFERENT")
        self.assertEqual(len(results_diff), 1)
        self.assertEqual(results_diff[0]["id"], m2.id)

        # Edited message search matches current content, not original
        chat_service.edit_message(self.db, self.alice, m1.id, "Special Giraffe in room")
        self.assertEqual(chat_service.search_conversation_messages(self.db, self.alice, "bob", "elephant"), [])
        res_edited = chat_service.search_conversation_messages(self.db, self.alice, "bob", "giraffe")
        self.assertEqual(len(res_edited), 1)
        self.assertEqual(res_edited[0]["content"], "Special Giraffe in room")

        # Soft-deleted messages are excluded
        chat_service.delete_message(self.db, self.alice, m1.id)
        self.assertEqual(chat_service.search_conversation_messages(self.db, self.alice, "bob", "giraffe"), [])

        # Charlie cannot see Alice↔Bob messages in his search
        res_charlie = chat_service.search_conversation_messages(self.db, self.charlie, "alice", "elephant")
        self.assertEqual(len(res_charlie), 1)
        self.assertEqual(res_charlie[0]["id"], m_cross.id)

    def test_search_conversation_messages_empty_or_no_match(self):
        """Search returns empty list for empty/whitespace query, no match, or raises for non-friend."""
        chat_service.create_message(self.db, self.alice, self.bob, text="Hello", image_url=None)

        self.assertEqual(chat_service.search_conversation_messages(self.db, self.alice, "bob", ""), [])
        self.assertEqual(chat_service.search_conversation_messages(self.db, self.alice, "bob", "   "), [])
        self.assertEqual(chat_service.search_conversation_messages(self.db, self.alice, "bob", "nomatchquery"), [])

        # Non-friend search
        with self.assertRaises(NotFoundError) as ctx:
            chat_service.search_conversation_messages(self.db, self.bob, "charlie", "hello")
        self.assertEqual(str(ctx.exception), "Friend not found")


class TestReplies(BaseTestCase):
    """Tests for reply functionality and constraints (Area 8)."""

    def test_reply_to_message_in_same_conversation(self):
        """Creating a reply to a message in the same conversation succeeds and persists relationship."""
        parent = chat_service.create_message(
            self.db, self.alice, self.bob, text="Parent question", image_url=None
        )
        reply1 = chat_service.create_message(
            self.db, self.bob, self.alice, text="Reply 1", image_url=None,
            reply_to_message_id=parent.id
        )
        reply2 = chat_service.create_message(
            self.db, self.alice, self.bob, text="Reply 2 to same parent", image_url=None,
            reply_to_message_id=parent.id
        )

        self.assertEqual(reply1.reply_to_message_id, parent.id)
        self.assertEqual(reply1.reply_to.id, parent.id)
        self.assertEqual(reply2.reply_to_message_id, parent.id)
        self.assertEqual(reply2.reply_to.id, parent.id)

    def test_reply_validation_errors(self):
        """Reply rejects nonexistent parent or parent from a different conversation."""
        # Nonexistent parent
        with self.assertRaises(BadRequestError) as ctx:
            chat_service.create_message(
                self.db, self.alice, self.bob, text="Bad parent", image_url=None,
                reply_to_message_id=99999
            )
        self.assertEqual(str(ctx.exception), "Reply target message not found")

        # Parent in different conversation (Alice and Charlie)
        cross_parent = chat_service.create_message(
            self.db, self.alice, self.charlie, text="Alice to Charlie", image_url=None
        )
        with self.assertRaises(BadRequestError) as ctx:
            chat_service.create_message(
                self.db, self.bob, self.alice, text="Bob replies across convo", image_url=None,
                reply_to_message_id=cross_parent.id
            )
        self.assertEqual(str(ctx.exception), "Reply target does not belong to this conversation")

    def test_reply_to_deleted_parent(self):
        """Replying to a soft-deleted parent succeeds, and serialized reply masks parent content."""
        parent = chat_service.create_message(
            self.db, self.alice, self.bob, text="Will be deleted", image_url=None
        )
        chat_service.delete_message(self.db, self.alice, parent.id)

        # Replying to deleted parent in same conversation is permitted
        reply = chat_service.create_message(
            self.db, self.bob, self.alice, text="Replying to deleted", image_url=None,
            reply_to_message_id=parent.id
        )
        self.assertEqual(reply.reply_to_message_id, parent.id)

        ser = chat_service.serialize_message_for_api(self.db, self.bob, reply)
        self.assertEqual(ser["reply_to"]["content"], "This message was deleted")


class TestReactionsIntegration(BaseTestCase):
    """Tests for reactions integration within the chat service (Area 9)."""

    def test_reaction_integration_in_chat_history(self):
        """get_chat_history integrates reactions, handles multiple emojis, and reflects soft-deleted state."""
        msg = chat_service.create_message(
            self.db, self.alice, self.bob, text="React to me", image_url=None
        )

        # Alice reacts 👍
        reaction_service.add_reaction(self.db, self.alice, msg.id, "👍")
        # Bob reacts 👍 as well
        reaction_service.add_reaction(self.db, self.bob, msg.id, "👍")
        # Alice reacts ❤️
        reaction_service.add_reaction(self.db, self.alice, msg.id, "❤️")

        # Duplicate reaction by Alice with 👍 is idempotent
        reaction_service.add_reaction(self.db, self.alice, msg.id, "👍")

        # History includes aggregated reactions
        history = chat_service.get_chat_history(self.db, self.alice, "bob")
        self.assertEqual(len(history), 1)
        reactions = history[0]["reactions"]
        reactions_by_emoji = {r["emoji"]: r for r in reactions}

        self.assertIn("👍", reactions_by_emoji)
        self.assertEqual(reactions_by_emoji["👍"]["count"], 2)
        self.assertIn(self.alice.id, reactions_by_emoji["👍"]["user_ids"])
        self.assertIn(self.bob.id, reactions_by_emoji["👍"]["user_ids"])

        self.assertIn("❤️", reactions_by_emoji)
        self.assertEqual(reactions_by_emoji["❤️"]["count"], 1)

        # Reactions remain on soft-deleted messages
        chat_service.delete_message(self.db, self.alice, msg.id)
        history_after_delete = chat_service.get_chat_history(self.db, self.alice, "bob")
        self.assertEqual(len(history_after_delete[0]["reactions"]), 2)

    def test_reaction_lifecycle_and_boundaries(self):
        """Reaction removal works and non-participant/nonexistent message reactions are rejected."""
        msg = chat_service.create_message(
            self.db, self.alice, self.bob, text="Lifecycle", image_url=None
        )
        reaction_service.add_reaction(self.db, self.alice, msg.id, "🔥")

        # Remove reaction
        updated = reaction_service.remove_reaction(self.db, self.alice, msg.id, "🔥")
        self.assertEqual(updated, [])

        # Non-participant (Charlie) cannot react to Alice↔Bob message
        with self.assertRaises(reaction_service.NotFoundError):
            reaction_service.add_reaction(self.db, self.charlie, msg.id, "👍")

        # Reacting to nonexistent message fails
        with self.assertRaises(reaction_service.NotFoundError):
            reaction_service.add_reaction(self.db, self.alice, 99999, "👍")


class TestConversationListing(BaseTestCase):
    """Tests for list_conversations (Area 10)."""

    def test_list_conversations_aggregation_and_ordering(self):
        """list_conversations summarizes latest messages, unread counts, and excludes non-friends."""
        base_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        # Message 1 with Bob (older)
        m1 = chat_service.create_message(self.db, self.bob, self.alice, text="Older Bob msg", image_url=None)
        m1.timestamp = base_time
        # Message 2 with Bob (newer, unread)
        m2 = chat_service.create_message(self.db, self.bob, self.alice, text="Newer Bob msg", image_url=None)
        m2.timestamp = base_time + timedelta(minutes=5)
        self.db.commit()

        # Alice views conversations
        convs = {c["username"]: c for c in chat_service.list_conversations(self.db, self.alice)}
        self.assertIn("bob", convs)
        self.assertEqual(convs["bob"]["last_message"], "Newer Bob msg")
        self.assertEqual(convs["bob"]["unread_count"], 2)

        # Charlie has no messages: last_message is None, unread_count is 0
        self.assertIn("charlie", convs)
        self.assertIsNone(convs["charlie"]["last_message"])
        self.assertIsNone(convs["charlie"]["last_message_time"])
        self.assertEqual(convs["charlie"]["unread_count"], 0)

        # Soft-deleting the latest message masks its content in listing
        chat_service.delete_message(self.db, self.bob, m2.id)
        convs_after_del = {c["username"]: c for c in chat_service.list_conversations(self.db, self.alice)}
        self.assertEqual(convs_after_del["bob"]["last_message"], "This message was deleted")
        self.assertEqual(convs_after_del["bob"]["unread_count"], 1)

    def test_list_conversations_excludes_pending_or_non_friends(self):
        """Users with pending or nonexistent friendships do not appear in conversation listing."""
        dave = self.create_user(username="dave")
        # Alice sends friend request to Dave (pending)
        self.db.add(Friend(user_id=self.alice.id, friend_id=dave.id, status="pending"))
        self.db.commit()

        conv_usernames = {c["username"] for c in chat_service.list_conversations(self.db, self.alice)}
        self.assertNotIn("dave", conv_usernames)


class TestCrossConversationBoundaries(BaseTestCase):
    """Tests for cross-conversation data isolation (Area 11)."""

    def test_cross_conversation_isolation(self):
        """Messages, chat history, and unread counts never leak across conversation boundaries."""
        # Alice sends message to Bob
        chat_service.create_message(self.db, self.alice, self.bob, text="Alice to Bob private", image_url=None)

        # Alice's history with Charlie does not contain Alice↔Bob messages
        charlie_history = chat_service.get_chat_history(self.db, self.alice, "charlie")
        self.assertEqual(len(charlie_history), 0)

        # Bob cannot access Charlie's conversation (not friends)
        with self.assertRaises(NotFoundError) as ctx:
            chat_service.get_chat_history(self.db, self.bob, "charlie")
        self.assertEqual(str(ctx.exception), "Friend not found")

        # Internal helper _get_message_for_user rejects non-participants
        msg = self.db.query(Message).first()
        with self.assertRaises(NotFoundError) as ctx:
            chat_service._get_message_for_user(self.db, self.charlie, msg.id)
        self.assertEqual(str(ctx.exception), "Message not found")


if __name__ == "__main__":
    unittest.main()
