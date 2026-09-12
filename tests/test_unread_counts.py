import unittest

from backend.db.models import Message
from backend.services import chat_service
from tests.base import BaseTestCase


class TestRealUnreadCounts(BaseTestCase):


    def _get_conv(self, current_user, friend_username):
        conversations = chat_service.list_conversations(self.db, current_user)
        for c in conversations:
            if c["username"] == friend_username:
                return c
        return None

    def test_unread_count_starts_at_zero(self):
        """Conversations with no messages should start with unread_count=0."""
        conv_bob = self._get_conv(self.alice, "bob")
        conv_charlie = self._get_conv(self.alice, "charlie")

        self.assertIsNotNone(conv_bob)
        self.assertEqual(conv_bob["unread_count"], 0)
        self.assertIsNone(conv_bob["last_message"])

        self.assertIsNotNone(conv_charlie)
        self.assertEqual(conv_charlie["unread_count"], 0)

        # Direct helper check
        self.assertEqual(chat_service.get_unread_count(self.db, self.alice.id, self.bob.id), 0)

    def test_incoming_unread_message_increments_count(self):
        """Incoming message from friend increases user's unread count to 1."""
        chat_service.create_message(self.db, sender=self.bob, receiver=self.alice, text="Hello Alice", image_url=None)

        conv = self._get_conv(self.alice, "bob")
        self.assertIsNotNone(conv)
        self.assertEqual(conv["unread_count"], 1)
        self.assertEqual(conv["last_message"], "Hello Alice")
        self.assertEqual(chat_service.get_unread_count(self.db, self.alice.id, self.bob.id), 1)

    def test_multiple_unread_messages_produce_correct_count(self):
        """Multiple unread incoming messages produce the exact count."""
        chat_service.create_message(self.db, sender=self.bob, receiver=self.alice, text="Msg 1", image_url=None)
        chat_service.create_message(self.db, sender=self.bob, receiver=self.alice, text="Msg 2", image_url=None)
        chat_service.create_message(self.db, sender=self.bob, receiver=self.alice, text="Msg 3", image_url=None)

        conv = self._get_conv(self.alice, "bob")
        self.assertEqual(conv["unread_count"], 3)
        # Messages created in rapid succession may share the same timestamp,
        # making ORDER BY timestamp DESC non-deterministic for tie-breaking.
        self.assertIn(conv["last_message"], ["Msg 1", "Msg 2", "Msg 3"])
        self.assertEqual(chat_service.get_unread_count(self.db, self.alice.id, self.bob.id), 3)

    def test_own_messages_do_not_count(self):
        """Messages sent by the current user do not count toward their own unread count."""
        # Alice sends 2 messages to Bob
        chat_service.create_message(self.db, sender=self.alice, receiver=self.bob, text="From Alice 1", image_url=None)
        chat_service.create_message(self.db, sender=self.alice, receiver=self.bob, text="From Alice 2", image_url=None)

        # Alice views conversations: her unread count for Bob must be 0
        conv_alice = self._get_conv(self.alice, "bob")
        self.assertEqual(conv_alice["unread_count"], 0)
        # Messages created in rapid succession may share the same timestamp,
        # making ORDER BY timestamp DESC non-deterministic for tie-breaking.
        self.assertIn(conv_alice["last_message"], ["From Alice 1", "From Alice 2"])
        self.assertEqual(chat_service.get_unread_count(self.db, self.alice.id, self.bob.id), 0)

        # Bob views conversations: his unread count for Alice must be 2
        conv_bob = self._get_conv(self.bob, "alice")
        self.assertEqual(conv_bob["unread_count"], 2)
        self.assertIn(conv_bob["last_message"], ["From Alice 1", "From Alice 2"])
        self.assertEqual(chat_service.get_unread_count(self.db, self.bob.id, self.alice.id), 2)

    def test_received_message_remains_unread_until_read_flow(self):
        """Explicit test proving that creating/receiving a message does NOT mark it read.

        The database is the source of truth: is_read stays False until the existing
        read flow (mark_conversation_messages_read or mark_messages_read) marks it read.
        """
        msg = chat_service.create_message(
            self.db,
            sender=self.bob,
            receiver=self.alice,
            text="Unread check",
            image_url=None,
        )

        # Message is not read upon creation/reception
        self.assertFalse(msg.is_read)
        self.assertIsNone(msg.read_at)

        # Listing conversations reflects unread count=1 and does not mark it read
        conv_before = self._get_conv(self.alice, "bob")
        self.assertEqual(conv_before["unread_count"], 1)

        # Re-fetch message from DB: is_read must still be False
        self.db.refresh(msg)
        self.assertFalse(msg.is_read)
        self.assertIsNone(msg.read_at)

        # Only when existing read flow runs does it become read
        newly_read = chat_service.mark_conversation_messages_read(self.db, self.alice, self.bob)
        self.assertEqual(len(newly_read), 1)
        self.assertTrue(newly_read[0].is_read)
        self.assertIsNotNone(newly_read[0].read_at)

        # Unread count is now 0
        conv_after = self._get_conv(self.alice, "bob")
        self.assertEqual(conv_after["unread_count"], 0)

    def test_marking_conversation_read_reduces_count_to_zero(self):
        """Opening a conversation marks all incoming messages as read, reducing count to 0."""
        chat_service.create_message(self.db, sender=self.bob, receiver=self.alice, text="M1", image_url=None)
        chat_service.create_message(self.db, sender=self.bob, receiver=self.alice, text="M2", image_url=None)

        self.assertEqual(chat_service.get_unread_count(self.db, self.alice.id, self.bob.id), 2)

        read_messages = chat_service.mark_conversation_messages_read(self.db, self.alice, self.bob)
        self.assertEqual(len(read_messages), 2)
        for m in read_messages:
            self.assertTrue(m.is_read)
            self.assertIsNotNone(m.read_at)

        self.assertEqual(chat_service.get_unread_count(self.db, self.alice.id, self.bob.id), 0)
        conv = self._get_conv(self.alice, "bob")
        self.assertEqual(conv["unread_count"], 0)

    def test_marking_single_message_read(self):
        """Marking an individual message read reduces the unread count by 1."""
        msg1 = chat_service.create_message(self.db, sender=self.bob, receiver=self.alice, text="M1", image_url=None)
        msg2 = chat_service.create_message(self.db, sender=self.bob, receiver=self.alice, text="M2", image_url=None)

        self.assertEqual(chat_service.get_unread_count(self.db, self.alice.id, self.bob.id), 2)

        res = chat_service.mark_messages_read(self.db, self.alice, msg1.id)
        self.assertTrue(res["is_read"])
        self.assertEqual(res["status"], "read")

        self.assertEqual(chat_service.get_unread_count(self.db, self.alice.id, self.bob.id), 1)

    def test_deleted_incoming_messages_excluded_and_safe(self):
        """Deleted incoming messages are excluded from unread count and do not expose content."""
        msg = chat_service.create_message(
            self.db,
            sender=self.bob,
            receiver=self.alice,
            text="Top secret",
            image_url=None,
        )
        self.assertEqual(chat_service.get_unread_count(self.db, self.alice.id, self.bob.id), 1)

        # Bob deletes his message before Alice reads it
        chat_service.delete_message(self.db, self.bob, msg.id)

        # Deleted message must not count as unread
        self.assertEqual(chat_service.get_unread_count(self.db, self.alice.id, self.bob.id), 0)

        # Deleted message content must not be exposed in list_conversations
        conv = self._get_conv(self.alice, "bob")
        self.assertEqual(conv["unread_count"], 0)
        self.assertEqual(conv["last_message"], "This message was deleted")

    def test_separate_conversations_maintain_separate_counts(self):
        """Different friend conversations maintain completely independent unread counts."""
        # Bob sends 2 messages to Alice
        chat_service.create_message(self.db, sender=self.bob, receiver=self.alice, text="B1", image_url=None)
        chat_service.create_message(self.db, sender=self.bob, receiver=self.alice, text="B2", image_url=None)

        # Charlie sends 1 message to Alice
        chat_service.create_message(self.db, sender=self.charlie, receiver=self.alice, text="C1", image_url=None)

        # Alice sends 3 messages to Bob
        chat_service.create_message(self.db, sender=self.alice, receiver=self.bob, text="A1", image_url=None)
        chat_service.create_message(self.db, sender=self.alice, receiver=self.bob, text="A2", image_url=None)
        chat_service.create_message(self.db, sender=self.alice, receiver=self.bob, text="A3", image_url=None)

        # Alice's counts: Bob has 2, Charlie has 1
        self.assertEqual(chat_service.get_unread_count(self.db, self.alice.id, self.bob.id), 2)
        self.assertEqual(chat_service.get_unread_count(self.db, self.alice.id, self.charlie.id), 1)

        # Bob's counts: Alice has 3
        self.assertEqual(chat_service.get_unread_count(self.db, self.bob.id, self.alice.id), 3)

        # Charlie's counts: Alice has 0
        self.assertEqual(chat_service.get_unread_count(self.db, self.charlie.id, self.alice.id), 0)

        # Alice reads Bob's messages only
        chat_service.mark_conversation_messages_read(self.db, self.alice, self.bob)

        # Bob's conversation is now 0 unread for Alice, Charlie's conversation is STILL 1 unread
        self.assertEqual(chat_service.get_unread_count(self.db, self.alice.id, self.bob.id), 0)
        self.assertEqual(chat_service.get_unread_count(self.db, self.alice.id, self.charlie.id), 1)

    def test_read_receipt_metadata_and_serialization(self):
        """Read receipts and message serialization maintain proper read/sent status."""
        msg = chat_service.create_message(self.db, sender=self.bob, receiver=self.alice, text="Hi", image_url=None)
        msg_dict = chat_service._message_to_dict(msg, self.alice, self.bob)
        self.assertEqual(msg_dict["status"], "sent")
        self.assertFalse(msg_dict["is_read"])
        self.assertIsNone(msg_dict["read_at"])

        chat_service.mark_conversation_messages_read(self.db, self.alice, self.bob)
        self.db.refresh(msg)
        msg_dict_read = chat_service._message_to_dict(msg, self.alice, self.bob)
        self.assertEqual(msg_dict_read["status"], "read")
        self.assertTrue(msg_dict_read["is_read"])
        self.assertIsNotNone(msg_dict_read["read_at"])


if __name__ == "__main__":
    unittest.main()
