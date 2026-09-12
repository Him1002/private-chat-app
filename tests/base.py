"""Base test case and database isolation for ChatSpic automated tests.

Provides an isolated, in-memory SQLite database for each test case with
foreign-key enforcement enabled, automatic table creation/cleanup, and
standard fixture seeding.
"""
import unittest
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.db.database import Base
from backend.db.models import User, Friend


def _enable_sqlite_fk(dbapi_conn, connection_record):
    """Enable SQLite foreign key constraint enforcement."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


class BaseTestCase(unittest.TestCase):
    """Base test case providing an isolated SQLite database and common fixtures.

    Each test case receives an isolated in-memory database instance with
    PRAGMA foreign_keys=ON enforced. No test writes to or depends on the
    development chat.db.
    """

    seed_default_users: bool = True

    def setUp(self):
        super().setUp()

        # Dedicated, isolated in-memory database per test case.
        # StaticPool ensures all connections within this test case operate on
        # the same in-memory instance without sharing state across test cases.
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )

        # Enforce foreign key constraints across all connections
        event.listen(self.engine, "connect", _enable_sqlite_fk)

        # Build schema fresh from metadata
        Base.metadata.create_all(bind=self.engine)

        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine,
        )
        self.db = self.SessionLocal()

        # Verify foreign keys are active
        fk_status = self.db.execute(text("PRAGMA foreign_keys")).scalar()
        if fk_status != 1:
            raise RuntimeError("PRAGMA foreign_keys must be ON in test database session")

        if self.seed_default_users:
            self.seed_standard_users_and_friendships()

    def tearDown(self):
        try:
            if hasattr(self, "db") and self.db:
                self.db.close()
            if hasattr(self, "engine") and self.engine:
                Base.metadata.drop_all(bind=self.engine)
                self.engine.dispose()
        finally:
            super().tearDown()

    def seed_standard_users_and_friendships(self):
        """Seed standard test users (alice, bob, charlie) and two-way friendships."""
        self.alice = User(
            username="alice",
            password_hash="hash1",
            display_name="Alice",
        )
        self.bob = User(
            username="bob",
            password_hash="hash2",
            display_name="Bob",
        )
        self.charlie = User(
            username="charlie",
            password_hash="hash3",
            display_name="Charlie",
        )
        self.db.add_all([self.alice, self.bob, self.charlie])
        self.db.commit()
        self.db.refresh(self.alice)
        self.db.refresh(self.bob)
        self.db.refresh(self.charlie)

        # Establish two-way accepted friendships
        # alice <-> bob
        self.db.add(Friend(user_id=self.alice.id, friend_id=self.bob.id, status="accepted"))
        self.db.add(Friend(user_id=self.bob.id, friend_id=self.alice.id, status="accepted"))
        # alice <-> charlie
        self.db.add(Friend(user_id=self.alice.id, friend_id=self.charlie.id, status="accepted"))
        self.db.add(Friend(user_id=self.charlie.id, friend_id=self.alice.id, status="accepted"))
        self.db.commit()

    def create_user(self, username: str, password_hash: str = "hash", display_name: str = None) -> User:
        """Helper to create and persist a test user."""
        user = User(
            username=username,
            password_hash=password_hash,
            display_name=display_name or username.capitalize(),
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def create_two_way_friendship(self, user1: User, user2: User, status: str = "accepted"):
        """Helper to create and persist a bidirectional friendship."""
        self.db.add(Friend(user_id=user1.id, friend_id=user2.id, status=status))
        self.db.add(Friend(user_id=user2.id, friend_id=user1.id, status=status))
        self.db.commit()
