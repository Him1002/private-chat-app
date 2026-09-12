"""Tests package for ChatApp backend."""
import os

# Secondary safeguard: if any component imports backend.db.database during tests,
# ensure it does not default to the real chat.db.
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
