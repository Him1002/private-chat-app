"""
Call service module for ChatSpic V2 Voice & Video Calling (Phase 1: Backend Signaling).

Provides in-memory state management, call lifecycle tracking, and validation
for peer-to-peer 1-to-1 voice and video calls without database persistence.
"""
import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, UTC
from enum import Enum
from typing import Dict, List, Optional, Tuple, Set, Callable, Awaitable

from sqlalchemy.orm import Session
from backend.db.models import User
from backend.services.friend_service import are_friends

logger = logging.getLogger(__name__)


class CallState(str, Enum):
    CALLING = "calling"
    RINGING = "ringing"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    ENDED = "ended"
    DECLINED = "declined"
    MISSED = "missed"
    FAILED = "failed"


TERMINAL_STATES: Set[CallState] = {
    CallState.ENDED,
    CallState.DECLINED,
    CallState.MISSED,
    CallState.FAILED,
}

# Constraint 2: Rejection reasons strictly limited to these three
VALID_REJECTION_REASONS: Set[str] = {"declined", "busy", "unavailable"}


@dataclass
class ActiveCall:
    call_id: str
    caller_id: int
    callee_id: int
    call_type: str  # "voice" or "video"
    state: CallState = CallState.CALLING
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    caller_username: Optional[str] = None
    callee_username: Optional[str] = None


# In-memory registries:
# call_id -> ActiveCall
_active_calls: Dict[str, ActiveCall] = {}

# user_id -> call_id (provides O(1) busy lookup)
_user_active_call: Dict[int, str] = {}

# call_id -> asyncio.Task (for unanswered ring timeouts)
_timeout_tasks: Dict[str, asyncio.Task] = {}


def get_call(call_id: str) -> Optional[ActiveCall]:
    """Find an active call by call_id."""
    return _active_calls.get(call_id)


def is_user_in_call(user_id: int) -> bool:
    """Check whether a user is currently participating in an active call."""
    call_id = _user_active_call.get(user_id)
    if not call_id:
        return False
    call = _active_calls.get(call_id)
    if not call or call.state in TERMINAL_STATES:
        # Prune stale mapping if any
        _user_active_call.pop(user_id, None)
        return False
    return True


def get_user_call(user_id: int) -> Optional[ActiveCall]:
    """Retrieve the active call for a user if present."""
    call_id = _user_active_call.get(user_id)
    if not call_id:
        return None
    call = _active_calls.get(call_id)
    if not call or call.state in TERMINAL_STATES:
        _user_active_call.pop(user_id, None)
        return None
    return call


def is_user_participant(call: ActiveCall, user_id: int) -> bool:
    """Validate whether the user belongs to the call as caller or callee."""
    return user_id in (call.caller_id, call.callee_id)


def get_other_participant(call: ActiveCall, user_id: int) -> Optional[int]:
    """Return the other participant's user_id in the call."""
    if user_id == call.caller_id:
        return call.callee_id
    elif user_id == call.callee_id:
        return call.caller_id
    return None


def create_call(
    caller_id: int,
    callee_id: int,
    call_type: str,
    call_id: str,
    caller_username: Optional[str] = None,
    callee_username: Optional[str] = None,
) -> ActiveCall:
    """Create and register a new active call in in-memory state.

    Raises:
        ValueError: If either user is already in a call or call_id already exists.
    """
    if not call_id or not isinstance(call_id, str) or not call_id.strip():
        raise ValueError("Invalid call_id")

    call_id = call_id.strip()

    if call_type not in ("voice", "video"):
        raise ValueError("call_type must be 'voice' or 'video'")

    if is_user_in_call(caller_id):
        raise ValueError("Caller is already in an active call")

    if is_user_in_call(callee_id):
        raise ValueError("Callee is already in an active call")

    if call_id in _active_calls:
        raise ValueError(f"Call with id {call_id} already exists")

    call = ActiveCall(
        call_id=call_id,
        caller_id=caller_id,
        callee_id=callee_id,
        call_type=call_type,
        state=CallState.CALLING,
        caller_username=caller_username,
        callee_username=callee_username,
    )

    _active_calls[call_id] = call
    _user_active_call[caller_id] = call_id
    _user_active_call[callee_id] = call_id

    logger.info(
        "Call created: id=%s type=%s caller=%s(%s) callee=%s(%s)",
        call_id,
        call_type,
        caller_username,
        caller_id,
        callee_username,
        callee_id,
    )
    return call


def change_call_state(call_id: str, new_state: CallState) -> Optional[ActiveCall]:
    """Update call state. If transitioned to a terminal state, prunes from in-memory active state."""
    call = _active_calls.get(call_id)
    if not call:
        return None

    prev_state = call.state
    call.state = new_state

    if new_state == CallState.CONNECTED and not call.started_at:
        call.started_at = datetime.now(UTC)

    logger.debug("Call %s state change: %s -> %s", call_id, prev_state, new_state)

    if new_state in TERMINAL_STATES:
        call.ended_at = datetime.now(UTC)
        cancel_call_timeout(call_id)
        _active_calls.pop(call_id, None)
        _user_active_call.pop(call.caller_id, None)
        _user_active_call.pop(call.callee_id, None)

    return call


def end_call(call_id: str, terminal_state: CallState = CallState.ENDED) -> Optional[ActiveCall]:
    """End a call with a terminal state and clean up active memory structures."""
    if terminal_state not in TERMINAL_STATES:
        terminal_state = CallState.ENDED
    return change_call_state(call_id, terminal_state)


def cleanup_user_calls(user_id: int) -> List[ActiveCall]:
    """Find and terminate any active calls for the given user (e.g. on final socket disconnect)."""
    ended_calls: List[ActiveCall] = []
    call_id = _user_active_call.get(user_id)
    if call_id:
        call = _active_calls.get(call_id)
        if call:
            end_call(call_id, CallState.FAILED)
            ended_calls.append(call)
    return ended_calls


def cancel_call_timeout(call_id: str) -> None:
    """Cancel any pending unanswered call ring timeout task."""
    task = _timeout_tasks.pop(call_id, None)
    if task and not task.done():
        task.cancel()


def schedule_call_timeout(
    call_id: str,
    timeout_seconds: float,
    on_timeout: Optional[Callable[[ActiveCall], Awaitable[None]]] = None,
) -> asyncio.Task:
    """Schedule an asynchronous timer to expire unanswered calls."""
    cancel_call_timeout(call_id)

    async def _timer_worker():
        try:
            await asyncio.sleep(timeout_seconds)
            call = get_call(call_id)
            if call and call.state in (CallState.CALLING, CallState.RINGING):
                logger.info("Call %s timed out waiting for answer", call_id)
                end_call(call_id, CallState.MISSED)
                if on_timeout:
                    await on_timeout(call)
        except asyncio.CancelledError:
            pass
        finally:
            _timeout_tasks.pop(call_id, None)

    task = asyncio.create_task(_timer_worker())
    _timeout_tasks[call_id] = task
    return task


def reset_call_state() -> None:
    """Reset all active calls and pending timeouts (strictly for test isolation)."""
    for task in list(_timeout_tasks.values()):
        if not task.done():
            task.cancel()
    _timeout_tasks.clear()
    _active_calls.clear()
    _user_active_call.clear()
