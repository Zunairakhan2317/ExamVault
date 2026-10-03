"""UTC exam-window checks for authorization.

The ONLY time source is the server clock (utc_now()); no function accepts a time
from a browser. The ``now`` parameter exists only so tests control time. Refusals
are logged by the web layer. The boundary rule is identical to
crypto/services/paper_service.py so both always agree: start is inclusive and
end is exclusive.
"""

import math
import sqlite3
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class WindowStatus(str, Enum):
    """Authorization state determined from the trusted UTC clock."""

    BEFORE = "before"
    OPEN = "open"
    CLOSED = "closed"


class WindowError(Exception):
    """Safe authorization refusal carrying the exam-window state."""

    def __init__(self, status: WindowStatus, message: str) -> None:
        """Preserve the structured refusal status for the web layer."""
        super().__init__(message)
        self.status = status
        self.message = message


def utc_now() -> datetime:
    """Return the trusted server clock in UTC for time-window authorization."""
    return datetime.now(timezone.utc)


def parse_utc(value: str | datetime) -> datetime:
    """Parse an aware instant and normalize it to UTC for secure comparisons."""
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError as error:
            raise ValueError("time must be a valid ISO 8601 datetime") from error
    else:
        raise TypeError("time must be an ISO 8601 string or datetime")

    if parsed.utcoffset() is None:
        raise ValueError("time must include a timezone")
    return parsed.astimezone(timezone.utc)


def _get_window_value(exam: Any, field_name: str) -> str | datetime:
    """Read an exam window field from a mapping, SQLite row, or object."""
    try:
        if isinstance(exam, dict):
            return exam[field_name]
        if isinstance(exam, sqlite3.Row):
            return exam[field_name]
        return getattr(exam, field_name)
    except (KeyError, IndexError, AttributeError, TypeError) as error:
        raise ValueError(f"exam is missing required field {field_name}") from error


def window_bounds(exam: Any) -> tuple[datetime, datetime]:
    """Read and validate the signed UTC window bounds used for authorization."""
    start = parse_utc(_get_window_value(exam, "release_window_start"))
    end = parse_utc(_get_window_value(exam, "release_window_end"))
    if end <= start:
        raise ValueError("release window end must be after start")
    return start, end


def _effective_now(now: str | datetime | None) -> datetime:
    """Use server UTC unless a test-only controlled timestamp is provided."""
    return utc_now() if now is None else parse_utc(now)


def window_status(
    exam: Any,
    now: str | datetime | None = None,
) -> WindowStatus:
    """Classify an exam window using UTC and the service's inclusive/exclusive bounds."""
    start, end = window_bounds(exam)
    current = _effective_now(now)
    if current < start:
        return WindowStatus.BEFORE
    if current < end:
        return WindowStatus.OPEN
    return WindowStatus.CLOSED


def is_within_window(exam: Any, now: str | datetime | None = None) -> bool:
    """Authorize an action only while its exam window is open on the server clock."""
    return window_status(exam, now) is WindowStatus.OPEN


def require_open(exam: Any, now: str | datetime | None = None) -> None:
    """Raise a structured authorization refusal when the server-clock window is closed."""
    status = window_status(exam, now)
    if status is WindowStatus.BEFORE:
        raise WindowError(WindowStatus.BEFORE, "Window not open yet")
    if status is WindowStatus.CLOSED:
        raise WindowError(WindowStatus.CLOSED, "Window closed")


def seconds_until_open(exam: Any, now: str | datetime | None = None) -> int:
    """Return a non-negative rounded-up countdown until authorization opens."""
    start, _ = window_bounds(exam)
    seconds = (start - _effective_now(now)).total_seconds()
    return max(0, math.ceil(seconds))


def seconds_until_close(exam: Any, now: str | datetime | None = None) -> int:
    """Return a non-negative rounded-up countdown until authorization closes."""
    _, end = window_bounds(exam)
    seconds = (end - _effective_now(now)).total_seconds()
    return max(0, math.ceil(seconds))


def window_summary(
    exam: Any,
    now: str | datetime | None = None,
) -> dict[str, str | int | WindowStatus]:
    """Provide UTC bounds, status, and safe countdown values for the invigilator view."""
    start, end = window_bounds(exam)
    current = _effective_now(now)
    status = window_status(exam, current)
    return {
        "status": status,
        "seconds_until_open": max(0, math.ceil((start - current).total_seconds())),
        "seconds_until_close": max(0, math.ceil((end - current).total_seconds())),
        "start_utc": start.isoformat(),
        "end_utc": end.isoformat(),
    }
