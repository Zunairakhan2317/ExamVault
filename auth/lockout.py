"""Username-based login lockout and IP rate-limit configuration.

Call ``is_locked`` before verifying a password, and show the same generic error
for a wrong password and a locked account. Never reveal whether a username
exists. The web layer writes audit entries for failures, lockouts, and rate-limit
hits; this module itself does not log credentials or attempts.
"""

import os
import sqlite3
import time
from math import ceil
from typing import Any

from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

FAILURE_WINDOW_SECONDS = 900
MAX_USERNAME_LENGTH = 150
LOGIN_RATE_LIMIT = "5 per minute"


def get_threshold() -> int:
    """Read the failed-login threshold dynamically for lockout policy."""
    return int(os.environ.get("LOCKOUT_THRESHOLD", "5"))


def get_lockout_seconds() -> int:
    """Read the account lockout duration dynamically, in seconds."""
    return int(os.environ.get("LOCKOUT_MINUTES", "15")) * 60


class AccountLockedError(Exception):
    """Signal that a correct password cannot bypass an active account lockout."""

    def __init__(self, seconds_remaining: int) -> None:
        """Expose only the remaining lock duration, never account credentials."""
        super().__init__("Account is temporarily locked")
        self.seconds_remaining = seconds_remaining


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the single login-attempt table and lookup index idempotently."""
    conn.execute(
        """CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip TEXT,
            ts REAL NOT NULL,
            success INTEGER NOT NULL
        )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_login_attempts_username_ts "
        "ON login_attempts (username, ts)"
    )


def normalize_username(username: str) -> str:
    """Canonicalize usernames so case and surrounding spaces share one lockout."""
    if not isinstance(username, str):
        raise ValueError("username must be a string")
    return username.strip().casefold()[:MAX_USERNAME_LENGTH]


def _replay(
    rows: list[tuple[float, int]],
    threshold: int,
    lockout_seconds: int,
) -> tuple[int, float | None]:
    """Replay timestamped outcomes to compute failures and the active lock deadline."""
    count = 0
    last_fail_ts: float | None = None
    locked_until: float | None = None
    for timestamp, success in rows:
        if locked_until is not None and timestamp < locked_until:
            continue
        if success == 1:
            count = 0
            last_fail_ts = None
            locked_until = None
        else:
            if last_fail_ts is None or timestamp - last_fail_ts > FAILURE_WINDOW_SECONDS:
                count = 1
            else:
                count += 1
            last_fail_ts = timestamp
            if count >= threshold:
                locked_until = timestamp + lockout_seconds
                count = 0
                last_fail_ts = None
    return count, locked_until


def _lock_state(
    conn: sqlite3.Connection,
    normalized_username: str,
    timestamp: float,
) -> tuple[int, float | None]:
    """Calculate lock state from this username's ordered attempt history."""
    rows = conn.execute(
        "SELECT ts, success FROM login_attempts WHERE username = ? ORDER BY ts, id",
        (normalized_username,),
    ).fetchall()
    attempts = [(float(row[0]), int(row[1])) for row in rows]
    return _replay(attempts, get_threshold(), get_lockout_seconds())


def is_locked(
    conn: sqlite3.Connection,
    username: str,
    now: float | None = None,
) -> tuple[bool, int]:
    """Check whether the normalized account is currently locked using server time."""
    normalized_username = normalize_username(username)
    timestamp = time.time() if now is None else now
    _, locked_until = _lock_state(conn, normalized_username, timestamp)
    if locked_until is not None and timestamp < locked_until:
        return True, ceil(locked_until - timestamp)
    return False, 0


def record_failure(
    conn: sqlite3.Connection,
    username: str,
    ip: str | None,
    now: float | None = None,
) -> dict[str, Any]:
    """Persist a failed login and report whether this attempt newly caused lockout."""
    normalized_username = normalize_username(username)
    timestamp = time.time() if now is None else now
    normalized_ip = ip[:64] if isinstance(ip, str) else None

    with conn:
        ensure_schema(conn)
        was_locked, _ = is_locked(conn, normalized_username, timestamp)
        conn.execute(
            "INSERT INTO login_attempts (username, ip, ts, success) VALUES (?, ?, ?, ?)",
            (normalized_username, normalized_ip, timestamp, 0),
        )
        failed_count, locked_until = _lock_state(
            conn, normalized_username, timestamp
        )

    locked = locked_until is not None and timestamp < locked_until
    return {
        "locked": locked,
        "failed_count": failed_count,
        "locked_until": locked_until,
        "just_locked": not was_locked and locked,
    }


def record_success(
    conn: sqlite3.Connection,
    username: str,
    ip: str | None,
    now: float | None = None,
) -> None:
    """Record a successful login only when no active lockout forbids authentication."""
    normalized_username = normalize_username(username)
    timestamp = time.time() if now is None else now
    normalized_ip = ip[:64] if isinstance(ip, str) else None

    with conn:
        ensure_schema(conn)
        locked, seconds_remaining = is_locked(conn, normalized_username, timestamp)
        if locked:
            raise AccountLockedError(seconds_remaining)
        conn.execute(
            "INSERT INTO login_attempts (username, ip, ts, success) VALUES (?, ?, ?, ?)",
            (normalized_username, normalized_ip, timestamp, 1),
        )


def create_limiter(app: Flask) -> Limiter:
    """Configure the Flask per-IP limiter used to curb repeated login attempts."""
    return Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=[],
        storage_uri="memory://",
    )
