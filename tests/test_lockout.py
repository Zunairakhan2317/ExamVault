"""Tests for username lockout history and Flask per-IP rate limiting."""

import sqlite3

import pytest
from flask import Flask

from auth.lockout import (
    FAILURE_WINDOW_SECONDS,
    LOGIN_RATE_LIMIT,
    MAX_USERNAME_LENGTH,
    AccountLockedError,
    create_limiter,
    ensure_schema,
    get_lockout_seconds,
    get_threshold,
    is_locked,
    normalize_username,
    record_failure,
    record_success,
)


@pytest.fixture
def database() -> sqlite3.Connection:
    """Create an isolated in-memory lockout database connection."""
    return sqlite3.connect(":memory:")


def _failures(
    database: sqlite3.Connection,
    username: str,
    count: int,
    start: float = 100.0,
    step: float = 1.0,
) -> list[dict[str, object]]:
    """Record deterministic failures without waiting for wall-clock time."""
    return [
        record_failure(database, username, "127.0.0.1", now=start + index * step)
        for index in range(count)
    ]


def test_ensure_schema_is_idempotent_and_creates_only_required_table(
    database: sqlite3.Connection,
) -> None:
    """Repeated schema setup creates login_attempts and no other table."""
    ensure_schema(database)
    ensure_schema(database)

    tables = database.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    assert tables == [("login_attempts",)]
    columns = [row[1] for row in database.execute("PRAGMA table_info(login_attempts)")]
    assert columns == ["id", "username", "ip", "ts", "success"]


def test_never_seen_username_is_not_locked(database: sqlite3.Connection) -> None:
    """An unknown username receives the same unlocked state as any account."""
    ensure_schema(database)
    assert is_locked(database, "ghost", now=100.0) == (False, 0)


def test_fifth_failure_locks_and_marks_transition(database: sqlite3.Connection) -> None:
    """The configured fifth failed attempt starts a 15-minute lockout."""
    results = _failures(database, "alice", 5)

    assert all(not result["locked"] for result in results[:4])
    assert results[4]["locked"] is True
    assert results[4]["failed_count"] == 0
    assert results[4]["locked_until"] == 100.0 + 4 + 900
    assert results[4]["just_locked"] is True
    assert is_locked(database, "alice", now=104.0) == (True, 900)


def test_correct_password_during_lock_is_refused_and_failure_does_not_extend(
    database: sqlite3.Connection,
) -> None:
    """A correct password cannot bypass lockout and locked failures do not extend it."""
    result = _failures(database, "alice", 5)[-1]
    locked_until = result["locked_until"]
    before_count = database.execute("SELECT COUNT(*) FROM login_attempts").fetchone()[0]

    with pytest.raises(AccountLockedError) as error:
        record_success(database, "alice", "127.0.0.1", now=105.0)
    assert error.value.seconds_remaining == 899
    assert database.execute("SELECT COUNT(*) FROM login_attempts").fetchone()[0] == before_count

    during_lock = record_failure(database, "alice", "127.0.0.1", now=200.0)
    assert during_lock["locked"] is True
    assert during_lock["locked_until"] == locked_until
    assert during_lock["just_locked"] is False
    assert is_locked(database, "alice", now=200.0) == (True, int(locked_until - 200.0))


def test_lock_expires_at_exact_deadline_and_counter_starts_fresh(
    database: sqlite3.Connection,
) -> None:
    """Lock status uses strict-before expiry and a new failure sequence after expiry."""
    last = _failures(database, "alice", 5)[-1]
    locked_until = float(last["locked_until"])

    assert is_locked(database, "alice", now=locked_until) == (False, 0)
    outcomes = [
        record_failure(database, "alice", "127.0.0.1", now=locked_until + offset)
        for offset in range(4)
    ]
    assert all(outcome["locked"] is False for outcome in outcomes)
    assert outcomes[-1]["failed_count"] == 4
    fifth_after_expiry = record_failure(
        database, "alice", "127.0.0.1", now=locked_until + 4
    )
    assert fifth_after_expiry["just_locked"] is True
    assert fifth_after_expiry["locked"] is True


def test_success_resets_failure_counter(database: sqlite3.Connection) -> None:
    """A success between failure runs clears the previous failure count."""
    _failures(database, "alice", 4, start=100.0)
    record_success(database, "alice", "127.0.0.1", now=104.0)
    results = [
        record_failure(database, "alice", "127.0.0.1", now=105.0 + index)
        for index in range(4)
    ]

    assert all(result["locked"] is False for result in results)
    assert results[-1]["failed_count"] == 4


def test_failures_more_than_failure_window_apart_do_not_accumulate(
    database: sqlite3.Connection,
) -> None:
    """Failure counts reset when adjacent failed attempts are over 900 seconds apart."""
    results = [
        record_failure(
            database,
            "alice",
            "127.0.0.1",
            now=100.0 + index * (FAILURE_WINDOW_SECONDS + 1),
        )
        for index in range(8)
    ]

    assert all(result["locked"] is False for result in results)
    assert all(result["failed_count"] == 1 for result in results)


def test_usernames_share_casefolded_trimmed_counter_and_are_independent(
    database: sqlite3.Connection,
) -> None:
    """Case and surrounding whitespace normalize together while users stay isolated."""
    aliases = ("Ali", "ali", " ALI ", "Ali")
    outcomes = [
        record_failure(database, username, "127.0.0.1", now=100.0 + index)
        for index, username in enumerate(aliases)
    ]
    assert all(outcome["locked"] is False for outcome in outcomes)
    assert record_failure(database, "other", "127.0.0.2", now=104.0)["failed_count"] == 1
    assert is_locked(database, " ALI ", now=104.0) == (False, 0)


def test_unknown_username_locks_like_any_other_username(database: sqlite3.Connection) -> None:
    """Unknown names are tracked identically and reach lockout at the same threshold."""
    results = _failures(database, "ghost", 5)

    assert results[-1]["just_locked"] is True
    assert is_locked(database, "ghost", now=104.0)[0] is True


def test_sql_injection_username_is_stored_as_parameter_data(
    database: sqlite3.Connection,
) -> None:
    """SQL-looking usernames are stored safely and cannot alter the schema."""
    username = "x'); DROP TABLE login_attempts;--"
    record_failure(database, username, "127.0.0.1", now=100.0)

    stored = database.execute("SELECT username FROM login_attempts").fetchall()
    assert stored == [(normalize_username(username),)]
    assert database.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'login_attempts'"
    ).fetchone() == ("login_attempts",)


def test_rows_store_normalized_values_and_validate_username(database: sqlite3.Connection) -> None:
    """Rows contain normalized bounded usernames and the supplied event metadata."""
    long_username = "A" * 200
    record_failure(database, long_username, "i" * 100, now=321.5)
    row = database.execute(
        "SELECT username, ip, ts, success FROM login_attempts"
    ).fetchone()

    assert row == ("a" * MAX_USERNAME_LENGTH, "i" * 64, 321.5, 0)
    with pytest.raises(ValueError):
        normalize_username(42)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        record_failure(database, 42, None, now=322.0)  # type: ignore[arg-type]


def test_environment_settings_are_read_at_call_time(
    database: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Environment policy changes affect subsequent lockout calculations."""
    monkeypatch.setenv("LOCKOUT_THRESHOLD", "3")
    monkeypatch.setenv("LOCKOUT_MINUTES", "1")

    assert get_threshold() == 3
    assert get_lockout_seconds() == 60
    results = _failures(database, "alice", 3)
    assert results[-1]["locked"] is True
    assert results[-1]["just_locked"] is True
    assert results[-1]["locked_until"] == 162.0


def test_limiter_allows_five_per_ip_and_blocks_sixth_only_for_that_ip() -> None:
    """The configured login limit is five requests per minute per remote IP."""
    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = create_limiter(app)

    @app.get("/login")
    @limiter.limit(LOGIN_RATE_LIMIT)
    def login_route() -> str:
        return "ok"

    client = app.test_client()
    for _ in range(5):
        assert client.get("/login", environ_overrides={"REMOTE_ADDR": "10.0.0.1"}).status_code == 200
    assert client.get("/login", environ_overrides={"REMOTE_ADDR": "10.0.0.1"}).status_code == 429
    assert client.get("/login", environ_overrides={"REMOTE_ADDR": "10.0.0.2"}).status_code == 200
