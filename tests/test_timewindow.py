"""Tests for UTC-only exam authorization windows."""

import sqlite3
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from auth.timewindow import (
    WindowError,
    WindowStatus,
    is_within_window,
    parse_utc,
    require_open,
    seconds_until_close,
    seconds_until_open,
    utc_now,
    window_bounds,
    window_status,
    window_summary,
)

START = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
END = START + timedelta(seconds=100)


def _exam(start: datetime = START, end: datetime = END) -> dict[str, str]:
    """Build exam metadata using the window fields stored by paper_service."""
    return {
        "release_window_start": start.isoformat(),
        "release_window_end": end.isoformat(),
    }


def test_before_start_start_inclusive_open_interval_and_end_exclusive() -> None:
    """Window states follow paper_service: start inclusive and end exclusive."""
    exam = _exam()

    assert window_status(exam, START - timedelta(seconds=1)) is WindowStatus.BEFORE
    assert window_status(exam, START) is WindowStatus.OPEN
    assert window_status(exam, START + timedelta(seconds=50)) is WindowStatus.OPEN
    assert window_status(exam, END - timedelta(seconds=1)) is WindowStatus.OPEN
    assert window_status(exam, END) is WindowStatus.CLOSED
    assert window_status(exam, END + timedelta(seconds=1)) is WindowStatus.CLOSED
    assert is_within_window(exam, START)
    assert not is_within_window(exam, END)


def test_zero_length_or_reversed_window_and_missing_fields_raise_value_error() -> None:
    """Invalid or incomplete signed windows cannot authorize an action."""
    with pytest.raises(ValueError, match="end must be after start"):
        window_bounds(_exam(START, START))
    with pytest.raises(ValueError, match="end must be after start"):
        window_bounds(_exam(END, START))
    with pytest.raises(ValueError, match="missing required field"):
        window_bounds({"release_window_start": START.isoformat()})


@pytest.mark.parametrize(
    "invalid_time",
    [
        datetime(2025, 1, 1, 12, 0),
        "2025-01-01T12:00:00",
        "not-a-date",
    ],
)
def test_parse_utc_rejects_naive_or_invalid_time(invalid_time: str | datetime) -> None:
    """Naive and malformed instants are rejected instead of guessed as local time."""
    with pytest.raises(ValueError):
        parse_utc(invalid_time)


def test_parse_utc_rejects_another_type() -> None:
    """Only ISO strings and datetime values can define trusted window bounds."""
    with pytest.raises(TypeError):
        parse_utc(123)  # type: ignore[arg-type]


def test_parse_utc_accepts_z_and_converts_offset_to_utc() -> None:
    """ISO Z suffixes and offset datetimes normalize to the same UTC instant."""
    expected = datetime(2025, 1, 1, 7, 0, tzinfo=timezone.utc)

    assert parse_utc("2025-01-01T07:00:00Z") == expected
    assert parse_utc("2025-01-01T12:00:00+05:00") == expected


def test_window_bounds_accepts_dict_object_and_sqlite_row() -> None:
    """Supported exam representations produce identical normalized UTC bounds."""
    expected = (START, END)
    dictionary = _exam()
    object_exam = SimpleNamespace(**dictionary)
    database = sqlite3.connect(":memory:")
    database.row_factory = sqlite3.Row
    row = database.execute(
        "SELECT ? AS release_window_start, ? AS release_window_end",
        (dictionary["release_window_start"], dictionary["release_window_end"]),
    ).fetchone()

    assert window_bounds(dictionary) == expected
    assert window_bounds(object_exam) == expected
    assert window_bounds(row) == expected


def test_require_open_succeeds_when_open_and_carries_refusal_status() -> None:
    """Window refusals carry the exact authorization state for the web layer."""
    exam = _exam()

    assert require_open(exam, START) is None
    with pytest.raises(WindowError, match="Window not open yet") as before_error:
        require_open(exam, START - timedelta(seconds=1))
    assert before_error.value.status is WindowStatus.BEFORE
    with pytest.raises(WindowError, match="Window closed") as closed_error:
        require_open(exam, END)
    assert closed_error.value.status is WindowStatus.CLOSED


def test_countdowns_round_up_fractional_seconds_and_clamp_passed_times() -> None:
    """Countdowns round positive fractional seconds upward and never go negative."""
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    open_in_90 = {"release_window_start": (base + timedelta(seconds=90)).isoformat(),
                  "release_window_end": (base + timedelta(seconds=200)).isoformat()}
    open_in_90_5 = {"release_window_start": (base + timedelta(seconds=90.5)).isoformat(),
                    "release_window_end": (base + timedelta(seconds=200)).isoformat()}
    close_in_90 = {"release_window_start": (base - timedelta(seconds=20)).isoformat(),
                   "release_window_end": (base + timedelta(seconds=90)).isoformat()}
    close_in_90_5 = {"release_window_start": (base - timedelta(seconds=20)).isoformat(),
                     "release_window_end": (base + timedelta(seconds=90.5)).isoformat()}
    closed = _exam(START, END)

    assert seconds_until_open(open_in_90, base) == 90
    assert seconds_until_open(open_in_90_5, base) == 91
    assert seconds_until_close(close_in_90, base) == 90
    assert seconds_until_close(close_in_90_5, base) == 91
    assert seconds_until_open(closed, END + timedelta(seconds=1)) == 0
    assert seconds_until_close(closed, END) == 0


def test_summary_has_exact_keys_and_values_in_all_states() -> None:
    """Countdown summaries expose normalized bounds and status consistently."""
    exam = _exam()
    expected_keys = {
        "status",
        "seconds_until_open",
        "seconds_until_close",
        "start_utc",
        "end_utc",
    }

    before = window_summary(exam, START - timedelta(seconds=90.5))
    opened = window_summary(exam, START)
    closed = window_summary(exam, END)

    assert set(before) == expected_keys
    assert before == {
        "status": WindowStatus.BEFORE,
        "seconds_until_open": 91,
        "seconds_until_close": 191,
        "start_utc": START.isoformat(),
        "end_utc": END.isoformat(),
    }
    assert opened["status"] is WindowStatus.OPEN
    assert opened["seconds_until_open"] == 0
    assert opened["seconds_until_close"] == 100
    assert closed["status"] is WindowStatus.CLOSED
    assert closed["seconds_until_open"] == 0
    assert closed["seconds_until_close"] == 0
    assert closed["start_utc"] == START.isoformat()
    assert closed["end_utc"] == END.isoformat()


def test_utc_now_is_aware_and_zero_offset() -> None:
    """The authorization clock returns a timezone-aware UTC instant."""
    now = utc_now()

    assert now.tzinfo is not None
    assert now.utcoffset() == timedelta(0)
