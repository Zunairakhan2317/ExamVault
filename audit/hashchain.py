"""Append-only SHA-256 audit chain backed by SQLite."""

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

GENESIS_HASH = "0" * 64
_TABLE_NAME = "audit_entries"


def _canonical_entry(
    entry_id: int,
    timestamp: str,
    event_type: str,
    details: str,
    actor: str,
    prev_hash: str,
) -> bytes:
    """Serialize audit fields canonically so the chain hash is reproducible."""
    payload = {
        "actor": actor,
        "details": details,
        "event_type": event_type,
        "id": entry_id,
        "prev_hash": prev_hash,
        "timestamp": timestamp,
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _entry_hash(
    entry_id: int,
    timestamp: str,
    event_type: str,
    details: str,
    actor: str,
    prev_hash: str,
) -> str:
    """Calculate the SHA-256 digest for one canonical audit record."""
    return hashlib.sha256(
        _canonical_entry(entry_id, timestamp, event_type, details, actor, prev_hash)
    ).hexdigest()


def _ensure_schema(db_conn: sqlite3.Connection) -> None:
    """Create the audit table and integrity triggers on the caller's connection."""
    db_conn.execute(
        """CREATE TABLE IF NOT EXISTS audit_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            details TEXT NOT NULL,
            actor TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL UNIQUE
        )"""
    )
    db_conn.execute(
        """CREATE TRIGGER IF NOT EXISTS audit_entries_no_update
           BEFORE UPDATE ON audit_entries
           BEGIN
               SELECT RAISE(ABORT, 'audit entries are append-only');
           END"""
    )
    db_conn.execute(
        """CREATE TRIGGER IF NOT EXISTS audit_entries_no_delete
           BEFORE DELETE ON audit_entries
           BEGIN
               SELECT RAISE(ABORT, 'audit entries are append-only');
           END"""
    )
    db_conn.execute(
        """CREATE TRIGGER IF NOT EXISTS audit_entries_valid_append
           BEFORE INSERT ON audit_entries
           WHEN NEW.prev_hash != COALESCE(
               (SELECT entry_hash FROM audit_entries ORDER BY id DESC LIMIT 1),
               '0000000000000000000000000000000000000000000000000000000000000000'
           )
           BEGIN
               SELECT RAISE(ABORT, 'audit entry must extend the current chain tip');
           END"""
    )


def add_audit_entry(
    db_conn: sqlite3.Connection,
    event_type: str,
    details: str,
    actor: str,
) -> dict[str, Any]:
    """Append a SHA-256-linked audit event without committing the caller's transaction."""
    if not isinstance(db_conn, sqlite3.Connection):
        raise TypeError("db_conn must be an sqlite3.Connection")
    if not all(isinstance(value, str) for value in (event_type, details, actor)):
        raise TypeError("event_type, details, and actor must be strings")

    _ensure_schema(db_conn)
    if not verify_hashchain(db_conn):
        raise ValueError("existing audit chain is invalid")
    previous = db_conn.execute(
        "SELECT entry_hash FROM audit_entries ORDER BY id DESC LIMIT 1"
    ).fetchone()
    prev_hash = GENESIS_HASH if previous is None else str(previous[0])
    timestamp = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )
    maximum_id = int(
        db_conn.execute("SELECT COALESCE(MAX(id), 0) FROM audit_entries").fetchone()[0]
    )
    sequence_row = db_conn.execute(
        "SELECT seq FROM sqlite_sequence WHERE name = ?", (_TABLE_NAME,)
    ).fetchone()
    last_issued_id = maximum_id if sequence_row is None else max(maximum_id, int(sequence_row[0]))
    entry_id = last_issued_id + 1
    entry_hash = _entry_hash(entry_id, timestamp, event_type, details, actor, prev_hash)
    db_conn.execute(
        """INSERT INTO audit_entries
           (id, timestamp, event_type, details, actor, prev_hash, entry_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (entry_id, timestamp, event_type, details, actor, prev_hash, entry_hash),
    )
    return {
        "id": entry_id,
        "timestamp": timestamp,
        "event_type": event_type,
        "details": details,
        "actor": actor,
        "prev_hash": prev_hash,
        "entry_hash": entry_hash,
    }


def verify_hashchain(db_conn: sqlite3.Connection) -> bool:
    """Verify every audit digest and previous-hash link in sequence."""
    if not isinstance(db_conn, sqlite3.Connection):
        raise TypeError("db_conn must be an sqlite3.Connection")
    try:
        rows = db_conn.execute(
            """SELECT id, timestamp, event_type, details, actor, prev_hash, entry_hash
               FROM audit_entries ORDER BY id ASC"""
        ).fetchall()
    except sqlite3.Error:
        return False

    expected_previous = GENESIS_HASH
    expected_id = 1
    for row in rows:
        entry_id, timestamp, event_type, details, actor, prev_hash, stored_hash = row
        if (
            not isinstance(entry_id, int)
            or entry_id != expected_id
            or not all(
                isinstance(value, str)
                for value in (
                    timestamp,
                    event_type,
                    details,
                    actor,
                    prev_hash,
                    stored_hash,
                )
            )
            or prev_hash != expected_previous
        ):
            return False
        calculated_hash = _entry_hash(
            entry_id, timestamp, event_type, details, actor, prev_hash
        )
        if not isinstance(stored_hash, str) or stored_hash != calculated_hash:
            return False
        expected_previous = stored_hash
        expected_id += 1
    return True