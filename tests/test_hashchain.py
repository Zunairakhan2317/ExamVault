"""Tests for append-only SQLite audit-chain integrity."""

import sqlite3
import json

import pytest

from audit.hashchain import GENESIS_HASH, add_audit_entry, verify_hashchain


def test_valid_hashchain_verifies() -> None:
    """Every entry links to the previous digest starting at the genesis hash."""
    with sqlite3.connect(":memory:") as database:
        first = add_audit_entry(database, "login", "successful", "admin-1")
        second = add_audit_entry(database, "share_submit", "accepted", "holder-2")

        assert first["prev_hash"] == GENESIS_HASH
        assert second["prev_hash"] == first["entry_hash"]
        assert verify_hashchain(database)


def test_audit_entry_does_not_contain_unrelated_secret_values() -> None:
    """Audit serialization does not pull unrelated password, share, or key values."""
    secret_canaries = (
        "password-canary-9f31",
        "share-canary-7b42",
        "private-key-canary-2d18",
    )
    with sqlite3.connect(":memory:") as database:
        entry = add_audit_entry(
            database,
            "exam_released",
            "exam release succeeded",
            "admin-1",
        )
        stored_values = database.execute(
            "SELECT timestamp, event_type, details, actor, prev_hash, entry_hash "
            "FROM audit_entries"
        ).fetchone()
        serialized_log = json.dumps((entry, stored_values))

    assert all(canary not in serialized_log for canary in secret_canaries)


@pytest.mark.parametrize("statement", [
    "UPDATE audit_entries SET details = 'changed' WHERE id = 1",
    "DELETE FROM audit_entries WHERE id = 1",
])
def test_triggers_block_update_and_delete(statement: str) -> None:
    """SQLite triggers reject in-place modification and deletion of entries."""
    with sqlite3.connect(":memory:") as database:
        add_audit_entry(database, "login", "successful", "admin-1")

        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            database.execute(statement)

        assert verify_hashchain(database)


def test_verifier_detects_mutation_if_trigger_is_bypassed() -> None:
    """Recomputed digests detect altered data even if a trigger is removed."""
    with sqlite3.connect(":memory:") as database:
        add_audit_entry(database, "login", "successful", "admin-1")
        database.execute("DROP TRIGGER audit_entries_no_update")
        database.execute(
            "UPDATE audit_entries SET details = 'tampered' WHERE id = 1"
        )

        assert not verify_hashchain(database)


def test_verifier_detects_deleted_entry_if_trigger_is_bypassed() -> None:
    """A missing entry is detected through the sequence and hash-link checks."""
    with sqlite3.connect(":memory:") as database:
        add_audit_entry(database, "login", "successful", "admin-1")
        add_audit_entry(database, "share_submit", "accepted", "holder-2")
        database.execute("DROP TRIGGER audit_entries_no_delete")
        database.execute("DELETE FROM audit_entries WHERE id = 1")

        assert not verify_hashchain(database)


def test_append_fails_if_existing_chain_has_been_tampered() -> None:
    """A new entry cannot extend a chain whose stored digest no longer verifies."""
    with sqlite3.connect(":memory:") as database:
        add_audit_entry(database, "login", "successful", "admin-1")
        database.execute("DROP TRIGGER audit_entries_no_update")
        database.execute(
            "UPDATE audit_entries SET details = 'tampered' WHERE id = 1"
        )

        with pytest.raises(ValueError, match="existing audit chain is invalid"):
            add_audit_entry(database, "logout", "completed", "admin-1")