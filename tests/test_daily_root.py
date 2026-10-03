"""Tests for signed daily audit Merkle roots."""

import hashlib
import json
import sqlite3
from datetime import date

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit.daily_root import (
    compute_daily_root,
    configure_audit_signing_keys,
    verify_daily_root,
)
from audit.hashchain import add_audit_entry


@pytest.fixture
def signing_keys() -> tuple[Ed25519PrivateKey, Ed25519PrivateKey]:
    """Configure a fresh Ed25519 audit signing keypair for each test."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    configure_audit_signing_keys(private_key, public_key)
    return private_key, public_key


@pytest.fixture
def audit_database() -> sqlite3.Connection:
    """Create an in-memory database with two append-only audit entries."""
    database = sqlite3.connect(":memory:")
    add_audit_entry(database, "login", "accepted", "admin-1")
    add_audit_entry(database, "share_submit", "accepted", "holder-2")
    return database


def test_daily_root_computes_and_stores_signed_merkle_root(
    audit_database: sqlite3.Connection,
    signing_keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey],
) -> None:
    """Daily root contains the expected date/count and a valid signed root."""
    private_key, public_key = signing_keys
    target_date = date.today().isoformat()

    daily_root = compute_daily_root(audit_database, target_date)
    stored = audit_database.execute(
        """SELECT merkle_root, entry_count, signature, signed_at
           FROM merkle_roots WHERE target_date = ?""",
        (target_date,),
    ).fetchone()

    assert daily_root["target_date"] == target_date
    assert daily_root["entry_count"] == 2
    assert stored is not None
    assert stored[0] == daily_root["merkle_root"]
    assert stored[1] == 2
    payload = b"ExamVault daily audit root v1\x00" + json.dumps(
        {
            "entry_count": stored[1],
            "merkle_root": stored[0],
            "target_date": target_date,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    public_key.verify(bytes(stored[2]), payload)
    assert private_key.public_key() == public_key
    assert verify_daily_root(audit_database, target_date)


def test_tampering_with_audit_entry_invalidates_daily_root(
    audit_database: sqlite3.Connection,
    signing_keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey],
) -> None:
    """Changing a row after bypassing its trigger is detected during verification."""
    target_date = date.today().isoformat()
    compute_daily_root(audit_database, target_date)

    audit_database.execute("DROP TRIGGER audit_entries_no_update")
    audit_database.execute(
        "UPDATE audit_entries SET details = 'tampered' WHERE id = 1"
    )

    assert not verify_daily_root(audit_database, target_date)


def test_daily_root_rejects_changed_root_signature(
    audit_database: sqlite3.Connection,
    signing_keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey],
) -> None:
    """A signature cannot be reused for a different daily Merkle root."""
    target_date = date.today().isoformat()
    daily_root = compute_daily_root(audit_database, target_date)
    _, public_key = signing_keys
    forged_root = hashlib.sha256(b"forged-root").hexdigest()
    payload = b"ExamVault daily audit root v1\x00" + json.dumps(
        {
            "entry_count": daily_root["entry_count"],
            "merkle_root": forged_root,
            "target_date": target_date,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")

    with pytest.raises(InvalidSignature):
        public_key.verify(daily_root["signature"], payload)
    assert verify_daily_root(audit_database, target_date)


@pytest.mark.parametrize(
    ("column", "tampered_value"),
    [
        ("merkle_root", "f" * 64),
        ("signature", b"not-a-valid-ed25519-signature"),
    ],
)
def test_daily_root_verification_fails_when_stored_root_or_signature_is_tampered(
    audit_database: sqlite3.Connection,
    signing_keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey],
    column: str,
    tampered_value: str | bytes,
) -> None:
    """Changed root or signature bytes invalidate daily-root verification."""
    target_date = date.today().isoformat()
    compute_daily_root(audit_database, target_date)
    audit_database.execute("DROP TRIGGER merkle_roots_no_update")
    audit_database.execute(
        f"UPDATE merkle_roots SET {column} = ? WHERE target_date = ?",
        (tampered_value, target_date),
    )

    assert not verify_daily_root(audit_database, target_date)


def test_daily_root_is_immutable_and_cannot_be_recomputed(
    audit_database: sqlite3.Connection,
    signing_keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey],
) -> None:
    """A date can be sealed once and its stored root cannot be edited or removed."""
    target_date = date.today().isoformat()
    compute_daily_root(audit_database, target_date)

    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        audit_database.execute(
            "UPDATE merkle_roots SET entry_count = 99 WHERE target_date = ?",
            (target_date,),
        )
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        audit_database.execute(
            "DELETE FROM merkle_roots WHERE target_date = ?", (target_date,)
        )
    with pytest.raises(ValueError, match="already exists"):
        compute_daily_root(audit_database, target_date)