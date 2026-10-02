"""Tests for hybrid share encryption and database BLOB storage."""

import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from crypto.keywrap import unwrap_share, wrap_share


@pytest.fixture(scope="module")
def holder_private_key() -> rsa.RSAPrivateKey:
    """Create an RSA-3072 holder key pair for share-wrapping tests."""
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def test_share_round_trip_through_database_blob(
    holder_private_key: rsa.RSAPrivateKey,
) -> None:
    """A wrapped share survives SQLite BLOB storage and retrieval unchanged."""
    share = b"exam-2026-001: share index 3, value 987654321"
    blob = wrap_share(share, holder_private_key.public_key())

    with sqlite3.connect(":memory:") as database:
        database.execute(
            "CREATE TABLE wrapped_shares (share_id TEXT PRIMARY KEY, blob BLOB NOT NULL)"
        )
        database.execute(
            "INSERT INTO wrapped_shares (share_id, blob) VALUES (?, ?)",
            ("holder-3", blob),
        )
        stored_blob = database.execute(
            "SELECT blob FROM wrapped_shares WHERE share_id = ?", ("holder-3",)
        ).fetchone()[0]

    assert isinstance(stored_blob, bytes)
    assert stored_blob != share
    assert unwrap_share(stored_blob, holder_private_key) == share


def test_wrong_private_key_fails_to_unwrap(
    holder_private_key: rsa.RSAPrivateKey,
) -> None:
    """A share encrypted for one holder cannot be unwrapped by another."""
    wrong_private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    blob = wrap_share(b"confidential share", holder_private_key.public_key())

    with pytest.raises(ValueError):
        unwrap_share(blob, wrong_private_key)