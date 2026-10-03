"""Compute, sign, and verify immutable daily audit Merkle roots."""

import hashlib
import json
import re
import sqlite3
from datetime import date, datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from audit.hashchain import verify_hashchain
from audit.merkle import build_merkle_tree, get_merkle_root

_DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_SIGNING_DOMAIN = b"ExamVault daily audit root v1\x00"
_audit_private_key: Ed25519PrivateKey | None = None
_audit_public_key: Ed25519PublicKey | None = None


def configure_audit_signing_keys(
    private_key: Ed25519PrivateKey,
    public_key: Ed25519PublicKey,
) -> None:
    """Configure the trusted Ed25519 audit signer for this application process."""
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be an Ed25519 private key")
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("public_key must be an Ed25519 public key")
    challenge = b"ExamVault audit signing-key pair check v1"
    try:
        public_key.verify(private_key.sign(challenge), challenge)
    except InvalidSignature as error:
        raise ValueError("audit signing keys do not form a key pair") from error

    global _audit_private_key, _audit_public_key
    _audit_private_key = private_key
    _audit_public_key = public_key


def configure_audit_verification_key(public_key: Ed25519PublicKey) -> None:
    """Configure only the trusted public key for standalone root verification."""
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("public_key must be an Ed25519 public key")
    global _audit_public_key
    _audit_public_key = public_key


def _validate_date(target_date: str) -> str:
    """Validate and return a canonical ISO-8601 calendar date."""
    if not isinstance(target_date, str) or _DATE_PATTERN.fullmatch(target_date) is None:
        raise ValueError("target_date must use YYYY-MM-DD format")
    try:
        parsed_date = date.fromisoformat(target_date)
    except ValueError as error:
        raise ValueError("target_date is not a valid calendar date") from error
    if parsed_date.isoformat() != target_date:
        raise ValueError("target_date must use canonical YYYY-MM-DD format")
    return target_date


def _ensure_schema(db_conn: sqlite3.Connection) -> None:
    """Create immutable storage for one signed Merkle root per calendar date."""
    db_conn.execute(
        """CREATE TABLE IF NOT EXISTS merkle_roots (
            target_date TEXT PRIMARY KEY,
            merkle_root TEXT NOT NULL,
            entry_count INTEGER NOT NULL CHECK (entry_count > 0),
            signature BLOB NOT NULL,
            signed_at TEXT NOT NULL
        )"""
    )
    db_conn.execute(
        """CREATE TRIGGER IF NOT EXISTS merkle_roots_no_update
           BEFORE UPDATE ON merkle_roots
           BEGIN
               SELECT RAISE(ABORT, 'daily Merkle roots are immutable');
           END"""
    )
    db_conn.execute(
        """CREATE TRIGGER IF NOT EXISTS merkle_roots_no_delete
           BEFORE DELETE ON merkle_roots
           BEGIN
               SELECT RAISE(ABORT, 'daily Merkle roots are immutable');
           END"""
    )


def _root_message(target_date: str, merkle_root: str, entry_count: int) -> bytes:
    """Serialize signed daily-root metadata in a canonical, domain-separated form."""
    payload = {
        "entry_count": entry_count,
        "merkle_root": merkle_root,
        "target_date": target_date,
    }
    return _SIGNING_DOMAIN + json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _get_day_leaves(db_conn: sqlite3.Connection, target_date: str) -> list[str]:
    """Fetch audit digests for one UTC date in their append order."""
    rows = db_conn.execute(
        """SELECT entry_hash FROM audit_entries
           WHERE substr(timestamp, 1, 10) = ? ORDER BY id ASC""",
        (target_date,),
    ).fetchall()
    return [str(row[0]) for row in rows]


def compute_daily_root(db_conn: sqlite3.Connection, target_date: str) -> dict[str, object]:
    """Build and sign the immutable Merkle root for one date's audit entries."""
    if not isinstance(db_conn, sqlite3.Connection):
        raise TypeError("db_conn must be an sqlite3.Connection")
    target_date = _validate_date(target_date)
    if _audit_private_key is None:
        raise RuntimeError("configure_audit_signing_keys must be called before computing roots")
    if not verify_hashchain(db_conn):
        raise ValueError("audit hash chain is invalid")

    leaves = _get_day_leaves(db_conn, target_date)
    if not leaves:
        raise ValueError("no audit entries exist for target_date")
    merkle_root = get_merkle_root(build_merkle_tree(leaves))
    entry_count = len(leaves)
    signature = _audit_private_key.sign(
        _root_message(target_date, merkle_root, entry_count)
    )
    signed_at = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )

    _ensure_schema(db_conn)
    try:
        db_conn.execute(
            """INSERT INTO merkle_roots
               (target_date, merkle_root, entry_count, signature, signed_at)
               VALUES (?, ?, ?, ?, ?)""",
            (target_date, merkle_root, entry_count, signature, signed_at),
        )
    except sqlite3.IntegrityError:
        raise ValueError("a daily root already exists for target_date") from None
    return {
        "target_date": target_date,
        "merkle_root": merkle_root,
        "entry_count": entry_count,
        "signature": signature,
        "signed_at": signed_at,
    }


def verify_daily_root(db_conn: sqlite3.Connection, target_date: str) -> bool:
    """Verify a stored daily-root signature and its match to the current audit entries."""
    if not isinstance(db_conn, sqlite3.Connection):
        raise TypeError("db_conn must be an sqlite3.Connection")
    try:
        target_date = _validate_date(target_date)
        if _audit_public_key is None or not verify_hashchain(db_conn):
            return False
        stored_root = db_conn.execute(
            """SELECT merkle_root, entry_count, signature
               FROM merkle_roots WHERE target_date = ?""",
            (target_date,),
        ).fetchone()
        if stored_root is None:
            return False
        leaves = _get_day_leaves(db_conn, target_date)
        if not leaves:
            return False
        merkle_root = get_merkle_root(build_merkle_tree(leaves))
        stored_hash, stored_count, signature = stored_root
        if stored_hash != merkle_root or stored_count != len(leaves):
            return False
        _audit_public_key.verify(
            bytes(signature),
            _root_message(target_date, merkle_root, len(leaves)),
        )
        return True
    except (InvalidSignature, TypeError, ValueError, sqlite3.Error):
        return False