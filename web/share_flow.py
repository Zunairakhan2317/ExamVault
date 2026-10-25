"""Share submission and paper release (plan 4.6).

Flow for one invigilator: one-time nonce -> exam window check -> own wrapped share is looked up
on the server -> the uploaded RSA private key unwraps it -> Feldman verification -> the share is
held in server MEMORY only -> when the threshold of distinct valid shares is reached the paper is
released through crypto.services.paper_service.release_exam (which re-verifies every share,
decrypts, and checks the examiner signature and the signed release window).

Security rules:
- The uploaded private key is never written to disk or to the database. It is kept in process memory
  only until the paper is released or the exam window ends, and then dropped (known limitation:
  a restart forgets pending submissions, holders simply submit again).
- A holder can only unwrap the share assigned to their own account, so a stolen blob is useless.
- Every nonce can be used once (table used_nonces); replays are refused.
- Every refusal and every release is written to the audit chain. Shares, keys and paper content
  are never logged (only the paper SHA-256).
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from collections.abc import Callable, Sequence
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from auth import timewindow
from crypto import feldman, keywrap, pki
from crypto.services import paper_service
from web import exam_store
from web.audit_log import log_event

MAX_KEY_FILE_BYTES = 20000


class ShareRefused(Exception):
    """A submission was refused. `reason` goes to the audit log, `message` to the user."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


class PendingShares:
    """In-memory holder of verified submissions (wrapped blob + holder key) until release.

    Security purpose: keys and shares never touch the disk; entries vanish when the exam window ends.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: dict[str, dict[int, tuple[bytes, Any, float]]] = {}

    def _purge(self, now: float) -> None:
        for exam_id in list(self._items):
            holders = self._items[exam_id]
            for user_id in [u for u, (_b, _k, expires) in holders.items() if expires <= now]:
                del holders[user_id]
            if not holders:
                del self._items[exam_id]

    def add(self, exam_id: str, user_id: int, blob: bytes, key: Any, expires_at: float) -> None:
        """Remember one verified submission."""
        with self._lock:
            self._purge(time.time())
            self._items.setdefault(exam_id, {})[int(user_id)] = (blob, key, float(expires_at))

    def has(self, exam_id: str, user_id: int) -> bool:
        """True if this user already has a verified submission for the exam."""
        with self._lock:
            self._purge(time.time())
            return int(user_id) in self._items.get(exam_id, {})

    def count(self, exam_id: str) -> int:
        """Number of distinct verified submissions for the exam."""
        with self._lock:
            self._purge(time.time())
            return len(self._items.get(exam_id, {}))

    def snapshot(self, exam_id: str) -> list[tuple[int, bytes, Any]]:
        """All submissions as (user_id, wrapped blob, private key), ordered by user id."""
        with self._lock:
            self._purge(time.time())
            holders = self._items.get(exam_id, {})
            return [(uid, holders[uid][0], holders[uid][1]) for uid in sorted(holders)]

    def clear(self, exam_id: str) -> None:
        """Drop every pending submission (and with it the keys) for the exam."""
        with self._lock:
            self._items.pop(exam_id, None)


def load_private_key(pem: bytes) -> rsa.RSAPrivateKey:
    """Parse an uploaded unencrypted RSA private key PEM; anything else is refused."""
    if not pem or len(pem) > MAX_KEY_FILE_BYTES:
        raise ShareRefused("invalid_key_file", "Invalid key file")
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except Exception as exc:
        raise ShareRefused("invalid_key_file", "Invalid key file") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ShareRefused("invalid_key_file", "Invalid key file")
    return key


def validate_share(row: sqlite3.Row, private_key: rsa.RSAPrivateKey) -> tuple[int, int]:
    """Unwrap the holder's own share and check it against the Feldman commitments.

    Security purpose: a wrong key, a damaged blob or a forged share is rejected before it is counted.
    """
    try:
        share_bytes = keywrap.unwrap_share(bytes(row["wrapped_share_blob"]), private_key)
        x, y = paper_service._decode_share(share_bytes)
        commitments = [int(value) for value in json.loads(row["feldman_commitments_json"])]
    except Exception as exc:
        raise ShareRefused("share_invalid", "Share invalid, contact admin") from exc
    if not feldman.verify_share(x, y, commitments):
        raise ShareRefused("share_invalid", "Share invalid, contact admin")
    return x, y


def consume_nonce(conn: sqlite3.Connection, nonce: str, used_at: str) -> None:
    """Burn a one-time nonce; a second use is refused (replay protection)."""
    if not isinstance(nonce, str) or not nonce or len(nonce) > 200:
        raise ShareRefused("nonce_mismatch", "Request expired. Please try again.")
    try:
        with conn:
            conn.execute("INSERT INTO used_nonces (nonce, used_at) VALUES (?, ?)", (nonce, used_at))
    except sqlite3.IntegrityError as exc:
        raise ShareRefused("nonce_reuse", "This request was already used. Reload the page.") from exc


def submit_share(
    conn: sqlite3.Connection,
    pending: PendingShares,
    *,
    exam_id: str,
    user_id: int,
    username: str,
    key_pem: bytes,
    nonce: str,
    load_admin_public_key: Callable[[], Ed25519PublicKey],
    release_handlers: Sequence[Callable[[str, bytes], None]] = (),
    now: Any = None,
) -> dict[str, Any]:
    """Process one holder's submission. Raises ShareRefused (and audits it) when refused.

    Returns {"outcome": "accepted" | "released" | "release_failed", "received": n, "needed": k}.
    """
    now_dt = timewindow.parse_utc(now) if now is not None else timewindow.utc_now()
    try:
        return _submit(
            conn, pending, exam_id, user_id, username, key_pem, nonce,
            load_admin_public_key, release_handlers, now_dt,
        )
    except ShareRefused as refusal:
        log_event(
            conn, username, "share_refused",
            {"exam_id": str(exam_id)[:100], "reason": refusal.reason},
        )
        raise


def _submit(
    conn: sqlite3.Connection,
    pending: PendingShares,
    exam_id: str,
    user_id: int,
    username: str,
    key_pem: bytes,
    nonce: str,
    load_admin_public_key: Callable[[], Ed25519PublicKey],
    release_handlers: Sequence[Callable[[str, bytes], None]],
    now_dt: Any,
) -> dict[str, Any]:
    # Plan 6.6: certificate + CRL check (a revoked, expired or forged certificate is refused)
    if not pki.user_certificate_ok(conn, user_id):
        raise ShareRefused("revoked_certificate", "Your certificate has been revoked. Submission refused.")

    consume_nonce(conn, nonce, now_dt.isoformat())
    exam = exam_store.get_exam(exam_id)
    if exam is None:
        raise ShareRefused("unknown_exam", "Exam not found")
    row = exam_store.get_share_row(conn, exam_id, user_id)
    if row is None:
        raise ShareRefused("not_holder", "You are not a key holder for this exam")
    if exam_store.is_released(conn, exam_id):
        raise ShareRefused("already_released", "Paper already released")
    try:
        timewindow.require_open(exam, now_dt)
    except timewindow.WindowError as exc:
        if exc.status == timewindow.WindowStatus.BEFORE:
            raise ShareRefused("window_before", "Window not open yet") from exc
        raise ShareRefused("window_closed", "Window closed, submission refused") from exc
    if pending.has(exam_id, user_id):
        raise ShareRefused("already_submitted", "Share already submitted")
    private_key = load_private_key(key_pem)
    validate_share(row, private_key)
    expires_at = timewindow.window_bounds(exam)[1].timestamp()
    pending.add(exam_id, user_id, bytes(row["wrapped_share_blob"]), private_key, expires_at)
    with conn:
        conn.execute(
            "INSERT INTO share_submissions (exam_id, user_id, share_index, submitted_at, proof_nonce, accepted) "
            "VALUES (?, ?, ?, ?, ?, 1)",
            (exam_id, int(user_id), int(row["share_index"]), now_dt.isoformat(), nonce),
        )
    received = pending.count(exam_id)
    needed = int(exam["threshold"])
    log_event(conn, username, "share_accepted", {"exam_id": exam_id, "received": received, "needed": needed})
    if received < needed:
        return {"outcome": "accepted", "received": received, "needed": needed}
    return _try_release(
        conn, pending, username, exam_id, received, needed,
        load_admin_public_key, release_handlers, now_dt,
    )


def _try_release(
    conn: sqlite3.Connection,
    pending: PendingShares,
    username: str,
    exam_id: str,
    received: int,
    needed: int,
    load_admin_public_key: Callable[[], Ed25519PublicKey],
    release_handlers: Sequence[Callable[[str, bytes], None]],
    now_dt: Any,
) -> dict[str, Any]:
    """Threshold reached: let the paper service verify everything and decrypt in memory."""
    entries = pending.snapshot(exam_id)
    try:
        public_key = load_admin_public_key()
        plaintext = paper_service.release_exam(
            exam_id, [blob for _uid, blob, _key in entries], [key for _uid, _blob, key in entries], public_key
        )
    except Exception as exc:
        log_event(conn, username, "release_failed", {"exam_id": exam_id, "error_type": type(exc).__name__})
        return {"outcome": "release_failed", "received": received, "needed": needed}
    digest = hashlib.sha256(plaintext).hexdigest()
    exam_store.mark_released(conn, exam_id, digest, now_dt.isoformat())
    pending.clear(exam_id)
    log_event(conn, username, "paper_released", {"exam_id": exam_id, "paper_sha256": digest, "used": len(entries)})
    for handler in release_handlers:
        try:
            handler(exam_id, plaintext)
        except Exception:
            log_event(conn, username, "release_handler_failed", {"exam_id": exam_id})
    return {"outcome": "released", "received": received, "needed": needed}