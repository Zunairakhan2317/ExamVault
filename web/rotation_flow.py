"""Share rotation ceremony (plan 3.7): admin opens it, k current holders approve, the server rotates.

Flow:
1. The admin opens a ceremony for one unreleased exam (usually after revoking a holder). The new holder set is
   the remaining usable holders plus any extra invigilators the admin adds, with a new threshold.
2. Each current, non-revoked holder logs in and approves by uploading their own private key. The key only
   unwraps their own share; the share point is kept in server MEMORY (the key itself is dropped at once).
3. When k distinct holders have approved, the server rebuilds the old paper key in memory, re-keys the paper,
   issues new wrapped shares and retires the old ones (crypto.services.rotation_service).

Security rules:
- A revoked, disabled or certificate-less holder can never approve (certificate + CRL check), so a leaver's old
  share cannot take part in a rotation.
- Nothing secret is stored in the database or the audit log. A restart forgets an open ceremony (holders
  simply approve again), the same limitation as the share submission store.
- Every start, approval, refusal, cancellation, failure and completion is written to the audit chain.
"""
from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from crypto import pki
from crypto.services import rotation_service
from web import exam_store, share_flow
from web.audit_log import log_event

SIGNING_KEY_NAME = "examiner_signing.pem"  # same demo key file the examiner upload page signs with
CEREMONY_TTL_SECONDS = 30 * 60  # an open ceremony expires (and forgets its in-memory shares) after 30 minutes

RotationRefused = share_flow.ShareRefused  # same (reason, message) shape: reason -> audit log, message -> user


@dataclass
class Ceremony:
    """One open rotation ceremony. `approvals` maps holder user id -> that holder's share point (memory only)."""

    exam_id: str
    started_by: str
    expires_at: float
    quorum: int
    new_threshold: int
    new_holder_ids: list[int]
    approvals: dict[int, tuple[int, int]] = field(default_factory=dict)


class RotationCeremonies:
    """Thread-safe in-memory registry of open ceremonies (one per exam)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: dict[str, Ceremony] = {}

    def _purge(self, now: float) -> None:
        for exam_id in [e for e, c in self._items.items() if c.expires_at <= now]:
            del self._items[exam_id]

    def start(self, ceremony: Ceremony, now: float | None = None) -> None:
        with self._lock:
            self._purge(time.time() if now is None else now)
            self._items[ceremony.exam_id] = ceremony

    def get(self, exam_id: str, now: float | None = None) -> Ceremony | None:
        with self._lock:
            self._purge(time.time() if now is None else now)
            return self._items.get(exam_id)

    def cancel(self, exam_id: str) -> bool:
        """Drop the ceremony (and every share point held for it). True if one was open."""
        with self._lock:
            return self._items.pop(exam_id, None) is not None

    def add_approval(self, exam_id: str, user_id: int, point: tuple[int, int]) -> int:
        """Record one holder's share point and return how many holders have approved."""
        with self._lock:
            ceremony = self._items.get(exam_id)
            if ceremony is None:
                raise RotationRefused("no_ceremony", "No rotation ceremony is open for this exam.")
            ceremony.approvals[int(user_id)] = point
            return len(ceremony.approvals)


def load_examiner_signing_key(keys_dir: Path) -> ed25519.Ed25519PrivateKey:
    """Read the examiner's Ed25519 signing key for this request only (the paper signature must be renewed).

    Honest limitation for the report: in this demo the server holds that key; in production the examiner
    would re-sign the new record on their own device.
    """
    key = serialization.load_pem_private_key((Path(keys_dir) / SIGNING_KEY_NAME).read_bytes(), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("Key must be an Ed25519 private key")
    return key


def get_ceremonies(app: Any) -> RotationCeremonies:
    """The app-wide registry (created on first use, so route modules can be registered in any order)."""
    return app.extensions.setdefault("examvault_rotation", RotationCeremonies())


def _usable(conn: sqlite3.Connection, user_id: int, is_active: Any) -> bool:
    """A holder can take part only if the account is active AND the certificate/CRL check passes."""
    return bool(is_active) and pki.user_certificate_ok(conn, int(user_id))


def holder_status(conn: sqlite3.Connection, exam_id: str) -> list[dict[str, Any]]:
    """Current holders of an exam with whether each may still take part (active account, valid certificate)."""
    rows = conn.execute(
        "SELECT u.id AS user_id, u.username AS username, u.is_active AS is_active, sh.generation AS generation "
        "FROM shares sh JOIN users u ON u.id = sh.holder_user_id "
        "WHERE sh.exam_id = ? AND sh.is_current = 1 ORDER BY u.username",
        (exam_id,),
    ).fetchall()
    return [
        {
            "user_id": int(r["user_id"]),
            "username": r["username"],
            "generation": int(r["generation"]),
            "usable": _usable(conn, r["user_id"], r["is_active"]),
        }
        for r in rows
    ]


def extra_holder_candidates(conn: sqlite3.Connection, exam_id: str, keys_dir: Path) -> list[dict[str, Any]]:
    """Active invigilators who are not holders yet, have a valid certificate and a public key file."""
    rows = conn.execute(
        "SELECT id, username, is_active FROM users WHERE role = 'invigilator' AND is_active = 1 "
        "AND id NOT IN (SELECT holder_user_id FROM shares WHERE exam_id = ? AND is_current = 1) ORDER BY username",
        (exam_id,),
    ).fetchall()
    return [
        {"user_id": int(r["id"]), "username": r["username"]}
        for r in rows
        if (Path(keys_dir) / f"{r['username']}_public.pem").is_file() and _usable(conn, r["id"], r["is_active"])
    ]


def admin_overview(conn: sqlite3.Connection, ceremonies: RotationCeremonies, keys_dir: Path) -> list[dict[str, Any]]:
    """One row per UNRELEASED exam for the admin page (a released paper cannot be protected by rotation)."""
    rows: list[dict[str, Any]] = []
    for exam in exam_store._all_exam_rows():
        exam_id = exam["exam_id"]
        if exam_store.is_released(conn, exam_id):
            continue
        holders = holder_status(conn, exam_id)
        if not holders:
            continue  # not created through the web app: no web shares to rotate
        ceremony = ceremonies.get(exam_id)
        usable = [h for h in holders if h["usable"]]
        approved_names = []
        if ceremony is not None:
            names = {h["user_id"]: h["username"] for h in holders}
            approved_names = sorted(names.get(uid, str(uid)) for uid in ceremony.approvals)
        rows.append(
            {
                "exam_id": exam_id,
                "title": exam.get("exam_title") or "",
                "threshold": int(exam["threshold"]),
                "generation": max(h["generation"] for h in holders),
                "holders": holders,
                "usable_count": len(usable),
                "needs_rotation": len(usable) < len(holders),
                "can_start": len(usable) >= int(exam["threshold"]),
                "default_threshold": min(int(exam["threshold"]), len(usable)),
                "extras": extra_holder_candidates(conn, exam_id, keys_dir),
                "ceremony": ceremony,
                "approved_names": approved_names,
                "minutes_left": max(0, int((ceremony.expires_at - time.time()) // 60)) if ceremony else 0,
            }
        )
    return rows


def start_ceremony(
    conn: sqlite3.Connection,
    ceremonies: RotationCeremonies,
    *,
    exam_id: str,
    admin_username: str,
    keys_dir: Path,
    extra_holder_ids: list[int],
    new_threshold: int | None,
) -> Ceremony:
    """Open a ceremony. Refuses when the quorum could never be reached or the parameters are wrong."""
    exam = exam_store.get_exam(exam_id)
    if exam is None:
        raise RotationRefused("unknown_exam", "Unknown exam.")
    if exam_store.is_released(conn, exam_id):
        raise RotationRefused("already_released", "The paper was already released; rotation cannot protect it now.")
    holders = holder_status(conn, exam_id)
    quorum = int(exam["threshold"])
    usable_ids = [h["user_id"] for h in holders if h["usable"]]
    if len(usable_ids) < quorum:
        raise RotationRefused(
            "quorum_impossible",
            f"Only {len(usable_ids)} usable holders remain but {quorum} must approve. Rotation cannot start.",
        )
    allowed_extras = {c["user_id"] for c in extra_holder_candidates(conn, exam_id, keys_dir)}
    extras = sorted({int(i) for i in extra_holder_ids})
    if not set(extras) <= allowed_extras:
        raise RotationRefused("bad_extra_holder", "An added holder is not eligible (inactive, no key file or revoked).")
    new_ids = sorted(set(usable_ids) | set(extras))
    threshold = min(quorum, len(new_ids)) if new_threshold is None else new_threshold
    if not 2 <= threshold <= len(new_ids):
        raise RotationRefused("bad_threshold", f"The new threshold must be between 2 and {len(new_ids)}.")
    if ceremonies.get(exam_id) is not None:
        raise RotationRefused("already_open", "A ceremony is already open for this exam. Cancel it first.")
    ceremony = Ceremony(
        exam_id=exam_id,
        started_by=admin_username,
        expires_at=time.time() + CEREMONY_TTL_SECONDS,
        quorum=quorum,
        new_threshold=threshold,
        new_holder_ids=new_ids,
    )
    ceremonies.start(ceremony)
    log_event(
        conn, admin_username, "rotation_ceremony_started",
        {"exam_id": exam_id, "needed": quorum, "new_threshold": threshold, "new_holders": len(new_ids)},
    )
    return ceremony


def cancel_ceremony(conn: sqlite3.Connection, ceremonies: RotationCeremonies, exam_id: str, admin_username: str) -> bool:
    """Close a ceremony and drop every share point held for it."""
    cancelled = ceremonies.cancel(exam_id)
    if cancelled:
        log_event(conn, admin_username, "rotation_ceremony_cancelled", {"exam_id": exam_id})
    return cancelled


def approve(
    conn: sqlite3.Connection,
    ceremonies: RotationCeremonies,
    pending: Any,
    *,
    exam_id: str,
    user_id: int,
    username: str,
    key_pem: bytes,
    keys_dir: Path,
    load_signing_key: Callable[[], ed25519.Ed25519PrivateKey],
) -> dict[str, Any]:
    """One holder approves the rotation with their private key. Rotates when k holders have approved."""
    ceremony = ceremonies.get(exam_id)
    if ceremony is None:
        raise RotationRefused("no_ceremony", "No rotation ceremony is open for this exam.")
    row = exam_store.get_share_row(conn, exam_id, user_id)
    if row is None:
        raise RotationRefused("not_a_holder", "You do not hold a share of this exam.")
    account = conn.execute("SELECT is_active FROM users WHERE id = ?", (int(user_id),)).fetchone()
    if account is None or not _usable(conn, user_id, account["is_active"]):
        raise RotationRefused("revoked_certificate", "Your certificate has been revoked. Approval refused.")
    already = int(user_id) in ceremony.approvals
    if already and len(ceremony.approvals) < ceremony.quorum:
        raise RotationRefused("already_approved", "You have already approved this rotation.")
    # (once the quorum is complete a holder may approve again to retry a rotation that failed, e.g. a missing
    # signing key; the key must still unwrap their own share)
    x, y = share_flow.validate_share(row, share_flow.load_private_key(key_pem))  # the key is dropped right after
    if already:
        received = len(ceremony.approvals)
    else:
        received = ceremonies.add_approval(exam_id, user_id, (x, y))
        log_event(conn, username, "rotation_approved", {"exam_id": exam_id, "received": received, "needed": ceremony.quorum})
    if received < ceremony.quorum:
        return {"outcome": "approved", "received": received, "needed": ceremony.quorum}
    return _execute(conn, ceremonies, pending, ceremony, username, keys_dir, load_signing_key)


def _execute(
    conn: sqlite3.Connection,
    ceremonies: RotationCeremonies,
    pending: Any,
    ceremony: Ceremony,
    username: str,
    keys_dir: Path,
    load_signing_key: Callable[[], ed25519.Ed25519PrivateKey],
) -> dict[str, Any]:
    """Quorum reached: re-check the new holders, rotate, then forget every in-memory share."""
    exam_id = ceremony.exam_id
    public_keys: list[rsa.RSAPublicKey] = []
    for holder_id in ceremony.new_holder_ids:
        user = conn.execute("SELECT username, is_active FROM users WHERE id = ?", (holder_id,)).fetchone()
        if user is None or not _usable(conn, holder_id, user["is_active"]):
            log_event(conn, username, "rotation_failed", {"exam_id": exam_id, "reason": "holder_changed"})
            raise RotationRefused("holder_changed", "A new holder was revoked during the ceremony. Cancel it and start again.")
        try:
            key = serialization.load_pem_public_key((Path(keys_dir) / f"{user['username']}_public.pem").read_bytes())
        except (OSError, ValueError):
            log_event(conn, username, "rotation_failed", {"exam_id": exam_id, "reason": "missing_holder_key"})
            raise RotationRefused("missing_holder_key", f"Missing or bad public key for {user['username']}; ask an admin.")
        if not isinstance(key, rsa.RSAPublicKey):
            raise RotationRefused("missing_holder_key", f"Missing or bad public key for {user['username']}; ask an admin.")
        public_keys.append(key)
    try:
        signing_key = load_signing_key()
    except (OSError, ValueError):
        log_event(conn, username, "rotation_failed", {"exam_id": exam_id, "reason": "signing_key_unavailable"})
        raise RotationRefused("signing_key_unavailable", "The examiner signing key is missing or invalid. Nothing was changed.")
    try:
        result = rotation_service.rotate_exam_with_quorum(
            conn, exam_id, list(ceremony.approvals.values()), ceremony.new_holder_ids, public_keys,
            ceremony.new_threshold, signing_key,
        )
    except (ValueError, TypeError) as exc:
        log_event(conn, username, "rotation_failed", {"exam_id": exam_id, "reason": "service_refused"})
        raise RotationRefused("rotation_failed", f"Rotation failed, nothing was changed: {exc}") from exc
    ceremonies.cancel(exam_id)  # drops the in-memory share points
    if pending is not None:
        pending.clear(exam_id)  # submissions made with the old shares are void
    log_event(
        conn, username, "rotation_completed",
        {"exam_id": exam_id, "generation": result["generation"], "holders": result["holders"], "threshold": result["threshold"]},
    )
    return {"outcome": "rotated", **result}
