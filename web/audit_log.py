"""Single place where the web layer writes to the audit chain.

It calls audit.hashchain.add_audit_entry and maps our (actor, action, details) onto that
function's real parameter names, so the web layer never guesses the signature.
Security rule: secret-looking keys are removed before anything is written.
"""
from __future__ import annotations

import inspect
import json
import sqlite3
from typing import Any

from audit.hashchain import add_audit_entry, verify_hashchain

_FORBIDDEN_KEY_PARTS = ("password", "secret", "share", "token", "otp", "code", "key", "private")
_HINTS = (
    ("action", ("event", "action")),
    ("details", ("detail", "outcome", "result", "message", "data")),
    ("actor", ("actor", "user", "holder", "subject")),
)


class AuditTamperedError(ValueError):
    """Raised when the audit chain is tampered or invalid, so routes can handle it gracefully.

    Inherits from ValueError so existing except ValueError handlers in routes still catch it.
    """
    pass


def _scrub(details: dict[str, Any] | None) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in (details or {}).items():
        if any(part in str(key).lower() for part in _FORBIDDEN_KEY_PARTS):
            continue
        clean[str(key)] = value
    return clean


def _parameter_map() -> dict[str, str]:
    params = list(inspect.signature(add_audit_entry).parameters.values())[1:]  # skip the connection
    mapping: dict[str, str] = {}
    for param in params:
        name = param.name.lower()
        for role, hints in _HINTS:
            if role not in mapping and any(h in name for h in hints):
                mapping[role] = param.name
                break
    return mapping


def log_event(
    conn: sqlite3.Connection, actor: str, action: str, details: dict[str, Any] | None = None
) -> None:
    """Append one event to the tamper-evident audit chain (secret-looking keys are dropped).

    Raises AuditTamperedError if the chain is corrupted, so callers can catch it
    and display a user-friendly banner instead of a 500 server error.
    """
    mapping = _parameter_map()
    if len(mapping) != 3:
        raise RuntimeError(
            "add_audit_entry signature not recognised: "
            f"{inspect.signature(add_audit_entry)}. Tell the assistant this exact line."
        )
    payload = json.dumps(_scrub(details), sort_keys=True, default=str)
    try:
        add_audit_entry(
            conn,
            **{mapping["action"]: action, mapping["details"]: payload, mapping["actor"]: str(actor)},
        )
    except ValueError as exc:
        if "existing audit chain is invalid" in str(exc):
            raise AuditTamperedError("Audit chain is tampered or invalid") from exc
        raise
    conn.commit()


def ensure_audit_intact(conn: sqlite3.Connection) -> None:
    """Fail closed before a sensitive action when the audit chain no longer verifies.

    Security property: an action that must be audited (for example creating an exam) never runs
    against a tampered log; the caller gets AuditTamperedError, which the web layer turns into a
    friendly banner (status 503). Only the hash chain is checked here (daily Merkle roots may
    simply not exist yet on a fresh system, which is not tampering).
    """
    try:
        has_table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'audit_entries'"
        ).fetchone()
    except sqlite3.Error as exc:
        raise AuditTamperedError("Audit log could not be read") from exc
    if has_table and not verify_hashchain(conn):
        raise AuditTamperedError("Audit chain is tampered or invalid")
