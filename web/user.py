"""Flask-Login user object for ExamVault."""
from __future__ import annotations

import sqlite3

from flask_login import UserMixin


class User(UserMixin):
    """A logged-in staff member. Only active accounts are ever loaded."""

    def __init__(self, row: sqlite3.Row) -> None:
        self.id = int(row["id"])
        self.username = row["username"]
        self.role = row["role"]
        self.full_name = row["full_name"] or row["username"]


def load_user_by_id(conn: sqlite3.Connection, user_id: object) -> User | None:
    """Load an ACTIVE user by id; disabled or revoked accounts lose access immediately."""
    try:
        uid = int(user_id)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    row = conn.execute(
        "SELECT id, username, full_name, role, is_active FROM users WHERE id = ?", (uid,)
    ).fetchone()
    if row is None or not row["is_active"]:
        return None
    return User(row)