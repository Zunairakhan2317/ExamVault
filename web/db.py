"""Database helpers for the ExamVault web layer.

Creates only the tables that no other module creates itself:
audit_entries/merkle_roots (audit/) and exams/exam_shares (crypto/services/paper_service.py)
are NOT created here. login_attempts is created through auth.lockout.ensure_schema.
All SQL is static or parameterised.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from flask import current_app, g

from auth import lockout

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    full_name TEXT,
    email TEXT,
    role TEXT NOT NULL CHECK (role IN ('admin', 'examiner', 'invigilator', 'auditor')),
    password_hash TEXT NOT NULL,
    totp_secret_encrypted BLOB,
    totp_last_step INTEGER,
    last_login_at TEXT,
    schnorr_public_y TEXT,
    cert_serial TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS share_submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    exam_id TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id),
    share_index INTEGER NOT NULL,
    submitted_at TEXT NOT NULL,
    proof_nonce TEXT,
    accepted INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS copies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    exam_id TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id),
    slot_pattern TEXT NOT NULL,
    file_path TEXT
);

CREATE TABLE IF NOT EXISTS tardos_params (
    exam_id TEXT PRIMARY KEY,
    bias_vector_encrypted BLOB NOT NULL,
    slot_count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS used_nonces (
    nonce TEXT PRIMARY KEY,
    used_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS honeytoken_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    user_id INTEGER,
    ip TEXT,
    file_id TEXT
);

CREATE TABLE IF NOT EXISTS certificates (
    serial TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    pem TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    exam_id TEXT NOT NULL,
    holder_user_id INTEGER NOT NULL REFERENCES users(id),
    wrapped_share_blob BLOB NOT NULL,
    share_index INTEGER NOT NULL,
    feldman_commitments_json TEXT NOT NULL,
    generation INTEGER NOT NULL DEFAULT 1,
    is_current INTEGER NOT NULL DEFAULT 1,
    UNIQUE (exam_id, holder_user_id, generation)
);

CREATE TABLE IF NOT EXISTS exam_release (
    exam_id TEXT PRIMARY KEY,
    released_at TEXT NOT NULL,
    paper_sha256 TEXT NOT NULL
);
"""


def get_connection(path: str) -> sqlite3.Connection:
    """Open a SQLite connection with dict-like rows and foreign keys enforced."""
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _migrate_users_table(conn: sqlite3.Connection) -> None:
    """Add any missing columns to the existing users table.

    CREATE TABLE IF NOT EXISTS does not add new columns to an already-existing
    table, so we inspect the current schema and ALTER TABLE for each column that
    the SCHEMA defines but the database does not yet have.  This is safe to run
    many times and never drops or rewrites existing data.
    """
    expected_columns = {
        "id",
        "username",
        "full_name",
        "email",
        "role",
        "password_hash",
        "totp_secret_encrypted",
        "totp_last_step",
        "last_login_at",
        "schnorr_public_y",
        "cert_serial",
        "is_active",
        "created_at",
    }

    # Get existing column names (SQLite >= 3.9.0)
    cursor = conn.execute("PRAGMA table_info(users)")
    existing = {row[1] for row in cursor.fetchall()}

    for col in expected_columns:
        if col not in existing:
            conn.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT")

    conn.commit()


def init_db(conn: sqlite3.Connection) -> None:
    """Create the web-layer tables and the lockout table. Safe to run many times."""
    conn.executescript(SCHEMA)
    _migrate_users_table(conn)
    lockout.ensure_schema(conn)
    conn.commit()


def get_db() -> sqlite3.Connection:
    """Return the per-request connection (closed automatically at the end of the request)."""
    if "db" not in g:
        g.db = get_connection(current_app.config["DATABASE_PATH"])
    return g.db


def close_db(_exc: BaseException | None = None) -> None:
    """Close the per-request connection."""
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()