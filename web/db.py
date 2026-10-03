"""Database helpers for the ExamVault web layer.

Creates only the tables that no other module creates itself:
audit_entries/merkle_roots (audit/), exams/shares (crypto/services/paper_service.py)
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
"""


def get_connection(path: str) -> sqlite3.Connection:
    """Open a SQLite connection with dict-like rows and foreign keys enforced."""
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Create the web-layer tables and the lockout table. Safe to run many times."""
    conn.executescript(SCHEMA)
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