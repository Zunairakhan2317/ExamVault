"""Honeytoken (plan 7.2): a decoy file that real staff have no reason to open.

Every request for the decoy is meaningful, so each hit:
  1. adds a row to honeytoken_events (this is what the red alert banner, KPI card and bell count),
  2. writes a CRITICAL entry to the tamper-evident audit chain (action "honeytoken_access"),
  3. suspends the account, except admins (an admin who opens it only raises the alert, so a demo can never
     lock the admin out), and
  4. optionally sends an e-mail through smtplib when SMTP_USER and SMTP_APP_PASSWORD are set.
Nothing secret is stored or logged. The decoy contains harmless placeholder text only.
"""
from __future__ import annotations

import io
import os
import smtplib
import sqlite3
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any

from crypto import pki
from web.audit_log import log_event

DECOY_FILE_ID = "f_a91c7e"  # opaque id used in the URL
DECOY_FILENAME = "FINAL_Exam_Paper_ANSWERS.pdf"  # a name nobody with a real job needs to open
HONEYTOKEN_ACTION = "honeytoken_access"  # the Auditor page already treats this action as CRITICAL
NEVER_SUSPENDED_ROLES = ("admin",)


def decoy_pdf_bytes() -> bytes:
    """A small PDF with harmless placeholder text (no real exam data anywhere)."""
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    pdf.setTitle("Final Exam Paper Answers (placeholder)")
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(72, 780, "Final Exam Paper - Answers")
    pdf.setFont("Helvetica", 11)
    for number, line in enumerate(
        ("This file is a placeholder with no real exam content.", "Q1: (placeholder)", "Q2: (placeholder)", "Q3: (placeholder)"),
        start=1,
    ):
        pdf.drawString(72, 780 - 28 * number, line)
    pdf.save()
    return buffer.getvalue()


def send_email_alert(subject: str, body: str) -> bool:
    """Optional e-mail through Gmail SMTP with an app password. Never raises: an alert must not break a request."""
    user, password = os.getenv("SMTP_USER"), os.getenv("SMTP_APP_PASSWORD")
    if not user or not password:
        return False
    try:
        message = EmailMessage()
        message["Subject"], message["From"], message["To"] = subject, user, os.getenv("ALERT_EMAIL_TO") or user
        message.set_content(body)
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=5) as smtp:
            smtp.login(user, password)
            smtp.send_message(message)
        return True
    except (OSError, smtplib.SMTPException):
        return False


def record_hit(conn: sqlite3.Connection, user_id: int, username: str, role: str, ip: str | None) -> dict[str, Any]:
    """Register one access to the decoy. Returns {"event_id": int, "suspended": bool}.

    The event row is written first, so the alert exists even if a later step (audit chain, e-mail) fails.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cursor = conn.execute(
        "INSERT INTO honeytoken_events (ts, user_id, ip, file_id) VALUES (?, ?, ?, ?)",
        (now, int(user_id), (ip or "")[:64], DECOY_FILE_ID),
    )
    conn.commit()
    suspended = False
    if role not in NEVER_SUSPENDED_ROLES:
        conn.execute("UPDATE users SET is_active = 0 WHERE id = ? AND role NOT IN ('admin')", (int(user_id),))
        conn.commit()
        suspended = True
    log_event(
        conn, username[:64], HONEYTOKEN_ACTION,
        {"severity": "CRITICAL", "file_id": DECOY_FILE_ID, "ip": (ip or "")[:64], "role": role, "suspended": suspended},
    )
    send_email_alert(
        "ExamVault CRITICAL: decoy file opened",
        f"User {username} ({role}) opened the decoy file at {now} from {ip}. Account suspended: {suspended}.",
    )
    return {"event_id": int(cursor.lastrowid), "suspended": suspended}


def list_events(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """All honeytoken events, newest first, with the user's current account state."""
    rows = conn.execute(
        "SELECT e.id, e.ts, e.ip, e.file_id, e.user_id, u.username, u.role, u.is_active "
        "FROM honeytoken_events e LEFT JOIN users u ON u.id = e.user_id ORDER BY e.id DESC"
    ).fetchall()
    return [
        {
            "id": int(r["id"]), "ts": r["ts"], "ip": r["ip"] or "-", "file_id": r["file_id"],
            "user_id": r["user_id"], "username": r["username"] or "(deleted user)", "role": r["role"] or "-",
            "suspended": r["is_active"] is not None and not r["is_active"],
        }
        for r in rows
    ]


def reinstate(conn: sqlite3.Connection, event_id: int, actor: str) -> str:
    """Admin lifts a honeytoken suspension after review. Returns "ok", "unknown", "admin" or "revoked".

    A user whose certificate is revoked stays locked: a suspension review must not undo a revocation.
    """
    row = conn.execute(
        "SELECT e.user_id, u.username, u.role FROM honeytoken_events e LEFT JOIN users u ON u.id = e.user_id WHERE e.id = ?",
        (int(event_id),),
    ).fetchone()
    if row is None or row["username"] is None:
        return "unknown"
    if row["role"] in NEVER_SUSPENDED_ROLES:
        return "admin"
    conn.execute("UPDATE users SET is_active = 1 WHERE id = ?", (int(row["user_id"]),))
    conn.commit()
    if not pki.user_certificate_ok(conn, int(row["user_id"])):
        conn.execute("UPDATE users SET is_active = 0 WHERE id = ?", (int(row["user_id"]),))
        conn.commit()
        return "revoked"
    log_event(conn, actor, "honeytoken_reinstated", {"event_id": int(event_id), "user": row["username"]})
    return "ok"
