"""Exam and holder-share lookups for the share submission flow (plan 4.6).

Reads exam metadata from the paper service database (crypto/services/paper_service.py,
table `exams`) and keeps the holder-to-share mapping in the web database (plan Section 2,
table `shares`). Nothing here ever sees a decrypted share or a private key.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from auth import timewindow
from crypto.services import paper_service

STEPS = [
    (1, "Waiting for window"),
    (2, "Submit your key share"),
    (3, "Waiting for others"),
    (4, "Paper released"),
    (5, "Download your copy"),
]


def get_exam(exam_id: object) -> dict[str, Any] | None:
    """Return the public exam record (id, title, threshold, window, is_active) or None if it does not exist."""
    if not isinstance(exam_id, str) or not exam_id or len(exam_id) > 200:
        return None
    try:
        conn = sqlite3.connect(str(paper_service.DATABASE_PATH))
    except sqlite3.Error:
        return None
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT exam_id, threshold, num_holders, release_window_start, release_window_end, "
            "exam_title, subject, paper_hash, is_active "
            "FROM exams WHERE exam_id = ?",
            (exam_id,),
        ).fetchone()
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    if row is None:
        return None
    record = dict(row)
    record["paper_hash"] = bytes(record["paper_hash"]).hex() if record.get("paper_hash") else ""
    record["is_active"] = bool(record.get("is_active", 1))
    return record


def register_shares(
    conn: sqlite3.Connection,
    exam_id: str,
    commitments: list[int],
    holder_ids: list[int],
    wrapped_shares: list[bytes],
) -> None:
    """Record which user holds which wrapped share. Only wrapped blobs are stored."""
    if len(holder_ids) != len(wrapped_shares):
        raise ValueError("Each wrapped share needs exactly one holder")
    commitments_json = json.dumps([str(int(value)) for value in commitments])
    with conn:
        for index, (holder_id, blob) in enumerate(zip(holder_ids, wrapped_shares), start=1):
            conn.execute(
                "INSERT INTO shares (exam_id, holder_user_id, wrapped_share_blob, share_index, "
                "feldman_commitments_json, generation, is_current) VALUES (?, ?, ?, ?, ?, 1, 1)",
                (exam_id, int(holder_id), bytes(blob), index, commitments_json),
            )


def get_share_row(conn: sqlite3.Connection, exam_id: str, user_id: int) -> sqlite3.Row | None:
    """Return the current wrapped share assigned to this user for this exam (or None)."""
    return conn.execute(
        "SELECT id, exam_id, holder_user_id, wrapped_share_blob, share_index, feldman_commitments_json "
        "FROM shares WHERE exam_id = ? AND holder_user_id = ? AND is_current = 1 "
        "ORDER BY generation DESC LIMIT 1",
        (exam_id, int(user_id)),
    ).fetchone()


def is_released(conn: sqlite3.Connection, exam_id: str) -> bool:
    """True once the paper was successfully released."""
    return (
        conn.execute("SELECT 1 FROM exam_release WHERE exam_id = ?", (exam_id,)).fetchone()
        is not None
    )


def mark_released(conn: sqlite3.Connection, exam_id: str, paper_sha256: str, released_at: str) -> None:
    """Remember that the paper was released (only its SHA-256 is stored, never the content)."""
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO exam_release (exam_id, released_at, paper_sha256) VALUES (?, ?, ?)",
            (exam_id, released_at, paper_sha256),
        )


def exam_view(
    conn: sqlite3.Connection, exam: dict[str, Any], user_id: int, pending: Any, now: Any = None
) -> dict[str, Any]:
    """Everything the countdown, submit and download pages need for one invigilator."""
    summary = timewindow.window_summary(exam, now)
    exam_id = exam["exam_id"]
    threshold = int(exam["threshold"])
    released = is_released(conn, exam_id)
    submitted = bool(pending is not None and pending.has(exam_id, user_id))
    received = threshold if released else (pending.count(exam_id) if pending is not None else 0)
    status = summary["status"]
    if released:
        label, badge, step, hint = "Released", "success", 5, "Paper already released"
    elif submitted:
        label, badge, step, hint = "Share submitted", "info", 3, "Share already submitted"
    elif status == "open":
        label, badge, step, hint = "Window open", "warning", 2, ""
    elif status == "before":
        label, badge, step, hint = "Waiting", "secondary", 1, "Window not open"
    else:
        label, badge, step, hint = "Window closed", "danger", 0, "Window closed"
    return {
        "exam_id": exam_id,
        "threshold": threshold,
        "start_utc": summary["start_utc"],
        "end_utc": summary["end_utc"],
        "status": status,
        "seconds_until_open": summary["seconds_until_open"],
        "seconds_until_close": summary["seconds_until_close"],
        "released": released,
        "submitted": submitted,
        "received": received,
        "label": label,
        "badge": badge,
        "step": step,
        "steps": STEPS,
        "submit_hint": hint,
    }


def exams_for_user(conn: sqlite3.Connection, user_id: int, pending: Any, now: Any = None) -> list[dict[str, Any]]:
    """The exams this user holds a share for, newest first, with a status badge."""
    rows = conn.execute(
        "SELECT DISTINCT exam_id FROM shares WHERE holder_user_id = ? AND is_current = 1 "
        "ORDER BY exam_id DESC",
        (int(user_id),),
    ).fetchall()
    views: list[dict[str, Any]] = []
    for row in rows:
        exam = get_exam(row["exam_id"])
        if exam is not None:
            views.append(exam_view(conn, exam, user_id, pending, now))
    return views


def _all_exam_rows() -> list[dict[str, Any]]:
    """Every exam in the paper database (public metadata only), newest first; [] if none yet."""
    try:
        db = sqlite3.connect(str(paper_service.DATABASE_PATH))
    except sqlite3.Error:
        return []
    db.row_factory = sqlite3.Row
    try:
        return [
            dict(row)
            for row in db.execute(
                "SELECT exam_id, threshold, num_holders, release_window_start, release_window_end, "
                "exam_title, subject, is_active FROM exams ORDER BY rowid DESC"
            ).fetchall()
        ]
    except sqlite3.Error:
        return []
    finally:
        db.close()


def exam_status(conn: sqlite3.Connection, exam: dict[str, Any], now: Any = None) -> tuple[str, str]:
    """(label, badge) for an exam: Draft, Encrypted, Window open, Released or Closed (brief page 11)."""
    if is_released(conn, exam["exam_id"]):
        return "Released", "success"
    if not exam.get("release_window_start") or not exam.get("release_window_end"):
        return "Draft", "secondary"
    status = timewindow.window_summary(exam, now)["status"]
    if status == "open":
        return "Window open", "warning"
    if status == "before":
        return "Encrypted", "info"
    return "Closed", "dark"


def examiner_exams_list(
    conn: sqlite3.Connection, user_id: int, pending: Any, now: Any = None
) -> list[dict[str, Any]]:
    """Status of each exam, newest first."""
    result: list[dict[str, Any]] = []
    for exam in _all_exam_rows():
        try:
            summary = timewindow.window_summary(exam, now)
            label, badge = exam_status(conn, exam, now)
        except Exception:
            continue
        threshold = int(exam["threshold"])
        released = label == "Released"
        received = threshold if released else (pending.count(exam["exam_id"]) if pending is not None else 0)
        result.append({
            "exam_id": exam["exam_id"],
            "title": exam["exam_title"] or "(untitled)",
            "subject": exam["subject"],
            "threshold": threshold,
            "num_holders": exam["num_holders"],
            "start_utc": summary["start_utc"],
            "end_utc": summary["end_utc"],
            "status_label": label,
            "badge": badge,
            "submitted_shares": received,
            "is_active": bool(exam.get("is_active", 1)),
            "deactivated": not bool(exam.get("is_active", 1)),
        })
    return result


def toggle_exam_active(exam_id: str, conn: sqlite3.Connection) -> bool:
    """Toggle exam active status. Returns True if exam is now active, False if deactivated."""
    if not isinstance(exam_id, str) or not exam_id or len(exam_id) > 200:
        return False
    try:
        with conn:
            row = conn.execute(
                "SELECT is_active FROM exams WHERE exam_id = ?",
                (exam_id,),
            ).fetchone()
            if row is None:
                return False
            new_is_active = 0 if row["is_active"] else 1
            conn.execute(
                "UPDATE exams SET is_active = ? WHERE exam_id = ?",
                (new_is_active, exam_id),
            )
        return bool(new_is_active)
    except sqlite3.Error:
        return False


def exam_holder_rows(conn: sqlite3.Connection, exam_id: str, pending: Any) -> list[dict[str, Any]]:
    """Holders of an exam with 'share submitted' and time."""
    rows = conn.execute(
        "SELECT u.id AS user_id, u.username AS username, "
        "(SELECT MAX(s.submitted_at) FROM share_submissions s "
        " WHERE s.exam_id = ? AND s.user_id = u.id AND s.accepted = 1) AS submitted_at "
        "FROM shares sh JOIN users u ON u.id = sh.holder_user_id "
        "WHERE sh.exam_id = ? AND sh.is_current = 1 ORDER BY u.username",
        (exam_id, exam_id),
    ).fetchall()
    holders = []
    for row in rows:
        waiting = bool(pending is not None and pending.has(exam_id, row["user_id"]))
        holders.append({
            "username": row["username"],
            "submitted": waiting or row["submitted_at"] is not None,
            "time": row["submitted_at"],
        })
    return holders


def exam_copy_rows(conn: sqlite3.Connection, exam_id: str) -> list[dict[str, Any]]:
    """Copies of an exam: who has one, whether the PDF is issued and when it was last downloaded."""
    rows = conn.execute(
        "SELECT u.username AS username, c.file_path AS file_path FROM copies c "
        "JOIN users u ON u.id = c.user_id WHERE c.exam_id = ? ORDER BY u.username",
        (exam_id,),
    ).fetchall()
    return [
        {
            "username": row["username"],
            "issued": bool(row["file_path"]),
            "downloaded_at": (copy_download_history(conn, exam_id, row["username"], 1) or [None])[0],
        }
        for row in rows
    ]


def copy_download_history(
    conn: sqlite3.Connection, exam_id: str, username: str, limit: int = 10
) -> list[str]:
    """Times (newest first) at which this holder downloaded the copy, from the audit log."""
    try:
        rows = conn.execute(
            "SELECT timestamp FROM audit_entries WHERE event_type = 'copy_downloaded' AND actor = ? "
            "AND instr(details, ?) > 0 ORDER BY id DESC LIMIT ?",
            (username, exam_id, int(limit)),
        ).fetchall()
    except sqlite3.OperationalError:
        return []  # the audit table is created by the first log entry
    return [row["timestamp"] for row in rows]


def exam_recent_events(conn: sqlite3.Connection, exam_id: str, limit: int = 10) -> list[dict[str, Any]]:
    """The last audit entries that mention this exam."""
    try:
        rows = conn.execute(
            "SELECT id, timestamp, event_type, actor FROM audit_entries "
            "WHERE instr(details, ?) > 0 ORDER BY id DESC LIMIT ?",
            (exam_id, int(limit)),
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    return [dict(row) for row in rows]


def count_active_exams(conn: sqlite3.Connection, now: Any = None) -> int | None:
    """Exams whose release window is open right now and whose paper is not yet released."""
    try:
        db = sqlite3.connect(str(paper_service.DATABASE_PATH))
    except sqlite3.Error:
        return None
    db.row_factory = sqlite3.Row
    try:
        rows = db.execute(
            "SELECT exam_id, threshold, num_holders, release_window_start, release_window_end FROM exams"
        ).fetchall()
    except sqlite3.Error:
        return None
    finally:
        db.close()
    active = 0
    for row in rows:
        exam = dict(row)
        try:
            is_open = timewindow.window_summary(exam, now)["status"] == "open"
        except Exception:
            continue
        if is_open and not is_released(conn, exam["exam_id"]):
            active += 1
    return active