"""Auditor pages 17 to 19: audit log, verification result, daily signed Merkle roots (plan 6.1 to 6.4).

Security rules: auditor role only; every query is parameterised; log text is escaped by Jinja;
CSV cells that could be read as spreadsheet formulas are neutralised; only COMPLETED days (before today,
UTC) can be sealed with a signed root, because a root signed for a day that is still running stops matching
as soon as the next audit entry of that day is written.
"""
from __future__ import annotations

import csv
import io
import re
import sqlite3
from datetime import date, datetime, timezone
from typing import Any

from flask import Flask, Response, flash, redirect, render_template, request
from flask_login import current_user

from audit.daily_root import compute_daily_root, verify_daily_root
from audit.verifier import verify_full_chain
from auth.rbac import role_required
from web.audit_log import log_event
from web.db import get_db

PAGE_SIZE = 50
CSV_LIMIT = 10000
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# Severity is derived from the event type (the audit table itself has no severity column).
CRITICAL_EVENTS = ("honeytoken_access", "log_tampering_detected")
WARNING_EVENTS = (
    "access_denied", "login_failed", "login_blocked", "totp_failed", "totp_enroll_failed", "account_locked",
    "rate_limited", "share_refused", "release_failed", "release_handler_failed", "totp_secret_unreadable",
    "user_revoked",
)


def severity_of(event_type: str) -> str:
    """'critical', 'warning' or 'info' for an audit event type."""
    if event_type in CRITICAL_EVENTS:
        return "critical"
    if event_type in WARNING_EVENTS:
        return "warning"
    return "info"


def _today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def _valid_date(value: str | None) -> str:
    """Return the value if it is a real YYYY-MM-DD date, else an empty string."""
    if not value or not _DATE_RE.fullmatch(value):
        return ""
    try:
        date.fromisoformat(value)
    except ValueError:
        return ""
    return value


def _like(text: str) -> str:
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _filters() -> dict[str, str]:
    args = request.args
    severity = args.get("severity", "")
    return {
        "date_from": _valid_date(args.get("date_from")),
        "date_to": _valid_date(args.get("date_to")),
        "actor": args.get("actor", "").strip()[:100],
        "action": args.get("action", "").strip()[:100],
        "severity": severity if severity in ("critical", "warning", "info") else "",
        "q": args.get("q", "").strip()[:100],
    }


def _where(filters: dict[str, str]) -> tuple[str, list[Any]]:
    parts: list[str] = []
    params: list[Any] = []
    if filters["date_from"]:
        parts.append("substr(timestamp, 1, 10) >= ?")
        params.append(filters["date_from"])
    if filters["date_to"]:
        parts.append("substr(timestamp, 1, 10) <= ?")
        params.append(filters["date_to"])
    if filters["actor"]:
        parts.append("actor = ?")
        params.append(filters["actor"])
    if filters["action"]:
        parts.append("event_type = ?")
        params.append(filters["action"])
    if filters["q"]:
        parts.append("(details LIKE ? ESCAPE '\\' OR actor LIKE ? ESCAPE '\\' OR event_type LIKE ? ESCAPE '\\')")
        params.extend([_like(filters["q"])] * 3)
    if filters["severity"] == "critical":
        marks = ",".join("?" * len(CRITICAL_EVENTS))
        parts.append(f"event_type IN ({marks})")
        params.extend(CRITICAL_EVENTS)
    elif filters["severity"] == "warning":
        marks = ",".join("?" * len(WARNING_EVENTS))
        parts.append(f"event_type IN ({marks})")
        params.extend(WARNING_EVENTS)
    elif filters["severity"] == "info":
        everything = CRITICAL_EVENTS + WARNING_EVENTS
        marks = ",".join("?" * len(everything))
        parts.append(f"event_type NOT IN ({marks})")
        params.extend(everything)
    return (" WHERE " + " AND ".join(parts)) if parts else "", params


def _csv_safe(value: Any) -> str:
    """Neutralise cells a spreadsheet could execute as a formula."""
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def _headline(report: dict[str, Any]) -> dict[str, Any]:
    """Turn the verifier report into a banner (level, title) plus the reasons behind it."""
    reasons: list[str] = []
    for index in report["altered_entry_indices"]:
        reasons.append(f"Entry #{index} was altered (content or hash changed)")
    for index in report["missing_entry_indices"]:
        reasons.append(f"Entry #{index} is missing (deleted)")
    for index in report["broken_link_indices"]:
        reasons.append(f"Entry #{index} has a broken link (reordered, or an earlier entry was removed)")
    for day in report["missing_daily_root_dates"]:
        reasons.append(f"No signed daily root for completed day {day}")
    for day in report["invalid_daily_root_dates"]:
        reasons.append(f"Daily root for {day} does not match the log or its signature is invalid")
    if report["valid"]:
        return {"level": "success", "title": "Log intact", "reasons": reasons}
    first = report["first_broken_index"]
    if first is not None:
        if first in report["missing_entry_indices"]:
            title = f"TAMPERED: entry #{first} is missing (deleted)"
        elif first in report["altered_entry_indices"]:
            title = f"TAMPERED: entry #{first} was altered"
        else:
            title = f"TAMPERED: entry #{first} has a broken link"
    else:
        title = "Daily roots need attention"
    return {"level": "danger", "title": title, "reasons": reasons}


def _past_dates_without_root(conn: sqlite3.Connection) -> list[str]:
    try:
        rows = conn.execute(
            "SELECT DISTINCT substr(timestamp, 1, 10) AS day FROM audit_entries "
            "WHERE substr(timestamp, 1, 10) < ? AND substr(timestamp, 1, 10) NOT IN "
            "(SELECT target_date FROM merkle_roots) ORDER BY day",
            (_today(),),
        ).fetchall()
    except sqlite3.OperationalError:  # merkle_roots does not exist before the first root
        try:
            rows = conn.execute(
                "SELECT DISTINCT substr(timestamp, 1, 10) AS day FROM audit_entries "
                "WHERE substr(timestamp, 1, 10) < ? ORDER BY day",
                (_today(),),
            ).fetchall()
        except sqlite3.OperationalError:
            return []
    return [row["day"] for row in rows]


def register(app: Flask) -> None:
    """Attach the three auditor pages."""

    @app.get("/auditor/log")
    @role_required("auditor")
    def auditor_log():
        conn = get_db()
        filters = _filters()
        where, params = _where(filters)
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        try:
            total = conn.execute(f"SELECT COUNT(*) FROM audit_entries{where}", params).fetchone()[0]
            rows = conn.execute(
                "SELECT id, timestamp, event_type, details, actor, prev_hash, entry_hash FROM audit_entries"
                f"{where} ORDER BY id DESC LIMIT ? OFFSET ?",
                [*params, PAGE_SIZE, (page - 1) * PAGE_SIZE],
            ).fetchall()
            actors = [r[0] for r in conn.execute("SELECT DISTINCT actor FROM audit_entries ORDER BY actor LIMIT 200")]
            actions = [r[0] for r in conn.execute("SELECT DISTINCT event_type FROM audit_entries ORDER BY event_type")]
        except sqlite3.OperationalError:  # no audit entry written yet
            total, rows, actors, actions = 0, [], [], []
        entries = [
            {**dict(row), "severity": severity_of(row["event_type"]), "short": row["details"][:120]}
            for row in rows
        ]
        return render_template(
            "auditor_log.html",
            entries=entries, filters=filters, fargs={k: v for k, v in filters.items() if v},
            page=page, total=total, total_pages=max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE),
            actors=actors, actions=actions,
        )

    @app.get("/auditor/log/export.csv")
    @role_required("auditor")
    def auditor_log_export():
        conn = get_db()
        where, params = _where(_filters())
        try:
            rows = conn.execute(
                "SELECT id, timestamp, event_type, actor, details, prev_hash, entry_hash FROM audit_entries"
                f"{where} ORDER BY id ASC LIMIT ?",
                [*params, CSV_LIMIT],
            ).fetchall()
        except sqlite3.OperationalError:
            rows = []
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["entry", "time_utc", "action", "actor", "details", "prev_hash", "hash"])
        for row in rows:
            writer.writerow([_csv_safe(value) for value in row])
        log_event(conn, current_user.username, "audit_log_exported", {"rows": len(rows)})
        return Response(
            buffer.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit_log.csv", "Cache-Control": "no-store"},
        )

    @app.get("/auditor/verify")
    @role_required("auditor")
    def auditor_verify():
        conn = get_db()
        report = verify_full_chain(conn)
        ran_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        try:
            log_event(
                conn, current_user.username, "log_verified",
                {"status": report["status"], "first_broken": report["first_broken_index"]},
            )
        except ValueError:
            # A tampered chain refuses new entries by design; the red result must still be shown.
            pass
        entries = conn.execute("SELECT COUNT(*) FROM audit_entries").fetchone()[0]
        checks = [
            ("Hash chain links", bool(report["hashchain_valid"])),
            ("Merkle roots of completed days", bool(report["daily_roots_valid"])),
            ("Root signatures", bool(report["signatures_valid"])),
        ]
        return render_template(
            "auditor_verify.html",
            report=report, headline=_headline(report), checks=checks, ran_at=ran_at, entries=entries,
        )

    @app.get("/auditor/roots")
    @role_required("auditor")
    def auditor_roots():
        conn = get_db()
        try:
            rows = conn.execute(
                "SELECT target_date, merkle_root, entry_count, signed_at FROM merkle_roots ORDER BY target_date DESC"
            ).fetchall()
        except sqlite3.OperationalError:
            rows = []
        roots = [{**dict(row), "valid": verify_daily_root(conn, row["target_date"])} for row in rows]
        return render_template(
            "auditor_roots.html", roots=roots, pending=_past_dates_without_root(conn), today=_today()
        )

    @app.post("/auditor/roots/generate")
    @role_required("auditor")
    def auditor_roots_generate():
        conn = get_db()
        requested = request.form.get("date", "")
        if requested == "all":
            days = _past_dates_without_root(conn)
        else:
            day = _valid_date(requested)
            if not day or day >= _today():
                flash("Only completed days (before today, UTC) can be sealed with a signed root.", "danger")
                return redirect("/auditor/roots")
            days = [day]
        if not days:
            flash("Nothing to seal: every completed day already has a signed root.", "info")
            return redirect("/auditor/roots")
        for day in days:
            try:
                compute_daily_root(conn, day)
                conn.commit()
            except (ValueError, RuntimeError) as exc:
                conn.rollback()
                flash(f"{day}: {exc}", "danger")
                continue
            log_event(conn, current_user.username, "daily_root_generated", {"date": day})
            flash(f"Signed root created for {day}", "success")
        return redirect("/auditor/roots")
