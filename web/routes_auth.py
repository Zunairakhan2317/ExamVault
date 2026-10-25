"""Login, 2FA, 2FA enrolment, logout and dashboard routes.

Plan 4.1 to 4.4 and Section 8; Frontend Design Brief pages 1 to 5.
Security rules: lockout is checked BEFORE the password; the same error is shown for a wrong
password and an unknown username (the dummy hash keeps the timing similar); every failed password
or code is counted by auth.lockout; the session is cleared before login (no session fixation);
the TOTP secret is only ever stored encrypted; secrets and passwords are never logged.
A locked message is safe to show because unknown usernames are locked exactly like real ones.
"""
from __future__ import annotations

import base64
import math
import sqlite3
import time
from datetime import datetime, timezone
from functools import lru_cache

from cryptography.exceptions import InvalidTag
from flask import Flask, current_app, flash, redirect, render_template, request, session
from flask_login import current_user, login_user, logout_user

from auth import lockout
from auth.passwords import hash_password, needs_rehash, verify_password
from auth.rbac import ROLES, role_required
from crypto import pki
from auth.totp import (
    new_secret,
    protect_secret,
    provisioning_uri,
    qr_png_bytes,
    unprotect_secret,
    verify_code,
)
from web import exam_store
from web.audit_log import log_event
from web.db import get_db
from web.user import load_user_by_id

PENDING_SECONDS = 300  # time allowed between the password step and the code step

NAV = {
    "admin": [("Dashboard", "/dashboard"), ("Users", "/admin/users"), ("Alerts", "/admin/alerts"),
              ("Files", "/files"), ("Demo", "/demo/ecb")],
    "examiner": [("Dashboard", "/dashboard"), ("Upload Exam", "/examiner/upload"),
                 ("My Exams", "/examiner/exams"), ("Variants", "/examiner/variants"),
                 ("Leak Analyzer", "/tracing/analyze"), ("Files", "/files")],
    "invigilator": [("Dashboard", "/dashboard"), ("My Exams", "/dashboard"), ("Files", "/files")],
    "auditor": [("Dashboard", "/dashboard"), ("Audit Log", "/auditor/log"),
                ("Verify", "/auditor/verify"), ("Daily Roots", "/auditor/roots"),
                ("Leak Analyzer", "/tracing/analyze")],
}

GENERIC_LOGIN_ERROR = "Invalid username or password"


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    """A hash of a throwaway password so unknown usernames cost the same time as real ones."""
    return hash_password("dummy-password-for-timing-only")


def _locked_text(seconds: int) -> str:
    minutes = max(1, math.ceil(seconds / 60))
    return f"Too many attempts. Try again after {minutes} minutes."


def _count(conn: sqlite3.Connection, sql: str) -> int | None:
    try:
        return int(conn.execute(sql).fetchone()[0])
    except sqlite3.OperationalError:  # table is created by a later module
        return None


def _scalar(conn: sqlite3.Connection, sql: str):
    """First column of the first row, or None if the table does not exist yet."""
    try:
        row = conn.execute(sql).fetchone()
    except sqlite3.OperationalError:
        return None
    return row[0] if row is not None else None


def _pending_user(conn: sqlite3.Connection):
    """The user who passed the password step in this browser session (or None)."""
    uid = session.get("pending_uid")
    started = session.get("pending_ts")
    if uid is None or started is None or time.time() - float(started) > PENDING_SECONDS:
        return None
    row = conn.execute(
        "SELECT id, username, role, totp_secret_encrypted, totp_last_step, is_active "
        "FROM users WHERE id = ?",
        (uid,),
    ).fetchone()
    if row is None or not row["is_active"]:
        return None
    return row


def _count_failure(conn: sqlite3.Connection, username: str, action: str) -> bool:
    """Record a failed attempt, write it to the audit chain, return True if the account just locked."""
    ip = request.remote_addr
    result = lockout.record_failure(conn, username, ip)
    log_event(conn, username[:64], action, {"ip": ip})
    if result["just_locked"]:
        log_event(conn, username[:64], "account_locked", {"ip": ip})
    return bool(result["just_locked"])


def _finish_login(conn: sqlite3.Connection, user: sqlite3.Row, step: int):
    """Both factors passed: store the TOTP step (replay protection) and start a fresh session."""
    ip = request.remote_addr
    if not pki.user_certificate_ok(conn, int(user["id"])):  # revoked between the two login steps
        session.clear()
        log_event(conn, user["username"], "login_refused", {"ip": ip, "reason": "revoked_certificate"})
        flash("Your certificate has been revoked. Contact the administrator.", "danger")
        return redirect("/login")
    previous_login = conn.execute(
        "SELECT last_login_at FROM users WHERE id = ?", (user["id"],)
    ).fetchone()["last_login_at"]
    conn.execute("UPDATE users SET totp_last_step = ? WHERE id = ?", (step, user["id"]))
    conn.commit()
    try:
        lockout.record_success(conn, user["username"], ip)
    except lockout.AccountLockedError as exc:
        session.clear()
        flash(_locked_text(exc.seconds_remaining), "danger")
        return redirect("/login")
    uid = int(user["id"])
    session.clear()  # new session after authentication
    login_user(load_user_by_id(conn, uid))
    session.permanent = True
    session["previous_login"] = previous_login  # shown on the dashboard as "Last login"
    conn.execute(
        "UPDATE users SET last_login_at = ? WHERE id = ?",
        (datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), uid),
    )
    conn.commit()
    log_event(conn, user["username"], "login_success", {"ip": ip})
    return redirect("/dashboard")


def register(app: Flask) -> None:
    """Attach the authentication routes. Needs app.extensions['examvault_limiter']."""
    limiter = app.extensions["examvault_limiter"]

    @app.context_processor
    def _inject_nav() -> dict:
        role = getattr(current_user, "role", None) if current_user.is_authenticated else None
        return {"nav_items": NAV.get(role, [])}

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit(lockout.LOGIN_RATE_LIMIT, methods=["POST"])
    def login():
        if current_user.is_authenticated:
            return redirect("/dashboard")
        if request.method == "GET":
            return render_template("login.html")
        conn = get_db()
        password = request.form.get("password", "")
        try:
            username = lockout.normalize_username(request.form.get("username", ""))
        except ValueError:
            username = ""
        if not username or not password:
            flash(GENERIC_LOGIN_ERROR, "danger")
            return render_template("login.html")
        locked, seconds = lockout.is_locked(conn, username)
        if locked:
            log_event(conn, username[:64], "login_blocked", {"ip": request.remote_addr})
            flash(_locked_text(seconds), "danger")
            return render_template("login.html")
        row = conn.execute(
            "SELECT id, username, password_hash, totp_secret_encrypted, is_active "
            "FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        stored = row["password_hash"] if row is not None else _dummy_hash()
        password_ok = verify_password(stored, password)
        if row is None or not row["is_active"] or not password_ok:
            _count_failure(conn, username, "login_failed")
            flash(GENERIC_LOGIN_ERROR, "danger")
            return render_template("login.html")
        if not pki.user_certificate_ok(conn, int(row["id"])):  # plan 6.6: certificate + CRL check
            log_event(conn, username[:64], "login_refused", {"ip": request.remote_addr, "reason": "revoked_certificate"})
            flash("Your certificate has been revoked. Contact the administrator.", "danger")
            return render_template("login.html")
        if needs_rehash(stored):
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(password), row["id"])
            )
            conn.commit()
        session.clear()
        session["pending_uid"] = int(row["id"])
        session["pending_ts"] = time.time()
        return redirect("/login/2fa" if row["totp_secret_encrypted"] else "/enroll-2fa")

    @app.route("/login/2fa", methods=["GET", "POST"])
    @limiter.limit(lockout.LOGIN_RATE_LIMIT, methods=["POST"])
    def login_2fa():
        conn = get_db()
        user = _pending_user(conn)
        if user is None:
            session.clear()
            flash("Session expired, please login again", "warning")
            return redirect("/login")
        if not user["totp_secret_encrypted"]:
            return redirect("/enroll-2fa")
        if request.method == "GET":
            return render_template("login_2fa.html")
        locked, seconds = lockout.is_locked(conn, user["username"])
        if locked:
            log_event(conn, user["username"], "login_blocked", {"ip": request.remote_addr})
            session.clear()
            flash(_locked_text(seconds), "danger")
            return redirect("/login")
        try:
            secret = unprotect_secret(
                bytes(user["totp_secret_encrypted"]), current_app.config["TOTP_KEY"], user["username"]
            )
        except (InvalidTag, ValueError):
            log_event(conn, user["username"], "totp_secret_unreadable", {})
            session.clear()
            flash(GENERIC_LOGIN_ERROR, "danger")
            return redirect("/login")
        ok, step = verify_code(secret, request.form.get("code", ""), user["totp_last_step"])
        if not ok or step is None:
            just_locked = _count_failure(conn, user["username"], "totp_failed")
            if just_locked:
                session.clear()
                flash(_locked_text(lockout.get_lockout_seconds()), "danger")
                return redirect("/login")
            flash("Invalid or expired code", "danger")
            return render_template("login_2fa.html")
        return _finish_login(conn, user, step)

    @app.route("/enroll-2fa", methods=["GET", "POST"])
    @limiter.limit(lockout.LOGIN_RATE_LIMIT, methods=["POST"])
    def enroll_2fa():
        conn = get_db()
        user = _pending_user(conn)
        if user is None:
            session.clear()
            flash("Session expired, please login again", "warning")
            return redirect("/login")
        if user["totp_secret_encrypted"]:
            flash("Two-factor is already enabled. Enter your code.", "info")
            return redirect("/login/2fa")
        key = current_app.config["TOTP_KEY"]
        username = user["username"]

        def _page(secret: str):
            uri = provisioning_uri(secret, username)
            qr = base64.b64encode(qr_png_bytes(uri)).decode("ascii")
            return render_template("enroll_2fa.html", qr_data=qr, secret=secret)

        if request.method == "GET":
            secret = new_secret()
            # kept in the session only in encrypted form
            session["enroll_blob"] = protect_secret(secret, key, username).hex()
            return _page(secret)
        blob_hex = session.get("enroll_blob")
        if not blob_hex:
            return redirect("/enroll-2fa")
        try:
            secret = unprotect_secret(bytes.fromhex(blob_hex), key, username)
        except (InvalidTag, ValueError):
            session.pop("enroll_blob", None)
            return redirect("/enroll-2fa")
        ok, step = verify_code(secret, request.form.get("code", ""), None)
        if not ok or step is None:
            if _count_failure(conn, username, "totp_enroll_failed"):
                session.clear()
                flash(_locked_text(lockout.get_lockout_seconds()), "danger")
                return redirect("/login")
            flash("Code did not match, try again", "danger")
            return _page(secret)
        conn.execute(
            "UPDATE users SET totp_secret_encrypted = ?, totp_last_step = ? WHERE id = ?",
            (protect_secret(secret, key, username), step, user["id"]),
        )
        conn.commit()
        log_event(conn, username, "totp_enrolled", {})
        session.pop("enroll_blob", None)
        fresh = _pending_user(conn)
        response = _finish_login(conn, fresh, step)
        flash("Two-factor enabled", "success")
        return response

    @app.post("/logout")
    @role_required(*ROLES)
    def logout():
        log_event(get_db(), current_user.username, "logout", {})
        logout_user()
        session.clear()
        flash("Logged out", "info")
        return redirect("/login")

    @app.get("/dashboard")
    @role_required(*ROLES)
    def dashboard():
        conn = get_db()
        role = getattr(current_user, "role", None)
        alerts = _count(conn, "SELECT COUNT(*) FROM honeytoken_events")
        stats = {
            "users": _count(conn, "SELECT COUNT(*) FROM users"),
            "revoked": _count(conn, "SELECT COUNT(*) FROM certificates WHERE revoked_at IS NOT NULL"),
            "alerts": alerts,
        }
        exams: list = []
        examiner_stats: dict = {}
        if role == "admin":
            stats["active_exams"] = exam_store.count_active_exams(conn)
        if role == "auditor":
            stats["log_entries"] = _count(conn, "SELECT COUNT(*) FROM audit_entries")
            stats["last_root_date"] = _scalar(conn, "SELECT MAX(target_date) FROM merkle_roots")
        if role == "invigilator":
            try:
                exams = exam_store.exams_for_user(
                    conn, current_user.id, current_app.extensions.get("examvault_pending")
                )
            except Exception:  # the exam database may not exist yet
                exams = []
        if role == "examiner":
            try:
                exams = exam_store.examiner_exams_list(
                    conn, current_user.id, current_app.extensions.get("examvault_pending")
                )
                # Filter active exams only
                active_exams = [e for e in exams if e.get("is_active", True)]
                # Total active exams count
                examiner_stats["my_exams_count"] = len(active_exams)
                # Next upcoming exam: active exams with window status "before" or "open", earliest start_utc
                upcoming = [e for e in active_exams if e.get("status") in ("before", "open")]
                if upcoming:
                    # Sort by start_utc and pick the earliest
                    upcoming.sort(key=lambda x: x.get("start_utc", ""))
                    examiner_stats["next_exam"] = upcoming[0]
                # Last 5 exams (most recent first)
                all_sorted = sorted(active_exams, key=lambda x: x.get("exam_id", ""), reverse=True)
                examiner_stats["recent_exams"] = all_sorted[:5]
            except Exception:  # the exam database may not exist yet
                exams = []
                examiner_stats = {
                    "my_exams_count": 0,
                    "next_exam": None,
                    "recent_exams": [],
                }
        show_alert_banner = role in ("admin", "auditor") and bool(alerts)
        return render_template(
            "dashboard.html",
            stats=stats,
            exams=exams,
            examiner_stats=examiner_stats,
            last_login=session.get("previous_login"),
            show_alert_banner=show_alert_banner,
        )