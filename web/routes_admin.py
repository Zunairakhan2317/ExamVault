"""Admin user management pages (Plan T1, Frontend Brief pages 6 and 7)."""
from __future__ import annotations

import io
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, abort, current_app, flash, make_response, redirect, render_template, request, send_file, url_for
from flask_login import current_user

from auth.passwords import check_policy, hash_password
from auth.rbac import role_required
from crypto import pki
from crypto.pki import issue_certificate
from web import exam_store, rotation_flow, share_flow
from web.audit_log import log_event
from web.db import get_db

KEYS_DIR = Path(__file__).parent.parent / "keys"
KEYS_DIR.mkdir(parents=True, exist_ok=True)

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,31}$")


def _get_filtered_users(conn: sqlite3.Connection, search: str, role: str, page: int, per_page: int) -> tuple[list[sqlite3.Row], int]:
    where_parts = []
    params: list[Any] = []
    if search:
        where_parts.append("(username LIKE ? OR full_name LIKE ? OR email LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like, like])
    if role:
        where_parts.append("role = ?")
        params.append(role)

    where_sql = "WHERE " + " AND ".join(where_parts) if where_parts else ""

    total = conn.execute(f"SELECT COUNT(*) FROM users {where_sql}", params).fetchone()[0]

    offset = (page - 1) * per_page
    params.extend([per_page, offset])
    rows = conn.execute(
        f"SELECT id, username, full_name, email, role, is_active, cert_serial, "
        f"EXISTS (SELECT 1 FROM certificates c WHERE c.user_id = users.id "
        f"AND c.revoked_at IS NOT NULL) AS is_revoked, "
        f"totp_secret_encrypted IS NOT NULL as has_2fa, last_login_at, created_at "
        f"FROM users {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?",
        params,
    ).fetchall()

    return rows, total


REVOKE_REASONS = {
    "left_job": "Left job",
    "key_lost": "Key lost",
    "suspicious_activity": "Suspicious activity",
}

KEY_HANDOFF_SECONDS = 300
_handoff_lock = threading.Lock()
_handoff: dict[str, tuple[int, str, bytes, float]] = {}


def _stash_private_key(admin_id: int, username: str, pem: bytes) -> str:
    token = secrets.token_urlsafe(32)
    now = time.time()
    with _handoff_lock:
        for old in [t for t, item in _handoff.items() if item[3] <= now]:
            del _handoff[old]
        _handoff[token] = (int(admin_id), username, pem, now + KEY_HANDOFF_SECONDS)
    return token


def _take_private_key(admin_id: int, token: str) -> tuple[str, bytes] | None:
    with _handoff_lock:
        item = _handoff.get(token)
        if item is None or item[3] <= time.time() or item[0] != int(admin_id):
            return None
        del _handoff[token]
    return item[1], item[2]


def _generate_rsa_keypair(username: str) -> tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def register(app: Flask) -> None:
    @app.get("/admin/users")
    @role_required("admin")
    def admin_users():
        search = request.args.get("search", "").strip()
        role_filter = request.args.get("role", "").strip()
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        per_page = 20

        conn = get_db()
        rows, total = _get_filtered_users(conn, search, role_filter, page, per_page)
        total_pages = max(1, (total + per_page - 1) // per_page)

        return render_template(
            "admin_users.html",
            users=rows,
            search=search,
            role_filter=role_filter,
            page=page,
            total_pages=total_pages,
            total=total,
            roles=["admin", "examiner", "invigilator", "auditor"],
            revoke_reasons=list(REVOKE_REASONS.items()),
        )

    @app.route("/admin/users/new", methods=["GET", "POST"])
    @role_required("admin")
    def admin_users_new():
        conn = get_db()

        if request.method == "GET":
            return render_template("admin_user_new.html", roles=["admin", "examiner", "invigilator", "auditor"])

        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip().lower()
        email = request.form.get("email", "").strip()
        role = request.form.get("role", "").strip()
        password = request.form.get("password", "")
        generate_password = request.form.get("generate_password") == "on"

        if not full_name or not username or not email or not role:
            flash("All fields are required", "danger")
            return render_template("admin_user_new.html", roles=["admin", "examiner", "invigilator", "auditor"])

        if not USERNAME_RE.fullmatch(username):
            flash(
                "Username must be 3 to 32 characters: lowercase letters, digits, dot, dash or underscore",
                "danger",
            )
            return render_template("admin_user_new.html", roles=["admin", "examiner", "invigilator", "auditor"])

        if role not in ("admin", "examiner", "invigilator", "auditor"):
            flash("Invalid role", "danger")
            return render_template("admin_user_new.html", roles=["admin", "examiner", "invigilator", "auditor"])

        if generate_password:
            password = secrets.token_urlsafe(16)
        if not password:
            flash("Password is required", "danger")
            return render_template("admin_user_new.html", roles=["admin", "examiner", "invigilator", "auditor"])

        try:
            check_policy(password)
        except ValueError as exc:
            flash(str(exc), "danger")
            return render_template("admin_user_new.html", roles=["admin", "examiner", "invigilator", "auditor"])

        # Schnorr proof of key possession (plan 4.7) is OFF until its full UI exists: the user must be given
        # the secret x once and have a local tool to build the proof. Storing only y (and throwing x away)
        # would lock the invigilator out of share submission, so schnorr_public_y stays NULL.
        schnorr_y = None

        try:
            conn.execute(
                "INSERT INTO users (username, full_name, email, role, password_hash, schnorr_public_y) VALUES (?, ?, ?, ?, ?, ?)",
                (username, full_name, email, role, hash_password(password), schnorr_y),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            flash("Username or email already exists", "danger")
            return render_template("admin_user_new.html", roles=["admin", "examiner", "invigilator", "auditor"])

        new_user = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        new_user_id = new_user["id"]

        log_event(
            conn,
            current_user.username,
            "user_created",
            {"new_user_id": new_user_id, "new_username": username, "role": role},
        )

        private_pem = None
        if role == "invigilator":
            private_pem, public_pem = _generate_rsa_keypair(username)
            public_path = KEYS_DIR / f"{username}_public.pem"
            if public_path.resolve().parent != KEYS_DIR.resolve():
                abort(400)
            public_path.write_bytes(public_pem)
            try:
                os.chmod(public_path, 0o600)
            except OSError:
                pass

            # Issue PKI Certificate for Invigilator
            serial_hex, cert_pem = issue_certificate(username, role, public_pem)
            with conn:
                conn.execute(
                    "INSERT INTO certificates (serial, user_id, pem, issued_at) VALUES (?, ?, ?, ?)",
                    (serial_hex, new_user_id, cert_pem, datetime.now(timezone.utc).isoformat()),
                )
                conn.execute(
                    "UPDATE users SET cert_serial = ? WHERE id = ?",
                    (serial_hex, new_user_id),
                )

            log_event(
                conn,
                current_user.username,
                "invigilator_keypair_generated",
                {"user_id": new_user_id, "username": username, "cert_serial": serial_hex},
            )

        flash(f"User '{username}' created successfully", "success")
        key_token = None
        if private_pem:
            key_token = _stash_private_key(current_user.id, username, private_pem)
            private_pem = None

        if generate_password or role == "invigilator":
            response = make_response(
                render_template(
                    "admin_user_new.html",
                    roles=["admin", "examiner", "invigilator", "auditor"],
                    created_user={"username": username, "password": password, "key_token": key_token},
                )
            )
            response.headers["Cache-Control"] = "no-store"
            return response
        else:
            return redirect(url_for("admin_users"))

    @app.get("/admin/users/private-key/<token>")
    @role_required("admin")
    def download_private_key(token: str):
        taken = _take_private_key(current_user.id, token)
        if taken is None:
            abort(404)
        username, pem = taken
        log_event(get_db(), current_user.username, "private_key_handed_over", {"username": username})
        response = send_file(
            io.BytesIO(pem),
            mimetype="application/x-pem-file",
            as_attachment=True,
            download_name=f"{username}_private.pem",
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/admin/users/<int:user_id>/disable")
    @role_required("admin")
    def admin_users_disable(user_id: int):
        if user_id == current_user.id:
            flash("You cannot disable yourself", "danger")
            return redirect(url_for("admin_users"))

        conn = get_db()
        user = conn.execute("SELECT username, is_active FROM users WHERE id = ?", (user_id,)).fetchone()
        if user is None:
            abort(404)

        if not user["is_active"]:
            flash("User is already disabled", "warning")
            return redirect(url_for("admin_users"))

        conn.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_id,))
        conn.commit()

        log_event(
            conn,
            current_user.username,
            "user_disabled",
            {"target_user_id": user_id, "target_username": user["username"]},
        )

        flash(f"User '{user['username']}' disabled", "success")
        return redirect(url_for("admin_users"))

    @app.post("/admin/users/<int:user_id>/enable")
    @role_required("admin")
    def admin_users_enable(user_id: int):
        if user_id == current_user.id:
            flash("You cannot enable yourself", "danger")
            return redirect(url_for("admin_users"))

        conn = get_db()
        user = conn.execute("SELECT username, is_active FROM users WHERE id = ?", (user_id,)).fetchone()
        if user is None:
            abort(404)

        if user["is_active"]:
            flash("User is already active", "warning")
            return redirect(url_for("admin_users"))

        conn.execute("UPDATE users SET is_active = 1 WHERE id = ?", (user_id,))
        conn.commit()

        log_event(
            conn,
            current_user.username,
            "user_enabled",
            {"target_user_id": user_id, "target_username": user["username"]},
        )

        flash(f"User '{user['username']}' enabled", "success")
        return redirect(url_for("admin_users"))

    @app.post("/admin/users/<int:user_id>/revoke")
    @role_required("admin")
    def admin_users_revoke(user_id: int):
        if user_id == current_user.id:
            flash("You cannot revoke yourself", "danger")
            return redirect(url_for("admin_users"))

        conn = get_db()
        user = conn.execute("SELECT username, is_active FROM users WHERE id = ?", (user_id,)).fetchone()
        if user is None:
            abort(404)

        reason = request.form.get("reason", "")
        if reason not in REVOKE_REASONS:
            flash("Select a reason for the revocation", "danger")
            return redirect(url_for("admin_users"))

        with conn:
            conn.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_id,))
        # Plan 6.5/6.6: every live certificate of this user goes onto a fresh CA-signed CRL (and is audited).
        serials = [
            r["serial"]
            for r in conn.execute(
                "SELECT serial FROM certificates WHERE user_id = ? AND revoked_at IS NULL", (user_id,)
            ).fetchall()
        ]
        for serial in serials:
            pki.revoke(conn, serial, REVOKE_REASONS[reason], actor=current_user.username)

        log_event(
            conn,
            current_user.username,
            "user_revoked",
            {"target_user_id": user_id, "target_username": user["username"], "reason": reason},
        )

        flash("User revoked. Please rotate shares for affected exams", "success")
        return redirect(url_for("admin_users"))

    # Rotation Admin Screen Routes (Plan 3.7): the admin opens a ceremony, k holders approve, the server rotates
    def _rotation_keys_dir() -> Path:
        return Path(current_app.config.get("KEYS_DIR") or KEYS_DIR)

    @app.get("/admin/rotations")
    @role_required("admin")
    def admin_rotations():
        rows = rotation_flow.admin_overview(
            get_db(), rotation_flow.get_ceremonies(current_app), _rotation_keys_dir()
        )
        return render_template("admin_rotation.html", rows=rows)

    @app.post("/admin/exams/<exam_id>/rotate")
    @role_required("admin")
    def admin_rotate_exam(exam_id: str):
        """Open a rotation ceremony: k current holders must approve before any share changes."""
        conn = get_db()
        if exam_store.get_exam(exam_id) is None:
            abort(404)
        extras: list[int] = []
        for value in request.form.getlist("extra_holders"):
            if not value.isdigit():
                abort(400)
            extras.append(int(value))
        raw_threshold = request.form.get("new_threshold", "").strip()
        if raw_threshold and not raw_threshold.isdigit():
            abort(400)
        try:
            ceremony = rotation_flow.start_ceremony(
                conn, rotation_flow.get_ceremonies(current_app), exam_id=exam_id,
                admin_username=current_user.username, keys_dir=_rotation_keys_dir(),
                extra_holder_ids=extras, new_threshold=int(raw_threshold) if raw_threshold else None,
            )
        except share_flow.ShareRefused as refused:
            log_event(conn, current_user.username, "rotation_refused", {"exam_id": exam_id, "reason": refused.reason})
            flash(refused.message, "danger")
            return redirect(url_for("admin_rotations"))
        flash(
            f"Ceremony opened for exam {exam_id}. {ceremony.quorum} current holders must approve "
            "(each on their own login). Nothing changes until then.",
            "success",
        )
        return redirect(url_for("admin_rotations"))

    @app.post("/admin/exams/<exam_id>/rotate/cancel")
    @role_required("admin")
    def admin_rotation_cancel(exam_id: str):
        """Close an open ceremony and forget every approval held for it."""
        cancelled = rotation_flow.cancel_ceremony(
            get_db(), rotation_flow.get_ceremonies(current_app), exam_id, current_user.username
        )
        flash("Ceremony cancelled." if cancelled else "No ceremony was open for this exam.", "info")
        return redirect(url_for("admin_rotations"))
