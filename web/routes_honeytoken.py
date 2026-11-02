"""Honeytoken pages (plan 7.2): /files (with the decoy), /files/download/<id>, /admin/alerts and reinstate."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from flask import Flask, Response, abort, flash, redirect, render_template, request, session
from flask_login import current_user, logout_user

from auth.rbac import role_required
from demo import honeytoken
from web import exam_store
from web.audit_log import log_event
from web.db import get_db

ALL_ROLES = ("admin", "examiner", "invigilator", "auditor")


def _real_files(conn: Any) -> list[dict[str, str]]:
    """Genuine items this user may open (links to pages that already exist), shown beside the decoy."""
    rows: list[dict[str, str]] = []
    if current_user.role == "examiner":
        for exam in exam_store._all_exam_rows():
            rows.append(
                {"name": f"Exam record - {exam.get('exam_title') or exam['exam_id']}", "location": "My exams",
                 "size": "-", "modified": "", "href": f"/examiner/exams/{exam['exam_id']}"}
            )
    elif current_user.role == "invigilator":
        for held in conn.execute(
            "SELECT DISTINCT exam_id FROM shares WHERE holder_user_id = ? AND is_current = 1", (current_user.id,)
        ).fetchall():
            exam = exam_store.get_exam(held["exam_id"])
            if exam is not None and exam_store.is_released(conn, held["exam_id"]):
                rows.append(
                    {"name": f"My exam copy - {exam.get('exam_title') or held['exam_id']}", "location": "My copies",
                     "size": "-", "modified": "", "href": f"/invigilator/copy/{held['exam_id']}"}
                )
    return rows


def register(app: Flask) -> None:
    @app.get("/files")
    @role_required(*ALL_ROLES)
    def files_list():
        conn = get_db()
        modified = (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%d")
        rows = _real_files(conn)
        rows.append(  # the decoy: looks like any other shared file
            {"name": honeytoken.DECOY_FILENAME, "location": "Shared / Exams-2026", "size": "212 KB",
             "modified": modified, "href": f"/files/download/{honeytoken.DECOY_FILE_ID}"}
        )
        return render_template("files.html", rows=rows)

    @app.get("/files/download/<file_id>")
    @role_required(*ALL_ROLES)
    def files_download(file_id: str):
        """The decoy route: ANY role (even admin) that requests it raises the alert."""
        if file_id != honeytoken.DECOY_FILE_ID:
            abort(404)
        conn = get_db()
        result = honeytoken.record_hit(conn, current_user.id, current_user.username, current_user.role, request.remote_addr)
        if result["suspended"]:
            logout_user()
            session.clear()
            flash("This account has been suspended pending a security review.", "danger")
            return redirect("/login")
        return Response(
            honeytoken.decoy_pdf_bytes(), mimetype="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{honeytoken.DECOY_FILENAME}"'},
        )

    @app.get("/admin/alerts")
    @role_required("admin", "auditor")
    def admin_alerts():
        return render_template("admin_alerts.html", events=honeytoken.list_events(get_db()))

    @app.post("/admin/alerts/<int:event_id>/reinstate")
    @role_required("admin")
    def admin_alert_reinstate(event_id: int):
        outcome = honeytoken.reinstate(get_db(), event_id, current_user.username)
        messages = {
            "ok": ("Account reinstated after review.", "success"),
            "unknown": ("Unknown alert.", "warning"),
            "admin": ("Admin accounts are never suspended by the decoy.", "info"),
            "revoked": ("Not reinstated: this user's certificate is revoked.", "danger"),
        }
        text, category = messages[outcome]
        flash(text, category)
        return redirect("/admin/alerts")
