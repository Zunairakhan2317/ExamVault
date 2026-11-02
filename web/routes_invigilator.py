"""Invigilator pages 14 to 16: countdown, submit key share, download copy (plan 4.6).

The decrypted paper is never stored here. Layer 3 (copy generation) will register a release handler in
app.extensions["examvault_release_handlers"] to build each invigilator's personal copy.
"""
from __future__ import annotations

import hmac
import io
import os
import secrets
import time
from pathlib import Path
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from flask import Flask, abort, current_app, flash, redirect, render_template, request, send_file, session
from flask_login import current_user

from auth.rbac import role_required
from auth.schnorr import verify_schnorr_proof
from crypto import pki
from web import copy_service, exam_store, rotation_flow, share_flow
from web.audit_log import log_event
from web.db import get_db

DEFAULT_EXAMINER_PUBLIC_KEY = "keys/examiner_signing_public.pem"

# Plan 4.7: the Schnorr proof of key possession stays OFF until its full UI exists (the invigilator is given the
# secret x once, and a local tool builds the proof for the submit-page fields). While False, nobody is blocked.
SCHNORR_ENABLED = False

# A share-submission page (nonce + timestamp) is only valid this long: shrinks the replay window.
NONCE_MAX_AGE_SECONDS = 300


def _examiner_key_loader() -> Callable[[], Ed25519PublicKey]:
    """Return a function that loads the examiner's Ed25519 public key (set EXAMINER_PUBLIC_KEY_PATH)."""
    path = Path(
        current_app.config.get("EXAMINER_PUBLIC_KEY_PATH")
        or os.environ.get("EXAMINER_PUBLIC_KEY_PATH")
        or DEFAULT_EXAMINER_PUBLIC_KEY
    )

    def load() -> Ed25519PublicKey:
        key = serialization.load_pem_public_key(path.read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("Examiner key must be Ed25519")
        return key

    return load


def register(app: Flask) -> None:
    """Attach pages 14 to 16 and create the in-memory pending store."""
    pending = share_flow.PendingShares()
    handlers: list[Callable[[str, bytes], None]] = []
    app.extensions["examvault_pending"] = pending
    app.extensions["examvault_release_handlers"] = handlers

    def _exam_or_404(exam_id: str) -> dict:
        exam = exam_store.get_exam(exam_id)
        if exam is None or exam_store.get_share_row(get_db(), exam_id, current_user.id) is None:
            abort(404)  # unknown exam, or this user is not a holder: same answer
        return exam

    def _view(exam: dict) -> dict:
        return exam_store.exam_view(get_db(), exam, current_user.id, pending)

    @app.get("/invigilator/exam/<exam_id>")
    @role_required("invigilator")
    def invigilator_exam(exam_id: str):
        ceremony = rotation_flow.get_ceremonies(current_app).get(exam_id)
        return render_template(
            "invigilator_exam.html", view=_view(_exam_or_404(exam_id)),
            rotation_open=ceremony is not None and current_user.id not in ceremony.approvals,
        )

    @app.route("/invigilator/rotation/<exam_id>", methods=["GET", "POST"])
    @role_required("invigilator")
    def rotation_approve(exam_id: str):
        """Approve a share rotation ceremony with your own private key (plan 3.7: k holders approve)."""
        exam = _exam_or_404(exam_id)
        conn = get_db()
        ceremonies = rotation_flow.get_ceremonies(current_app)
        if request.method == "POST":
            upload = request.files.get("keyfile")
            key_pem = upload.stream.read(share_flow.MAX_KEY_FILE_BYTES + 1) if upload else b""
            keys_dir = copy_service.keys_dir_for(current_app)
            try:
                result = rotation_flow.approve(
                    conn, ceremonies, pending, exam_id=exam_id, user_id=current_user.id,
                    username=current_user.username, key_pem=key_pem, keys_dir=keys_dir,
                    load_signing_key=lambda: rotation_flow.load_examiner_signing_key(keys_dir),
                )
            except share_flow.ShareRefused as refused:
                log_event(conn, current_user.username, "rotation_refused", {"exam_id": exam_id, "reason": refused.reason})
                flash(refused.message, "danger")
                return redirect(f"/invigilator/rotation/{exam_id}")
            if result["outcome"] == "rotated":
                flash("Rotation complete. The paper was re-keyed and new shares were issued.", "success")
                return redirect(f"/invigilator/exam/{exam_id}")
            flash(f"Approval recorded ({result['received']} of {result['needed']}).", "success")
            return redirect(f"/invigilator/rotation/{exam_id}")
        ceremony = ceremonies.get(exam_id)
        return render_template(
            "rotation_approve.html", view=_view(exam), ceremony=ceremony,
            approved=ceremony is not None and current_user.id in ceremony.approvals,
            received=len(ceremony.approvals) if ceremony else 0,
        )

    @app.route("/invigilator/submit-share/<exam_id>", methods=["GET", "POST"])
    @role_required("invigilator")
    def submit_share(exam_id: str):
        exam = _exam_or_404(exam_id)
        conn = get_db()
        if request.method == "GET":
            nonce = secrets.token_urlsafe(24)
            # Real server UTC time (never a random number, never a browser value). TEST_TIMESTAMP is test-only.
            timestamp = str(int(os.getenv("TEST_TIMESTAMP", "0")) or int(time.time()))
            session["share_nonce"] = {"exam": exam_id, "nonce": nonce, "timestamp": timestamp}
            return render_template("submit_share.html", view=_view(exam), nonce=nonce, timestamp=timestamp)

        expected = session.pop("share_nonce", None)
        submitted = request.form.get("nonce", "")
        if (
            not isinstance(expected, dict)
            or expected.get("exam") != exam_id
            or not hmac.compare_digest(str(expected.get("nonce", "")).encode(), submitted.encode())
        ):
            log_event(conn, current_user.username, "share_refused", {"exam_id": exam_id, "reason": "nonce_mismatch"})
            flash("Request expired. Please try again.", "warning")
            return redirect(f"/invigilator/submit-share/{exam_id}")

        # Replay window: the page that carried this nonce must be recent (server clock only).
        if not os.getenv("TEST_TIMESTAMP"):
            try:
                issued_at = int(str(expected.get("timestamp", "")))
            except ValueError:
                issued_at = 0
            if abs(int(time.time()) - issued_at) > NONCE_MAX_AGE_SECONDS:
                log_event(conn, current_user.username, "share_refused", {"exam_id": exam_id, "reason": "nonce_expired"})
                flash("Request expired. Please try again.", "warning")
                return redirect(f"/invigilator/submit-share/{exam_id}")

        # Verify Schnorr proof of key possession (plan 4.7), only when enabled and the user has a public y.
        user_row = conn.execute("SELECT schnorr_public_y FROM users WHERE id = ?", (current_user.id,)).fetchone()
        if SCHNORR_ENABLED and user_row and user_row["schnorr_public_y"] is not None:
            try:
                t_val = int(request.form.get("schnorr_t", "0"))
                s_val = int(request.form.get("schnorr_s", "0"))
                timestamp = str(expected.get("timestamp", ""))
                if not verify_schnorr_proof(int(user_row["schnorr_public_y"]), t_val, s_val, submitted, timestamp):
                    log_event(conn, current_user.username, "share_refused", {"exam_id": exam_id, "reason": "schnorr_verification_failed"})
                    flash("ZKP key possession proof failed.", "danger")
                    return redirect(f"/invigilator/exam/{exam_id}")
            except Exception:
                log_event(conn, current_user.username, "share_refused", {"exam_id": exam_id, "reason": "schnorr_parse_error"})
                flash("Invalid Schnorr proof parameters.", "danger")
                return redirect(f"/invigilator/exam/{exam_id}")

        upload = request.files.get("keyfile")
        key_pem = upload.stream.read(share_flow.MAX_KEY_FILE_BYTES + 1) if upload else b""
        try:
            result = share_flow.submit_share(
                conn, pending,
                exam_id=exam_id,
                user_id=current_user.id,
                username=current_user.username,
                key_pem=key_pem,
                nonce=submitted,
                load_admin_public_key=_examiner_key_loader(),
                release_handlers=handlers,
            )
        except share_flow.ShareRefused as refusal:
            flash(refusal.message, "danger")
            return redirect(f"/invigilator/exam/{exam_id}")
        if result["outcome"] == "released":
            flash("Share verified and accepted. Paper released.", "success")
        elif result["outcome"] == "release_failed":
            flash("Share accepted, but release failed. Contact admin.", "warning")
        else:
            flash("Share verified and accepted", "success")
        return redirect(f"/invigilator/exam/{exam_id}")

    def _copy_storage():
        """(data folder, storage key) for the encrypted copies of this server."""
        return (
            copy_service.data_dir_for(current_app),
            copy_service.storage_key(copy_service.keys_dir_for(current_app)),
        )

    @app.get("/invigilator/copy/<exam_id>")
    @role_required("invigilator")
    def invigilator_copy(exam_id: str):
        """Page 16: the holder's own copy (copy ID, file name, download button, download history)."""
        exam = _exam_or_404(exam_id)
        conn = get_db()
        view = _view(exam)
        row = copy_service.copy_info(conn, exam_id, current_user.id) if view["released"] else None
        return render_template(
            "copy_download.html", view=view,
            copy={"id": f"{row['id']:06d}", "file_name": f"exam_{exam_id[:8]}_copy.pdf", "ready": bool(row["file_path"])}
            if row is not None else None,
            history=exam_store.copy_download_history(conn, exam_id, current_user.username),
        )

    @app.get("/invigilator/copy/<exam_id>/download")
    @role_required("invigilator")
    def invigilator_copy_download(exam_id: str):
        """Give the holder their own PDF (decrypted only now): holder, released, not revoked, audited."""
        _exam_or_404(exam_id)
        conn = get_db()
        if not exam_store.is_released(conn, exam_id):
            abort(404)
        if not pki.user_certificate_ok(conn, current_user.id):  # certificate + CRL check (plan 6.6)
            log_event(conn, current_user.username, "copy_refused", {"exam_id": exam_id, "reason": "revoked"})
            abort(403)
        data_dir, key = _copy_storage()
        try:
            pdf = copy_service.load_copy_pdf(conn, data_dir, key, exam_id, current_user.id)
        except InvalidTag:  # the stored file was changed: refuse and record it
            log_event(conn, current_user.username, "copy_refused", {"exam_id": exam_id, "reason": "integrity_check_failed"})
            abort(500)
        if pdf is None:
            abort(404)
        log_event(conn, current_user.username, "copy_downloaded", {"exam_id": exam_id})
        response = send_file(
            io.BytesIO(pdf), mimetype="application/pdf", as_attachment=True,
            download_name=f"exam_{exam_id[:8]}_copy.pdf",
        )
        response.headers["Cache-Control"] = "no-store"
        return response
