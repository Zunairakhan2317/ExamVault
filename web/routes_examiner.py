"""Examiner pages: upload exam, My Exams, exam detail (Frontend Brief pages 10-12) and the Layer 3
placeholders for the variants review (page 13) and the Leak Analyzer (page 20).

Security properties:
- The paper is encrypted (AES-GCM) and split (Shamir k-of-n with Feldman commitments) by the paper
  service; only the paper hash prefix and public metadata ever leave the upload route.
- The examiner's Ed25519 signing key is read from disk into memory for this one request only and is
  never copied, cached, logged or shown.
- The signature binds paper hash + exam id + share policy + the UTC release window, and the window is
  enforced later on the server's UTC clock (never the browser's).
- Uploading fails closed when the audit chain is tampered (503 banner, nothing is created).
- Every route is role-protected; every user-supplied value is HTML-escaped by Jinja2.
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from flask import Flask, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user

from auth.rbac import role_required
from crypto.services import paper_service
from tracing import analyzer as leak_analyzer
from web import copy_service, exam_store
from web.audit_log import ensure_audit_intact, log_event
from web.db import get_db

MAX_PAPER_BYTES = 10 * 1024 * 1024
ALLOWED_PAPER_SUFFIXES = {".pdf", ".txt"}
DEFAULT_K, DEFAULT_N = 3, 5
DEFAULT_KEYS_DIR = Path(__file__).resolve().parent.parent / "keys"
SIGNING_KEY_NAME = "examiner_signing.pem"
PROGRESS_STEPS = ["Hash", "Sign", "Encrypt", "Split key", "Wrap shares", "Done"]


def _keys_dir() -> Path:
    """Folder with the demo key files (config KEYS_DIR, default <project>/keys)."""
    return Path(current_app.config.get("KEYS_DIR") or DEFAULT_KEYS_DIR)


def _load_public_rsa_key(path: Path) -> rsa.RSAPublicKey:
    """Load a holder's RSA public key (the private half never reaches the server)."""
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("Key must be an RSA public key")
    return key


def _load_signing_key(path: Path) -> ed25519.Ed25519PrivateKey:
    """Read the examiner's Ed25519 signing key into memory for this request only."""
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("Key must be an Ed25519 private key")
    return key


def _examiner_public_key() -> ed25519.Ed25519PublicKey | None:
    """The examiner's public key used to show 'Signature verified' (None if it is not available)."""
    path = (
        current_app.config.get("EXAMINER_PUBLIC_KEY_PATH")
        or os.environ.get("EXAMINER_PUBLIC_KEY_PATH")
        or _keys_dir() / "examiner_signing_public.pem"
    )
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except (OSError, ValueError):
        return None
    return key if isinstance(key, ed25519.Ed25519PublicKey) else None


def _active_invigilators(conn) -> list:
    """Active invigilators who can be chosen as key holders."""
    return conn.execute(
        "SELECT id, username FROM users WHERE role = 'invigilator' AND is_active = 1 ORDER BY username"
    ).fetchall()


def _parse_utc_local(value: str) -> datetime | None:
    """Parse a datetime-local value as UTC (the form says: time runs on the server's UTC clock)."""
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def _window_instant(utc_value: str, typed_value: str) -> datetime | None:
    """The window endpoint as a UTC instant.

    The upload page converts the examiner's LOCAL time to UTC in the browser and sends it in a hidden
    field (ISO text ending in Z). Without it (no JavaScript) the typed value is read as UTC, as the page
    says. Either way the window is stored in UTC and enforced on the server clock only.
    """
    if utc_value.strip():
        try:
            parsed = datetime.fromisoformat(utc_value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None else None
    return _parse_utc_local(typed_value)


def _int_field(value: str, default: int) -> int | None:
    """Read a small positive integer from a form field (default when empty, None when invalid)."""
    text = (value or "").strip()
    if not text:
        return default
    return int(text) if text.isdigit() and len(text) <= 3 else None


def register(app: Flask) -> None:
    """Attach the examiner routes (pages 10-12) and the Layer 3 placeholders (pages 13 and 20)."""

    def _form_page(conn, form, error: str | None = None, result: dict | None = None, status: int = 200):
        """Render the upload page again with what the user typed (never the file) and one error."""
        return render_template(
            "examiner_upload.html",
            holders=_active_invigilators(conn),
            form=form,
            error=error,
            result=result,
            steps=PROGRESS_STEPS,
        ), status

    @app.get("/examiner/upload")
    @role_required("examiner")
    def examiner_upload():
        """Upload form: exam info, UTC window, paper file, variants link, k and n, holders."""
        form = {"k": DEFAULT_K, "n": DEFAULT_N, "holders": []}
        return _form_page(get_db(), form)

    @app.post("/examiner/upload")
    @role_required("examiner")
    def examiner_upload_post():
        """Validate, then hash, sign, encrypt, split the key and wrap one share per holder."""
        conn = get_db()
        ensure_audit_intact(conn)  # fail closed before anything is created
        title = request.form.get("exam_title", "").strip()
        subject = request.form.get("subject", "").strip()
        k = _int_field(request.form.get("k", ""), DEFAULT_K)
        n = _int_field(request.form.get("n", ""), DEFAULT_N)
        selected = {int(x) for x in request.form.getlist("holder") if x.isdigit()}
        form = {
            "title": title, "subject": subject, "start": request.form.get("window_start", ""),
            "end": request.form.get("window_end", ""), "k": k if k is not None else request.form.get("k", ""),
            "n": n if n is not None else request.form.get("n", ""), "holders": selected,
        }

        def refuse(message: str):
            return _form_page(conn, form, error=message, status=400)

        if not title or not subject:
            return refuse("Exam title and subject are required")
        start = _window_instant(request.form.get("window_start_utc", ""), form["start"])
        end = _window_instant(request.form.get("window_end_utc", ""), form["end"])
        if start is None or end is None:
            return refuse("Valid start and end date-times are required")
        if end <= start:
            return refuse("End time must be after start time")
        if k is None or n is None or n < 2:
            return refuse("k and n must be whole numbers (n is at least 2)")
        if k > n:
            return refuse("k cannot be greater than n")
        if k < 2:
            return refuse("k must be at least 2")
        upload = request.files.get("paper")
        if upload is None or not upload.filename:
            return refuse("A paper file must be uploaded")
        if Path(upload.filename).suffix.lower() not in ALLOWED_PAPER_SUFFIXES:
            return refuse("Only PDF or text files are allowed")
        content = upload.stream.read(MAX_PAPER_BYTES + 1)
        if len(content) > MAX_PAPER_BYTES:
            return refuse("File too large")
        if not content:
            return refuse("The paper file is empty")
        try:  # variants come from the paper itself: {first wording | second wording}
            paper_text = copy_service.extract_paper_text(content)
        except ValueError:
            return refuse("The paper could not be read. Upload a text-based PDF or a text file")
        if not paper_text.strip():  # for example a screenshot or scan saved as PDF: no text layer
            return refuse(
                "No readable text found in the paper. Upload a text-based PDF "
                "(not a scan or screenshot) or a text file"
            )
        slots = copy_service.parse_template(paper_text)
        if len(slots) > copy_service.MAX_SLOTS:
            return refuse(f"Too many variant slots (at most {copy_service.MAX_SLOTS})")

        allowed = {row["id"]: row["username"] for row in _active_invigilators(conn)}
        if len(selected) != n or not selected <= set(allowed):
            return refuse(f"Select exactly {n} holders")
        holder_ids = sorted(selected)

        holder_keys = []
        for holder_id in holder_ids:
            key_path = _keys_dir() / f"{allowed[holder_id]}_public.pem"
            try:
                holder_keys.append(_load_public_rsa_key(key_path))
            except (OSError, ValueError):
                return refuse(f"Missing or bad holder key for {allowed[holder_id]}; ask an admin")
        try:
            signing_key = _load_signing_key(_keys_dir() / SIGNING_KEY_NAME)
        except (OSError, ValueError):
            return refuse("Examiner signing key is missing or invalid")

        try:
            result = paper_service.create_exam(
                content, holder_keys, signing_key, start, end,
                exam_title=title, subject=subject, threshold=k,
            )
        except (TypeError, ValueError) as exc:
            return refuse(f"Exam could not be created: {exc}")
        exam_store.register_shares(
            conn, result["exam_id"], result["commitments"], holder_ids, result["wrapped_shares"]
        )
        try:
            copy_service.prepare_exam_variants(
                conn, copy_service.data_dir_for(current_app),
                copy_service.storage_key(copy_service.keys_dir_for(current_app)),
                result["exam_id"], slots, holder_ids,
            )
        except (OSError, sqlite3.Error):
            return _form_page(
                conn, form, status=500,
                error="The exam was created but its copies could not be prepared. Contact an admin.",
            )
        log_event(conn, current_user.username, "exam_created", {
            "exam_id": result["exam_id"], "title": title, "subject": subject,
            "k": result["threshold"], "n": result["num_shares"],
            "paper_sha256_prefix": result["paper_hash"].hex()[:16], "variant_slots": len(slots),
            "window_start": result["release_window_start"], "window_end": result["release_window_end"],
        })
        card = {
            "exam_id": result["exam_id"],
            "paper_hash": result["paper_hash"].hex()[:16],
            "signature_valid": paper_service.verify_exam_record(result["exam_id"], signing_key.public_key()),
            "k": result["threshold"], "n": result["num_shares"], "issued": len(result["wrapped_shares"]),
            "start": result["release_window_start"], "end": result["release_window_end"],
            "slots": len(slots), "min_slots": copy_service.MIN_SLOTS,
        }
        return _form_page(conn, {"k": DEFAULT_K, "n": DEFAULT_N, "holders": []}, result=card)

    @app.post("/examiner/exams/<exam_id>/toggle")
    @role_required("examiner")
    def examiner_toggle_exam(exam_id: str):
        """Toggle exam active/inactive status."""
        conn = get_db()
        exam = exam_store.get_exam(exam_id)
        if exam is None:
            abort(404)
        is_active = exam_store.toggle_exam_active(exam_id, conn)
        if is_active:
            flash(f"Exam '{exam.get('exam_title', '(untitled)')}' has been activated.", "success")
            log_event(conn, current_user.username, "exam_activated", {"exam_id": exam_id})
        else:
            flash(f"Exam '{exam.get('exam_title', '(untitled)')}' has been deactivated.", "info")
            log_event(conn, current_user.username, "exam_deactivated", {"exam_id": exam_id})
        return redirect(url_for("examiner_exams"))

    @app.get("/examiner/exams")
    @role_required("examiner")
    def examiner_exams():
        """My exams: title, window, status badge, k-of-n and shares submitted."""
        conn = get_db()
        pending = current_app.extensions.get("examvault_pending")
        return render_template("examiner_exams.html", exams=exam_store.examiner_exams_list(conn, current_user.id, pending))

    @app.get("/examiner/exams/<exam_id>")
    @role_required("examiner")
    def examiner_exam_detail(exam_id: str):
        """Exam detail: info card, holders, copies and the last 10 audit entries for this exam."""
        conn = get_db()
        exam = exam_store.get_exam(exam_id)
        if exam is None:
            abort(404)
        pending = current_app.extensions.get("examvault_pending")
        view = exam_store.exam_view(conn, exam, current_user.id, pending)
        label, badge = exam_store.exam_status(conn, exam)
        public_key = _examiner_public_key()
        signature_ok = (
            paper_service.verify_exam_record(exam_id, public_key) if public_key is not None else None
        )
        released = conn.execute("SELECT released_at FROM exam_release WHERE exam_id = ?", (exam_id,)).fetchone()
        return render_template(
            "examiner_exam_detail.html",
            exam=exam, view=view, status_label=label, status_badge=badge, signature_ok=signature_ok,
            released_at=released["released_at"] if released else None,
            holders=exam_store.exam_holder_rows(conn, exam_id, pending),
            copies=exam_store.exam_copy_rows(conn, exam_id),
            events=exam_store.exam_recent_events(conn, exam_id, 10),
        )

    def _variant_storage():
        """(data folder, storage key) for the encrypted variants of this server."""
        return (
            copy_service.data_dir_for(current_app),
            copy_service.storage_key(copy_service.keys_dir_for(current_app)),
        )

    @app.get("/examiner/variants")
    @role_required("examiner")
    def examiner_variants():
        """Page 13: the variant slots read from an exam's uploaded paper, with review status."""
        conn = get_db()
        pending = current_app.extensions.get("examvault_pending")
        exams = exam_store.examiner_exams_list(conn, current_user.id, pending)
        wanted = request.args.get("exam_id")
        if wanted is not None and all(e["exam_id"] != wanted for e in exams):
            abort(404)
        selected = next((e for e in exams if e["exam_id"] == wanted), exams[0] if exams else None)
        slots, flt = None, request.args.get("filter", "all")
        if flt not in ("all", "reviewed", "doubtful"):
            flt = "all"
        if selected is not None:
            data_dir, key = _variant_storage()
            slots = copy_service.load_variant_slots(data_dir, key, selected["exam_id"])
        total = len(slots) if slots is not None else 0
        shown = [
            s for s in (slots or [])
            if flt == "all" or (flt == "reviewed" and s["status"] == "ok") or (flt == "doubtful" and s["status"] == "doubtful")
        ]
        variant_count = max(len(s["variants"]) for s in (slots or [])) if slots else 0
        variant_labels = [f"Variant {i + 1}" for i in range(variant_count)]
        return render_template(
            "examiner_variants.html", exams=exams, selected=selected, slots=slots, shown=shown, total=total,
            minimum=copy_service.MIN_SLOTS, percent=min(100, total * 100 // copy_service.MIN_SLOTS), flt=flt,
            variant_count=variant_count, variant_labels=variant_labels,
        )

    @app.post("/examiner/variants/<exam_id>/review")
    @role_required("examiner")
    def examiner_variant_review(exam_id: str):
        """Mark one slot reviewed (OK) or doubtful; recorded in the audit log."""
        conn = get_db()
        if exam_store.get_exam(exam_id) is None:
            abort(404)
        action = request.form.get("action", "")
        slot_text = request.form.get("slot_id", "")
        if action not in ("reviewed", "doubtful") or not slot_text.isdigit():
            abort(400)
        ensure_audit_intact(conn)
        data_dir, key = _variant_storage()
        status = "ok" if action == "reviewed" else "doubtful"
        if not copy_service.set_slot_review(data_dir, key, exam_id, int(slot_text), status, current_user.username):
            abort(404)
        log_event(conn, current_user.username, "variant_reviewed",
                  {"exam_id": exam_id, "slot_id": int(slot_text), "status": status})
        return redirect(url_for("examiner_variants", exam_id=exam_id, filter=request.form.get("filter", "all")), 303)

    def _suspects_for_exam(conn: sqlite3.Connection, exam_id: str) -> list[tuple[str, list[int]]] | None:
        """Return (username, code) pairs for every invigilator holding a copy of this exam.

        Revoked or disabled holders are kept on purpose: a leaker may well have been cut off since.
        """
        code_rows = conn.execute(
            "SELECT u.username, c.slot_pattern, c.user_id FROM copies c "
            "JOIN users u ON u.id = c.user_id WHERE c.exam_id = ? AND u.role = 'invigilator' "
            "ORDER BY c.user_id",
            (exam_id,),
        ).fetchall()
        if not code_rows:
            return None
        return [(row["username"], [int(bit) for bit in row["slot_pattern"]]) for row in code_rows]

    def _biases_for_exam(conn: sqlite3.Connection, exam_id: str) -> list[float] | None:
        """Return the Tardos bias vector for an exam, or None when the exam has no tracing data."""
        row = conn.execute(
            "SELECT bias_vector_encrypted FROM tardos_params WHERE exam_id = ?", (exam_id,)
        ).fetchone()
        if row is None:
            return None
        from crypto.aes_gcm import decrypt  # imported late to avoid circular imports
        key = copy_service.storage_key(copy_service.keys_dir_for(current_app))
        try:
            blob = bytes(row["bias_vector_encrypted"])
            plain = decrypt(blob[:12], blob[12:], key, f"tardos:{exam_id}".encode("utf-8"))
            return json.loads(plain.decode("utf-8"))
        except (ValueError, RuntimeError, KeyError, IndexError, TypeError, sqlite3.Error):
            return None

    @app.route("/tracing/analyze", methods=["GET", "POST"])
    @role_required("examiner", "auditor")
    def tracing_analyze():
        """Page 20 (Layer 3): examiner and auditor, analyze a leaked copy of an exam.

        Accepts pasted text or an uploaded text/PDF file, matches the wording against the
        variant slots of the selected exam, runs the Tardos accusation scores on every
        invigilator who holds a copy, and ranks them by score with confidence labels.
        """
        exam = exam_store.get_exam(request.args.get("exam_id"))
        if not exam:
            # No exam selected yet — render the page so the user can pick one from their exams
            exam = None
        conn = get_db()
        results, errors = None, []
        if exam is not None:
            try:
                suspects = _suspects_for_exam(conn, exam["exam_id"])
                biases = _biases_for_exam(conn, exam["exam_id"])
                if suspects is None:
                    errors.append("No copies of this exam were issued, so there is nothing to trace.")
                elif biases is None:
                    errors.append("Variant slots were stored but the tracing parameters are missing; re-release the exam.")
            except Exception as exc:  # no tracing tables yet, or storage issue
                errors.append(f"Could not load tracing data: {exc}")

        if request.method == "POST":
            if exam is None:
                flash("Select an exam to analyze", "danger")
            elif errors:
                flash("Leak analysis is unavailable for this exam: " + "; ".join(errors), "danger")
            else:
                leaked_text, extract_error = _read_leak_input(request)
                if extract_error:
                    flash(extract_error, "danger")
                elif leaked_text:
                    try:
                        slots = copy_service.load_variant_slots(
                            copy_service.data_dir_for(current_app),
                            copy_service.storage_key(copy_service.keys_dir_for(current_app)),
                            exam["exam_id"],
                        )
                        if slots is None:
                            flash("No variant slots found for this exam.", "danger")
                        else:
                            results = leak_analyzer.analyze_leak(
                                leaked_text,
                                slots,
                                [s[0] for s in suspects],
                                [s[1] for s in suspects],
                                biases,
                            )
                        try:
                            log_event(conn, current_user.username, "leak_analyzed", {
                                "exam_id": exam["exam_id"], "suspects": len(suspects), "ranked": len(results),
                            })
                        except ValueError:
                            pass
                    except Exception as exc:
                        flash(f"Analysis failed: {exc}", "danger")
        return render_template("tracing_analyze.html", exam=exam, results=results, errors=errors)

    def _read_leak_input(request) -> tuple[str, str | None]:
        """Return the submitted leaked text, or an error message if the input is invalid."""
        file = request.files.get("leak_file")
        if file and file.filename:
            if not file.filename.lower().endswith((".txt", ".pdf")):
                return "", "Leak files must be a text (.txt) or PDF file"
            try:
                content = file.stream.read(copy_service.MAX_PAPER_BYTES + 1)
            except Exception:
                return "", "The leak file could not be read"
            if len(content) > copy_service.MAX_PAPER_BYTES:
                return "", "Leak file is too large"
            if not content:
                return "", "The leak file is empty"
            try:
                return copy_service.extract_paper_text(content), None
            except ValueError:
                return "", "The leak file could not be read. Upload a text-based PDF or a text file"
        text = request.form.get("leak_text", "").strip()
        if text:
            return text, None
        if file and not file.filename:
            return "", "No file selected"
        return "", ""

    def _issue_copies(exam_id: str, plaintext: bytes) -> None:
        """Release handler: build every holder's encrypted PDF from the released paper (plan 5.4).

        Runs inside the request that released the paper; the paper exists only in memory here.
        """
        conn = get_db()
        exam = exam_store.get_exam(exam_id) or {}
        data_dir, key = _variant_storage()
        written = copy_service.build_copies(conn, data_dir, key, exam_id, plaintext, exam.get("exam_title", ""))
        log_event(conn, "system", "copies_issued", {"exam_id": exam_id, "count": written})

    app.extensions.setdefault("examvault_release_handlers", []).append(_issue_copies)
