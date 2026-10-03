"""ExamVault Flask application factory (Plan Sections 2 and 8)."""
from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from dotenv import load_dotenv
from flask import Flask, redirect, render_template, request, session
from flask_login import LoginManager, current_user
from flask_wtf.csrf import CSRFProtect

from audit.daily_root import configure_audit_signing_keys
from auth import lockout, rbac
from web.audit_log import log_event
from web.db import close_db, get_connection, get_db, init_db
from web.user import load_user_by_id

_INTERNAL_KEYS = {"SKIP_DOTENV", "SECRET_KEY", "TOTP_ENCRYPTION_KEY"}
_ERROR_TEXT = {
    403: ("Access denied", "Aap ke role ko is page ki ijazat nahi."),
    404: ("Page not found", ""),
    429: ("Too many requests", "Thori der baad try karo."),
    500: ("Something went wrong", ""),
}
_CSP = (
    "default-src 'self'; "
    "style-src 'self' https://cdn.jsdelivr.net; "
    "script-src 'self' https://cdn.jsdelivr.net; "
    "img-src 'self' data:; form-action 'self'; frame-ancestors 'none'"
)


def _parse_totp_key(value: str | None) -> bytes:
    """TOTP_ENCRYPTION_KEY must be 64 hex characters (32 bytes) for AES-256-GCM."""
    if not value:
        raise RuntimeError("TOTP_ENCRYPTION_KEY is missing. Set it in .env")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise RuntimeError("TOTP_ENCRYPTION_KEY must be 64 hex characters") from exc
    if len(raw) != 32:
        raise RuntimeError("TOTP_ENCRYPTION_KEY must be 64 hex characters")
    return raw


def _load_or_create_audit_key(path_str: str) -> Ed25519PrivateKey:
    """Load the persistent audit signing key, creating it on first start.

    The public key is written next to it so the standalone verifier can use it.
    Known limitation: the private key lives on the server.
    """
    path = Path(path_str)
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise RuntimeError("Audit signing key must be an Ed25519 key")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        key = Ed25519PrivateKey.generate()
        path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    path.with_name(path.stem + "_public.pem").write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return key


def create_app(config: dict | None = None) -> Flask:
    """Build the app. Refuses to start without SECRET_KEY and TOTP_ENCRYPTION_KEY."""
    cfg = dict(config or {})
    if not cfg.get("SKIP_DOTENV"):
        load_dotenv()

    def setting(name: str, default: str | None = None) -> str | None:
        value = cfg.get(name)
        if value in (None, ""):
            value = os.environ.get(name, default)
        return value

    secret_key = setting("SECRET_KEY")
    if not secret_key:
        raise RuntimeError("SECRET_KEY is missing. Set it in .env")
    totp_key = _parse_totp_key(setting("TOTP_ENCRYPTION_KEY"))
    db_path = setting("DATABASE_PATH", "data/examvault.db")
    audit_key_path = setting("AUDIT_SIGNING_KEY_PATH", "keys/audit_ed25519.pem")

    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=secret_key,
        TOTP_KEY=totp_key,
        DATABASE_PATH=db_path,
        AUDIT_SIGNING_KEY_PATH=audit_key_path,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=False,
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
        SESSION_REFRESH_EACH_REQUEST=True,
        MAX_CONTENT_LENGTH=10 * 1024 * 1024,
    )
    app.config.update({k: v for k, v in cfg.items() if k not in _INTERNAL_KEYS})

    conn = get_connection(db_path)
    try:
        init_db(conn)
    finally:
        conn.close()

    private_key = _load_or_create_audit_key(audit_key_path)
    configure_audit_signing_keys(private_key, private_key.public_key())

    CSRFProtect(app)
    login_manager = LoginManager()
    login_manager.init_app(app)

    @login_manager.user_loader
    def _load_user(user_id: str):
        return load_user_by_id(get_db(), user_id)

    app.extensions["examvault_limiter"] = lockout.create_limiter(app)
    app.teardown_appcontext(close_db)

    def _actor() -> str:
        return str(current_user.get_id()) if current_user.is_authenticated else "anonymous"

    def _on_denied(info: dict) -> None:
        required = info.get("required")
        if not isinstance(required, str):
            required = sorted(str(r) for r in (required or []))
        log_event(
            get_db(),
            str(info.get("user_id") or "anonymous"),
            "access_denied",
            {
                "path": info.get("path"),
                "method": info.get("method"),
                "role": info.get("role"),
                "required": required,
                "reason": info.get("reason"),
            },
        )

    rbac.set_denied_handler(_on_denied)

    @app.before_request
    def _permanent_session() -> None:
        session.permanent = True

    @app.after_request
    def _security_headers(response):
        response.headers["Content-Security-Policy"] = _CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def _error_page(code: int):
        title, line = _ERROR_TEXT[code]
        return render_template("error.html", code=code, title=title, line=line), code

    @app.errorhandler(401)
    def _unauthorized(_error):
        return redirect("/login")

    @app.errorhandler(403)
    def _forbidden(_error):
        return _error_page(403)

    @app.errorhandler(404)
    def _not_found(_error):
        return _error_page(404)

    @app.errorhandler(429)
    def _too_many(_error):
        try:
            log_event(
                get_db(), _actor(), "rate_limited",
                {"path": request.path, "method": request.method, "ip": request.remote_addr},
            )
        except Exception:  # never fail the response because logging failed
            app.logger.error("audit write failed for rate_limited")
        return _error_page(429)

    @app.errorhandler(500)
    def _server_error(_error):
        return _error_page(500)

    @app.get("/")
    def index():
        return "ExamVault is running"

    return app