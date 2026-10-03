import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest
from flask_login import login_user

from audit.hashchain import verify_hashchain
from auth.rbac import role_required
from web.app import create_app
from web.audit_log import log_event
from web.db import get_connection, get_db, init_db
from web.user import load_user_by_id

TOTP_KEY = "11" * 32  # 64 hex characters


def make_config(tmp_path, **extra):
    cfg = {
        "TESTING": True,
        "SKIP_DOTENV": True,
        "SECRET_KEY": "test-secret-key-not-for-production",
        "TOTP_ENCRYPTION_KEY": TOTP_KEY,
        "DATABASE_PATH": str(tmp_path / "test.db"),
        "AUDIT_SIGNING_KEY_PATH": str(tmp_path / "keys" / "audit.pem"),
    }
    cfg.update(extra)
    return cfg


def add_test_routes(app):
    @app.get("/_t/login/<role>")
    def _t_login(role):
        conn = get_db()
        conn.execute(
            "INSERT OR IGNORE INTO users (username, role, password_hash) VALUES (?, ?, ?)",
            (f"{role}1", role, "x"),
        )
        conn.commit()
        row = conn.execute("SELECT id FROM users WHERE username = ?", (f"{role}1",)).fetchone()
        login_user(load_user_by_id(conn, row["id"]))
        return "ok"

    @app.get("/_t/admin-only")
    @role_required("admin")
    def _t_admin():
        return "admin ok"


def audit_rows(app):
    conn = get_connection(app.config["DATABASE_PATH"])
    try:
        return [tuple(r) for r in conn.execute("SELECT * FROM audit_entries ORDER BY id")]
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


def test_boots_and_schema(tmp_path):
    app = create_app(make_config(tmp_path))
    conn = get_connection(app.config["DATABASE_PATH"])
    init_db(conn)
    init_db(conn)
    tables = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for name in ("users", "share_submissions", "copies", "tardos_params", "used_nonces",
                 "honeytoken_events", "certificates", "login_attempts"):
        assert name in tables
    assert "audit_entries" not in tables
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
    assert {"id", "username", "role", "password_hash", "totp_secret_encrypted", "schnorr_public_y",
            "cert_serial", "is_active", "created_at", "totp_last_step"} <= cols
    conn.close()
    assert app.test_client().get("/").status_code == 200


def test_security_headers(tmp_path):
    response = create_app(make_config(tmp_path)).test_client().get("/")
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"


def test_session_cookie_flags_and_lifetime(tmp_path):
    app = create_app(make_config(tmp_path))
    add_test_routes(app)
    response = app.test_client().get("/_t/login/admin")
    cookies = " ".join(response.headers.getlist("Set-Cookie")).lower()
    assert "httponly" in cookies and "samesite=lax" in cookies
    assert app.config["PERMANENT_SESSION_LIFETIME"] == timedelta(minutes=15)


def test_404_is_generic(tmp_path):
    response = create_app(make_config(tmp_path)).test_client().get("/nope")
    text = response.get_data(as_text=True)
    assert response.status_code == 404 and "Page not found" in text and "Traceback" not in text


def test_401_redirects_and_is_logged(tmp_path):
    app = create_app(make_config(tmp_path))
    add_test_routes(app)
    response = app.test_client().get("/_t/admin-only?password=hunter2-secret")
    assert response.status_code == 302 and response.headers["Location"].endswith("/login")
    rows = audit_rows(app)
    assert len(rows) == 1 and "hunter2-secret" not in str(rows)


def test_403_is_logged_and_chain_is_valid(tmp_path):
    app = create_app(make_config(tmp_path))
    add_test_routes(app)
    client = app.test_client()
    client.get("/_t/login/invigilator")
    assert client.get("/_t/admin-only").status_code == 403
    assert len(audit_rows(app)) == 1
    conn = get_connection(app.config["DATABASE_PATH"])
    assert verify_hashchain(conn)
    conn.close()


def test_refuses_to_start_without_keys(tmp_path, monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.delenv("TOTP_ENCRYPTION_KEY", raising=False)
    cfg = make_config(tmp_path)
    del cfg["SECRET_KEY"]
    with pytest.raises(RuntimeError):
        create_app(cfg)
    cfg = make_config(tmp_path, TOTP_ENCRYPTION_KEY="abc")
    with pytest.raises(RuntimeError):
        create_app(cfg)


def test_audit_key_created_once_and_reused(tmp_path):
    cfg = make_config(tmp_path)
    create_app(cfg)
    key_path = Path(cfg["AUDIT_SIGNING_KEY_PATH"])
    pub_path = key_path.with_name("audit_public.pem")
    first, first_pub = key_path.read_bytes(), pub_path.read_bytes()
    assert b"PRIVATE KEY" in first
    create_app(cfg)
    assert key_path.read_bytes() == first and pub_path.read_bytes() == first_pub


def test_rate_limit_429_is_logged(tmp_path):
    app = create_app(make_config(tmp_path))
    limiter = app.extensions["examvault_limiter"]

    @app.get("/_t/limited")
    @limiter.limit("1 per minute")
    def _t_limited():
        return "ok"

    client = app.test_client()
    assert client.get("/_t/limited").status_code == 200
    assert client.get("/_t/limited").status_code == 429
    assert len(audit_rows(app)) == 1


def test_inactive_user_is_not_loaded(tmp_path):
    app = create_app(make_config(tmp_path))
    conn = get_connection(app.config["DATABASE_PATH"])
    conn.execute("INSERT INTO users (username, role, password_hash, is_active) VALUES ('old', 'admin', 'x', 0)")
    conn.commit()
    uid = conn.execute("SELECT id FROM users WHERE username = 'old'").fetchone()["id"]
    assert load_user_by_id(conn, uid) is None
    assert load_user_by_id(conn, "not-a-number") is None
    conn.close()


def test_log_event_drops_secret_keys(tmp_path):
    app = create_app(make_config(tmp_path))
    conn = get_connection(app.config["DATABASE_PATH"])
    log_event(conn, "u1", "test_event", {"password": "abc-secret", "path": "/p"})
    conn.close()
    rows = audit_rows(app)
    assert len(rows) == 1 and "abc-secret" not in str(rows) and "/p" in str(rows)