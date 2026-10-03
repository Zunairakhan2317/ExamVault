import re
import time

import pyotp

from auth.passwords import hash_password
from auth.totp import new_secret, protect_secret, unprotect_secret
from web.app import create_app
from web.db import get_connection

TOTP_KEY = "11" * 32
PASSWORD = "Tr1cky-Exam-Vault!"


def make_config(tmp_path, **extra):
    cfg = {
        "TESTING": True,
        "SKIP_DOTENV": True,
        "SECRET_KEY": "test-secret-key-not-for-production",
        "TOTP_ENCRYPTION_KEY": TOTP_KEY,
        "DATABASE_PATH": str(tmp_path / "test.db"),
        "AUDIT_SIGNING_KEY_PATH": str(tmp_path / "keys" / "audit.pem"),
        "WTF_CSRF_ENABLED": False,
        "RATELIMIT_ENABLED": False,
    }
    cfg.update(extra)
    return cfg


def make_user(app, username, role="admin", password=PASSWORD, with_totp=True, active=1):
    secret = new_secret()
    blob = protect_secret(secret, app.config["TOTP_KEY"], username) if with_totp else None
    conn = get_connection(app.config["DATABASE_PATH"])
    conn.execute(
        "INSERT INTO users (username, role, password_hash, totp_secret_encrypted, is_active) "
        "VALUES (?, ?, ?, ?, ?)",
        (username, role, hash_password(password), blob, active),
    )
    conn.commit()
    conn.close()
    return secret


def db_value(app, sql, params=()):
    conn = get_connection(app.config["DATABASE_PATH"])
    try:
        return conn.execute(sql, params).fetchone()
    finally:
        conn.close()


def audit_text(app):
    conn = get_connection(app.config["DATABASE_PATH"])
    try:
        return str([tuple(r) for r in conn.execute("SELECT * FROM audit_entries ORDER BY id")])
    except Exception:
        return ""
    finally:
        conn.close()


def login_fully(client, secret, username="admin1", password=PASSWORD):
    first = client.post("/login", data={"username": username, "password": password})
    assert first.status_code == 302
    return client.post("/login/2fa", data={"code": pyotp.TOTP(secret).now()})


def test_login_page_renders_and_2fa_needs_pending_session(tmp_path):
    client = create_app(make_config(tmp_path)).test_client()
    page = client.get("/login")
    assert page.status_code == 200 and b"Username" in page.data and b"Password" in page.data
    assert b'name="csrf_token"' in page.data
    for path in ("/login/2fa", "/enroll-2fa"):
        response = client.get(path)
        assert response.status_code == 302 and response.headers["Location"].endswith("/login")


def test_full_login_reaches_dashboard_and_is_logged(tmp_path):
    app = create_app(make_config(tmp_path))
    secret = make_user(app, "admin1", "admin")
    client = app.test_client()
    first = client.post("/login", data={"username": "admin1", "password": PASSWORD})
    assert first.status_code == 302 and first.headers["Location"].endswith("/login/2fa")
    second = client.post("/login/2fa", data={"code": pyotp.TOTP(secret).now()})
    assert second.status_code == 302 and second.headers["Location"].endswith("/dashboard")
    page = client.get("/dashboard")
    assert page.status_code == 200 and b"admin1" in page.data and b"Total users" in page.data
    assert "login_success" in audit_text(app)
    assert db_value(app, "SELECT totp_last_step FROM users WHERE username = 'admin1'")[0] is not None


def test_wrong_password_is_generic_counted_and_logged(tmp_path):
    app = create_app(make_config(tmp_path))
    make_user(app, "admin1", "admin")
    client = app.test_client()
    response = client.post("/login", data={"username": "admin1", "password": "wrong-password-123"})
    assert response.status_code == 200 and b"Invalid username or password" in response.data
    assert client.get("/dashboard").status_code == 302
    assert db_value(app, "SELECT COUNT(*) FROM login_attempts WHERE success = 0")[0] == 1
    assert "login_failed" in audit_text(app)


def test_unknown_username_gets_the_same_message(tmp_path):
    app = create_app(make_config(tmp_path))
    response = app.test_client().post("/login", data={"username": "ghost", "password": "whatever-123456"})
    assert response.status_code == 200 and b"Invalid username or password" in response.data
    assert db_value(app, "SELECT COUNT(*) FROM login_attempts WHERE username = 'ghost'")[0] == 1


def test_sixth_attempt_is_blocked_even_with_correct_password(tmp_path):
    app = create_app(make_config(tmp_path))
    make_user(app, "locky", "admin")
    client = app.test_client()
    for _ in range(5):
        client.post("/login", data={"username": "locky", "password": "wrong-password-123"})
    response = client.post("/login", data={"username": "locky", "password": PASSWORD})
    assert response.status_code == 200 and b"Too many attempts" in response.data
    assert "Location" not in response.headers
    assert "account_locked" in audit_text(app)


def test_wrong_totp_code_is_refused_and_counted(tmp_path):
    app = create_app(make_config(tmp_path))
    make_user(app, "admin1", "admin")
    client = app.test_client()
    client.post("/login", data={"username": "admin1", "password": PASSWORD})
    response = client.post("/login/2fa", data={"code": "000000"})
    assert response.status_code == 200 and b"Invalid or expired code" in response.data
    assert client.get("/dashboard").status_code == 302
    assert db_value(app, "SELECT COUNT(*) FROM login_attempts WHERE success = 0")[0] == 1
    assert "totp_failed" in audit_text(app)


def test_totp_code_cannot_be_reused(tmp_path):
    app = create_app(make_config(tmp_path))
    secret = make_user(app, "admin1", "admin")
    code = pyotp.TOTP(secret).now()
    first = app.test_client()
    first.post("/login", data={"username": "admin1", "password": PASSWORD})
    assert first.post("/login/2fa", data={"code": code}).status_code == 302
    second = app.test_client()
    second.post("/login", data={"username": "admin1", "password": PASSWORD})
    response = second.post("/login/2fa", data={"code": code})
    assert response.status_code == 200 and b"Invalid or expired code" in response.data


def test_enrolment_stores_only_an_encrypted_secret(tmp_path):
    app = create_app(make_config(tmp_path))
    make_user(app, "newbie", "invigilator", with_totp=False)
    client = app.test_client()
    first = client.post("/login", data={"username": "newbie", "password": PASSWORD})
    assert first.headers["Location"].endswith("/enroll-2fa")
    page = client.get("/enroll-2fa")
    assert b"data:image/png;base64," in page.data
    secret = re.search(r'id="secret">([A-Z2-7]+)<', page.get_data(as_text=True)).group(1)
    done = client.post("/enroll-2fa", data={"code": pyotp.TOTP(secret).now()})
    assert done.status_code == 302 and done.headers["Location"].endswith("/dashboard")
    row = db_value(app, "SELECT totp_secret_encrypted, totp_last_step FROM users WHERE username = 'newbie'")
    blob = bytes(row[0])
    assert secret.encode() not in blob and row[1] is not None
    assert unprotect_secret(blob, app.config["TOTP_KEY"], "newbie") == secret
    assert client.get("/dashboard").status_code == 200
    assert "totp_enrolled" in audit_text(app)


def test_enrolment_with_wrong_code_saves_nothing(tmp_path):
    app = create_app(make_config(tmp_path))
    make_user(app, "newbie", "invigilator", with_totp=False)
    client = app.test_client()
    client.post("/login", data={"username": "newbie", "password": PASSWORD})
    client.get("/enroll-2fa")
    response = client.post("/enroll-2fa", data={"code": "000000"})
    assert response.status_code == 200 and b"Code did not match" in response.data
    assert db_value(app, "SELECT totp_secret_encrypted FROM users WHERE username = 'newbie'")[0] is None


def test_inactive_user_cannot_login(tmp_path):
    app = create_app(make_config(tmp_path))
    make_user(app, "old1", "admin", active=0)
    response = app.test_client().post("/login", data={"username": "old1", "password": PASSWORD})
    assert response.status_code == 200 and b"Invalid username or password" in response.data


def test_pending_session_expires(tmp_path):
    app = create_app(make_config(tmp_path))
    make_user(app, "admin1", "admin")
    client = app.test_client()
    client.post("/login", data={"username": "admin1", "password": PASSWORD})
    with client.session_transaction() as sess:
        sess["pending_ts"] = time.time() - 1000
    response = client.get("/login/2fa")
    assert response.status_code == 302 and response.headers["Location"].endswith("/login")


def test_logout_needs_post_and_ends_the_session(tmp_path):
    app = create_app(make_config(tmp_path))
    secret = make_user(app, "admin1", "admin")
    client = app.test_client()
    login_fully(client, secret)
    assert client.get("/logout").status_code == 405
    assert client.post("/logout").status_code == 302
    assert client.get("/dashboard").status_code == 302
    assert "logout" in audit_text(app)


def test_dashboard_menu_depends_on_role(tmp_path):
    app = create_app(make_config(tmp_path))
    admin_secret = make_user(app, "admin1", "admin")
    inv_secret = make_user(app, "inv1", "invigilator")
    admin_client, inv_client = app.test_client(), app.test_client()
    login_fully(admin_client, admin_secret, "admin1")
    login_fully(inv_client, inv_secret, "inv1")
    assert b"/admin/users" in admin_client.get("/dashboard").data
    inv_page = inv_client.get("/dashboard")
    assert inv_page.status_code == 200 and b"/admin/users" not in inv_page.data


def test_csrf_blocks_a_post_without_token(tmp_path):
    app = create_app(make_config(tmp_path, WTF_CSRF_ENABLED=True))
    response = app.test_client().post("/login", data={"username": "a", "password": "b"})
    assert response.status_code == 400


def test_login_is_rate_limited_per_ip(tmp_path):
    app = create_app(make_config(tmp_path, RATELIMIT_ENABLED=True))
    client = app.test_client()
    for _ in range(5):
        assert client.post("/login", data={"username": "ghost", "password": "x"}).status_code == 200
    assert client.post("/login", data={"username": "ghost", "password": "x"}).status_code == 429
    assert "rate_limited" in audit_text(app)