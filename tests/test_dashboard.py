"""Dashboard (Frontend Brief page 5): welcome line, last login, alert banner, role cards."""
from tests.test_web_auth import db_value, login_fully, make_config, make_user
from web.app import create_app
from web.db import get_connection
from crypto.services import paper_service


def _login(tmp_path, role, username="u1"):
    """Isolate the paper service DB so the examiner dashboard shows zero exams."""
    paper_service.DATABASE_PATH = tmp_path / "paper.db"
    app = create_app(make_config(tmp_path))
    secret = make_user(app, username, role)
    client = app.test_client()
    login_fully(client, secret, username)
    return app, client


def _add_alert(app):
    conn = get_connection(app.config["DATABASE_PATH"])
    conn.execute(
        "INSERT INTO honeytoken_events (ts, user_id, ip, file_id) VALUES (?, ?, ?, ?)",
        ("2026-10-04T10:00:00Z", 1, "127.0.0.1", "decoy"),
    )
    conn.commit()
    conn.close()


def test_first_login_then_previous_login_is_shown(tmp_path):
    app = create_app(make_config(tmp_path))
    secret = make_user(app, "u1", "admin")
    first = app.test_client()
    login_fully(first, secret, "u1")
    assert b"Last login: first login" in first.get("/dashboard").data
    stored = db_value(app, "SELECT last_login_at FROM users WHERE username = 'u1'")[0]
    assert stored and stored.endswith("Z")
    # TOTP replay protection blocks the same 30s code, so reset the stored step for the second login
    conn = get_connection(app.config["DATABASE_PATH"])
    conn.execute("UPDATE users SET totp_last_step = NULL WHERE username = 'u1'")
    conn.commit()
    conn.close()
    second = app.test_client()
    login_fully(second, secret, "u1")
    assert stored[:19].replace("T", " ").encode() in second.get("/dashboard").data


def test_welcome_line_and_role_badge(tmp_path):
    _app, client = _login(tmp_path, "auditor")
    page = client.get("/dashboard").data
    assert b"Welcome, u1" in page and b"auditor" in page


def test_admin_cards_buttons_and_no_banner_without_alerts(tmp_path):
    _app, client = _login(tmp_path, "admin")
    page = client.get("/dashboard").data
    for text in (b"Total users", b"Active exams", b"Revoked certificates", b"Open alerts",
                 b"Add user", b"Key rotation"):
        assert text in page
    assert b"Security alert" not in page


def test_alert_banner_and_red_card_for_admin_and_auditor_only(tmp_path):
    app, admin = _login(tmp_path, "admin", "adm")
    _add_alert(app)
    page = admin.get("/dashboard").data
    # Alerts now appear via KPI card with alert styling
    assert b"Open alerts" in page and b"tone-danger" in page
    secret = make_user(app, "aud", "auditor")
    auditor = app.test_client()
    login_fully(auditor, secret, "aud")
    page_a = auditor.get("/dashboard").data
    assert b"Open alerts" in page_a and b"tone-danger" in page_a
    secret = make_user(app, "inv", "invigilator")
    inv = app.test_client()
    login_fully(inv, secret, "inv")
    page_i = inv.get("/dashboard").data
    assert b"Security alert" not in page_i


def test_examiner_dashboard_cards_and_empty_state(tmp_path):
    _app, client = _login(tmp_path, "examiner")
    page = client.get("/dashboard").data
    for text in (b"My exams", b"Next exam", b"Upload new exam", b"No exams yet"):
        assert text in page
    assert b"/admin/users" not in page


def test_auditor_dashboard_cards(tmp_path):
    app, client = _login(tmp_path, "auditor")
    page = client.get("/dashboard").data
    for text in (b"Log entries", b"Last daily root", b"Open alerts", b"Verify audit log integrity",
                 b"Run verification"):
        assert text in page
    assert b"Not run yet" not in page  # auditor dashboard uses KPI cards, not the old card layout


def test_dashboard_has_no_inline_script_or_style(tmp_path):
    for role in ("admin", "examiner", "invigilator", "auditor"):
        (tmp_path / role).mkdir()
        _app, client = _login(tmp_path / role, role)
        text = client.get("/dashboard").get_data(as_text=True)
        assert "style=" not in text and "onclick=" not in text