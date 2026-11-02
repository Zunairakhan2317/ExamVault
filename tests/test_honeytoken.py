"""Honeytoken (plan 7.2): opening the decoy file raises an alert and a CRITICAL audit entry."""
from __future__ import annotations

import pytest

from demo import honeytoken
from tests.test_web_auth import login_fully, make_config, make_user
from web.app import create_app
from web.db import get_connection, init_db


# --- logic level (no browser) --------------------------------------------------------------------------

@pytest.fixture
def conn(tmp_path):
    connection = get_connection(tmp_path / "web.db")
    init_db(connection)
    for name, role in (("adm", "admin"), ("inv", "invigilator"), ("exm", "examiner"), ("aud", "auditor")):
        connection.execute("INSERT INTO users (username, role, password_hash) VALUES (?, ?, 'x')", (name, role))
    connection.commit()
    yield connection
    connection.close()


def _uid(conn, name):
    return conn.execute("SELECT id FROM users WHERE username = ?", (name,)).fetchone()["id"]


def _audit(conn):
    return str([tuple(r) for r in conn.execute("SELECT * FROM audit_entries")])


def test_hit_by_a_non_admin_creates_alert_audit_entry_and_suspends(conn):
    result = honeytoken.record_hit(conn, _uid(conn, "inv"), "inv", "invigilator", "10.0.0.5")
    assert result["suspended"] is True
    event = conn.execute("SELECT * FROM honeytoken_events").fetchone()
    assert event["user_id"] == _uid(conn, "inv") and event["ip"] == "10.0.0.5" and event["file_id"] == honeytoken.DECOY_FILE_ID
    assert conn.execute("SELECT is_active FROM users WHERE username = 'inv'").fetchone()[0] == 0
    audit = _audit(conn)
    assert honeytoken.HONEYTOKEN_ACTION in audit and "CRITICAL" in audit


def test_hit_by_an_admin_raises_the_alert_but_never_locks_the_admin(conn):
    result = honeytoken.record_hit(conn, _uid(conn, "adm"), "adm", "admin", "127.0.0.1")
    assert result["suspended"] is False
    assert conn.execute("SELECT is_active FROM users WHERE username = 'adm'").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM honeytoken_events").fetchone()[0] == 1
    assert honeytoken.HONEYTOKEN_ACTION in _audit(conn)


def test_every_non_admin_role_is_suspended(conn):
    for name, role in (("exm", "examiner"), ("aud", "auditor")):
        assert honeytoken.record_hit(conn, _uid(conn, name), name, role, None)["suspended"] is True


def test_list_events_shows_user_and_account_state(conn):
    honeytoken.record_hit(conn, _uid(conn, "inv"), "inv", "invigilator", "10.0.0.5")
    [event] = honeytoken.list_events(conn)
    assert event["username"] == "inv" and event["role"] == "invigilator" and event["suspended"] is True


def test_reinstate_lifts_a_suspension_and_is_audited(conn):
    event_id = honeytoken.record_hit(conn, _uid(conn, "inv"), "inv", "invigilator", None)["event_id"]
    assert honeytoken.reinstate(conn, event_id, "adm") == "ok"
    assert conn.execute("SELECT is_active FROM users WHERE username = 'inv'").fetchone()[0] == 1
    assert "honeytoken_reinstated" in _audit(conn)
    assert honeytoken.reinstate(conn, 9999, "adm") == "unknown"


def test_reinstate_does_not_undo_a_certificate_revocation(conn):
    uid = _uid(conn, "inv")
    event_id = honeytoken.record_hit(conn, uid, "inv", "invigilator", None)["event_id"]
    conn.execute(
        "INSERT INTO certificates (serial, user_id, pem, issued_at, revoked_at) VALUES ('S1', ?, 'pem', 'now', 'now')", (uid,)
    )
    conn.commit()
    assert honeytoken.reinstate(conn, event_id, "adm") == "revoked"
    assert conn.execute("SELECT is_active FROM users WHERE username = 'inv'").fetchone()[0] == 0


def test_decoy_pdf_is_harmless_placeholder():
    pdf = honeytoken.decoy_pdf_bytes()
    assert pdf.startswith(b"%PDF") and len(pdf) < 20000


def test_email_alert_is_skipped_without_smtp_settings(monkeypatch):
    monkeypatch.delenv("SMTP_USER", raising=False)
    monkeypatch.delenv("SMTP_APP_PASSWORD", raising=False)
    assert honeytoken.send_email_alert("subject", "body") is False


# --- web level -------------------------------------------------------------------------------------------

def _two_clients(tmp_path):
    app = create_app(make_config(tmp_path))
    admin_secret = make_user(app, "adm1", "admin")
    inv_secret = make_user(app, "inv1", "invigilator")
    admin, inv = app.test_client(), app.test_client()
    login_fully(admin, admin_secret, "adm1")
    login_fully(inv, inv_secret, "inv1")
    return app, admin, inv


def _db(app):
    return get_connection(app.config["DATABASE_PATH"])


def test_files_page_lists_the_decoy_for_every_role(tmp_path):
    app, admin, inv = _two_clients(tmp_path)
    for client in (admin, inv):
        page = client.get("/files")
        assert page.status_code == 200 and honeytoken.DECOY_FILENAME.encode() in page.data


def test_invigilator_opening_the_decoy_is_suspended_and_logged_out(tmp_path):
    app, admin, inv = _two_clients(tmp_path)
    response = inv.get(f"/files/download/{honeytoken.DECOY_FILE_ID}")
    assert response.status_code == 302 and response.headers["Location"].endswith("/login")
    conn = _db(app)
    assert conn.execute("SELECT COUNT(*) FROM honeytoken_events").fetchone()[0] == 1
    assert conn.execute("SELECT is_active FROM users WHERE username = 'inv1'").fetchone()[0] == 0
    assert honeytoken.HONEYTOKEN_ACTION in _audit(conn)
    assert inv.get("/files").status_code in (302, 401)  # the session is gone


def test_admin_opening_the_decoy_gets_the_dummy_pdf_and_stays_active(tmp_path):
    app, admin, inv = _two_clients(tmp_path)
    response = admin.get(f"/files/download/{honeytoken.DECOY_FILE_ID}")
    assert response.status_code == 200 and response.mimetype == "application/pdf" and response.data.startswith(b"%PDF")
    conn = _db(app)
    assert conn.execute("SELECT is_active FROM users WHERE username = 'adm1'").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM honeytoken_events").fetchone()[0] == 1


def test_unknown_file_id_is_404_and_raises_no_alert(tmp_path):
    app, admin, inv = _two_clients(tmp_path)
    assert admin.get("/files/download/not-a-file").status_code == 404
    assert _db(app).execute("SELECT COUNT(*) FROM honeytoken_events").fetchone()[0] == 0


def test_alerts_page_shows_events_to_admin_and_blocks_invigilators(tmp_path):
    app, admin, inv = _two_clients(tmp_path)
    assert admin.get("/admin/alerts").data.count(b"All clear") == 1
    admin.get(f"/files/download/{honeytoken.DECOY_FILE_ID}")
    page = admin.get("/admin/alerts").get_data(as_text=True)
    assert "adm1" in page and "decoy access event" in page
    assert inv.get("/admin/alerts").status_code == 403


def test_bell_shows_the_alert_count_and_admin_can_reinstate(tmp_path):
    app, admin, inv = _two_clients(tmp_path)
    inv.get(f"/files/download/{honeytoken.DECOY_FILE_ID}")  # suspends inv1
    assert b"1 security alerts" in admin.get("/dashboard").data
    event_id = _db(app).execute("SELECT id FROM honeytoken_events").fetchone()[0]
    page = admin.post(f"/admin/alerts/{event_id}/reinstate", follow_redirects=True).get_data(as_text=True)
    assert "Account reinstated" in page
    assert _db(app).execute("SELECT is_active FROM users WHERE username = 'inv1'").fetchone()[0] == 1


def _audit(conn):
    return str([tuple(r) for r in conn.execute("SELECT * FROM audit_entries")])
