"""Auditor pages 17 to 19, the verifier's open-day rule and the admin username rule (plan 6.1 to 6.4)."""
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

import audit.hashchain as hashchain
from audit.verifier import verify_full_chain
from web import routes_admin
from web.app import create_app
from web.audit_log import log_event
from web.db import get_connection

TOTP_KEY = "11" * 32


@pytest.fixture
def env(tmp_path):
    app = create_app(
        {
            "TESTING": True, "SKIP_DOTENV": True, "SECRET_KEY": "test-secret-key-not-for-production",
            "TOTP_ENCRYPTION_KEY": TOTP_KEY, "DATABASE_PATH": str(tmp_path / "test.db"),
            "AUDIT_SIGNING_KEY_PATH": str(tmp_path / "keys" / "audit.pem"),
            "WTF_CSRF_ENABLED": False, "RATELIMIT_ENABLED": False,
        }
    )
    conn = get_connection(app.config["DATABASE_PATH"])
    for name, role in [("aud1", "auditor"), ("adm1", "admin"), ("inv1", "invigilator")]:
        conn.execute("INSERT INTO users (username, role, password_hash) VALUES (?, ?, 'x')", (name, role))
    conn.commit()
    ids = {r["username"]: r["id"] for r in conn.execute("SELECT id, username FROM users")}

    def client(name):
        c = app.test_client()
        with c.session_transaction() as sess:
            sess["_user_id"] = str(ids[name])
            sess["_fresh"] = True
        return c

    yield type("Env", (), {"app": app, "conn": conn, "client": staticmethod(client)})
    conn.close()


def write_entries_on(monkeypatch, conn, day, events):
    """Write audit entries that carry a chosen (past) UTC date."""
    class FakeDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.fromisoformat(f"{day}T10:00:00+00:00")

    monkeypatch.setattr(hashchain, "datetime", FakeDateTime)
    for actor, action in events:
        log_event(conn, actor, action, {"note": "seeded"})
    monkeypatch.undo()


def test_only_the_auditor_can_open_the_pages(env):
    for path in ("/auditor/log", "/auditor/verify", "/auditor/roots", "/auditor/log/export.csv"):
        assert env.client("aud1").get(path).status_code == 200
        assert env.client("adm1").get(path).status_code == 403
        assert env.client("inv1").get(path).status_code == 403
        assert env.app.test_client().get(path).status_code == 302
    assert env.client("adm1").post("/auditor/roots/generate", data={"date": "all"}).status_code == 403


def test_log_lists_filters_and_highlights(env):
    log_event(env.conn, "alice", "login_success", {"ip": "1.2.3.4"})
    log_event(env.conn, "mallory", "access_denied", {"path": "/admin/users"})
    log_event(env.conn, "bob", "honeytoken_access", {"file": "decoy"})
    client = env.client("aud1")
    page = client.get("/auditor/log").get_data(as_text=True)
    assert "login_success" in page and "access_denied" in page and "table-danger" in page
    only_bob = client.get("/auditor/log?actor=bob").get_data(as_text=True)
    assert "<td>honeytoken_access" in only_bob and "<td>login_success" not in only_bob
    critical = client.get("/auditor/log?severity=critical").get_data(as_text=True)
    assert "<td>honeytoken_access" in critical and "<td>access_denied" not in critical
    searched = client.get("/auditor/log?q=admin%2Fusers").get_data(as_text=True)
    assert "<td>access_denied" in searched and "<td>login_success" not in searched
    assert b"Page 1 of 1" in client.get("/auditor/log?page=abc").data
    assert client.get("/auditor/log?date_from=not-a-date").status_code == 200


def test_log_escapes_html_in_details(env):
    log_event(env.conn, "eve", "login_failed", {"note": "<script>alert(1)</script>"})
    page = env.client("aud1").get("/auditor/log").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page


def test_csv_export_neutralises_formulas_and_is_audited(env):
    log_event(env.conn, "=HYPERLINK(1)", "login_success", {})
    response = env.client("aud1").get("/auditor/log/export.csv")
    text = response.get_data(as_text=True)
    assert response.mimetype == "text/csv" and "attachment" in response.headers["Content-Disposition"]
    assert text.startswith("entry,time_utc,action,actor,details,prev_hash,hash")
    assert "'=HYPERLINK(1)" in text and ",=HYPERLINK(1)," not in text
    rows = [r[0] for r in env.conn.execute("SELECT event_type FROM audit_entries")]
    assert "audit_log_exported" in rows


def test_verify_is_green_for_an_untouched_log_with_entries_from_today(env):
    log_event(env.conn, "alice", "login_success", {})
    report = verify_full_chain(env.conn)
    assert report["valid"] and report["missing_daily_root_dates"] == []
    page = env.client("aud1").get("/auditor/verify").get_data(as_text=True)
    assert "Log intact" in page and "entries checked" in page


def test_verify_names_the_altered_entry(env):
    for i in range(4):
        log_event(env.conn, "alice", "login_success", {"n": i})
    env.conn.execute("DROP TRIGGER audit_entries_no_update")
    env.conn.execute("UPDATE audit_entries SET details = 'changed' WHERE id = 3")
    env.conn.commit()
    page = env.client("aud1").get("/auditor/verify").get_data(as_text=True)
    assert "TAMPERED: entry #3 was altered" in page and "alert-danger" in page


def test_a_completed_day_needs_a_signed_root_and_the_page_can_create_it(env, monkeypatch):
    write_entries_on(monkeypatch, env.conn, "2020-01-15", [("alice", "login_success"), ("bob", "logout")])
    auditor = env.client("aud1")
    assert not verify_full_chain(env.conn)["valid"]
    assert "No signed daily root for completed day 2020-01-15" in auditor.get("/auditor/verify").get_data(as_text=True)
    roots_page = auditor.get("/auditor/roots").get_data(as_text=True)
    assert "2020-01-15" in roots_page and "Generate all missing roots" in roots_page
    response = auditor.post("/auditor/roots/generate", data={"date": "all"}, follow_redirects=True)
    assert b"Signed root created for 2020-01-15" in response.data
    assert env.conn.execute("SELECT entry_count FROM merkle_roots WHERE target_date = '2020-01-15'").fetchone()[0] == 2
    assert b"Valid" in auditor.get("/auditor/roots").data
    assert verify_full_chain(env.conn)["valid"]
    assert "Log intact" in auditor.get("/auditor/verify").get_data(as_text=True)
    again = auditor.post("/auditor/roots/generate", data={"date": "all"}, follow_redirects=True)
    assert b"Nothing to seal" in again.data


def test_today_cannot_be_sealed(env):
    log_event(env.conn, "alice", "login_success", {})
    today = datetime.now(timezone.utc).date().isoformat()
    response = env.client("aud1").post("/auditor/roots/generate", data={"date": today}, follow_redirects=True)
    assert b"Only completed days" in response.data
    assert env.conn.execute("SELECT COUNT(*) FROM audit_entries").fetchone()[0] >= 1
    bad = env.client("aud1").post("/auditor/roots/generate", data={"date": "2020-13-45"}, follow_redirects=True)
    assert b"Only completed days" in bad.data


def test_tampering_with_a_sealed_day_is_reported(env, monkeypatch):
    write_entries_on(monkeypatch, env.conn, "2020-02-01", [("alice", "login_success"), ("bob", "logout")])
    auditor = env.client("aud1")
    auditor.post("/auditor/roots/generate", data={"date": "all"})
    env.conn.execute("DROP TRIGGER audit_entries_no_update")
    env.conn.execute("UPDATE audit_entries SET actor = 'mallory' WHERE id = 1")
    env.conn.commit()
    page = auditor.get("/auditor/verify").get_data(as_text=True)
    assert "TAMPERED: entry #1 was altered" in page


def test_username_rule_blocks_path_tricks_and_keys_stay_in_the_keys_folder(env, tmp_path, monkeypatch):
    monkeypatch.setattr(routes_admin, "KEYS_DIR", tmp_path / "keys_out")
    (tmp_path / "keys_out").mkdir()
    admin = env.client("adm1")
    form = {"full_name": "Eve", "email": "e@example.com", "role": "invigilator", "password": "Tr1cky-Exam-Vault!"}
    for bad in ("../evil", "a/b", "ab", "UPPER space", "x" * 40):
        response = admin.post("/admin/users/new", data={**form, "username": bad})
        assert b"Username must be" in response.data, bad
    assert env.conn.execute("SELECT COUNT(*) FROM users WHERE role = 'invigilator'").fetchone()[0] == 1
    assert list((tmp_path / "keys_out").iterdir()) == []
    ok = admin.post("/admin/users/new", data={**form, "username": "good.user-1"})
    assert ok.status_code == 200 and ok.headers["Cache-Control"] == "no-store"
    assert (tmp_path / "keys_out" / "good.user-1_public.pem").exists()
    assert not list((tmp_path / "keys_out").glob("*private*"))


def test_log_pagination_keeps_the_filters(env):
    for i in range(55):
        log_event(env.conn, "alice", "login_success", {"n": i})
    auditor = env.client("aud1")
    first = auditor.get("/auditor/log?actor=alice").get_data(as_text=True)
    assert "Page 1 of 2" in first and "actor=alice" in first and "page=2" in first
    second = auditor.get("/auditor/log?actor=alice&page=2").get_data(as_text=True)
    assert "Page 2 of 2" in second and "page=1" in second
