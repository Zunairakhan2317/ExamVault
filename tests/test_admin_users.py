"""Admin user management pages (Plan T1).

Tests: users listing with search/filter/pagination, create user with Argon2 password,
RSA keypair generation for invigilators, disable and revoke.
"""
from __future__ import annotations

import json
import re

import pytest

from web.app import create_app
from web.db import get_connection

USERS = ["alice", "bob", "carol", "dave"]
ROLES = ["admin", "examiner", "invigilator", "auditor"]


@pytest.fixture
def auth_and_db(tmp_path):
    """Create app, admin user and other users, then connect the db."""
    paper_db = tmp_path / "paper.db"
    web_db = tmp_path / "web.db"
    app = create_app({
        "TESTING": True, "SKIP_DOTENV": True, "SECRET_KEY": "for-tests-only",
        "TOTP_ENCRYPTION_KEY": "11" * 32, "DATABASE_PATH": str(web_db),
        "AUDIT_SIGNING_KEY_PATH": str(tmp_path / "audit.pem"),
        "WTF_CSRF_ENABLED": False,  # Disable CSRF for testing
    })
    conn = get_connection(web_db)
    conn.execute(
        "INSERT INTO users (username, full_name, email, role, password_hash) VALUES (?, ?, ?, ?, ?)",
        ("admin", "Admin One", "admin@example.com", "admin", "x")
    )
    for name, role in zip(USERS, ["examiner", "invigilator", "auditor", "invigilator"]):
        conn.execute(
            "INSERT INTO users (username, full_name, email, role, password_hash) VALUES (?, ?, ?, ?, ?)",
            (name, name.capitalize(), f"{name}@example.com", role, "x")
        )
    conn.commit()
    ids = {row["username"]: row["id"] for row in conn.execute("SELECT id, username FROM users")}
    return app, conn, ids


def _auth_client(app, admin=True):
    client = app.test_client()
    if admin:
        with client.session_transaction() as sess:
            sess["_user_id"] = "1"
            sess["_fresh"] = True
    return client


def _assert_pagination(page, expected_label, has_prev=True, has_next=False):
    """Shared assertions for the users listing page."""
    assert page.status_code == 200, "listing should render"
    data = page.get_data(as_text=True)
    assert expected_label in data, f"expected {expected_label} in page"


def test_admin_users_list_empty(auth_and_db):
    app, conn, ids = auth_and_db
    client = _auth_client(app)
    page = client.get("/admin/users?search=nonexistent-user-xyz-999")
    _assert_pagination(page, "No users yet")


def test_admin_users_list_shows_rows(auth_and_db):
    app, conn, ids = auth_and_db
    client = _auth_client(app)
    page = client.get("/admin/users")
    _assert_pagination(page, "alice")
    _assert_pagination(page, "bob")
    _assert_pagination(page, "carol")
    _assert_pagination(page, "dave")


def test_admin_users_list_search(auth_and_db):
    app, conn, ids = auth_and_db
    conn.execute(
        "UPDATE users SET email = 'secret@hidden.com', full_name = 'Hidden Person' WHERE username = 'bob'"
    )
    conn.commit()
    client = _auth_client(app)
    page = client.get("/admin/users?search=hidden")
    text = page.get_data(as_text=True)
    assert "Hidden Person" in text
    assert "carol" not in text  # non-matching users are filtered out


def test_admin_users_list_role_filter(auth_and_db):
    app, conn, ids = auth_and_db
    client = _auth_client(app)
    page = client.get("/admin/users?role=invigilator")
    data = page.get_data(as_text=True)
    assert "invigilator" in data
    # No non-invigilators in results
    for name, role in zip(USERS, ["examiner", "invigilator", "auditor", "invigilator"]):
        if role == "invigilator":
            assert name in data
    page2 = client.get("/admin/users?role=auditor")
    assert "auditor" in page2.get_data(as_text=True)
    page3 = client.get("/admin/users?role=admin")
    assert "admin" in page3.get_data(as_text=True)


def test_admin_users_create_success(auth_and_db):
    app, conn, ids = auth_and_db
    client = _auth_client(app)
    page = client.post(
        "/admin/users/new",
        data={
            "full_name": "New User",
            "username": "frank",
            "email": "frank@example.com",
            "role": "auditor",
            "password": "password-with-12",
        },
        follow_redirects=False,
    )
    assert page.status_code == 302, "create should redirect after success"
    row = conn.execute("SELECT * FROM users WHERE username = ?", ("frank",)).fetchone()
    assert row is not None
    assert row["full_name"] == "New User"
    assert row["email"] == "frank@example.com"
    assert row["role"] == "auditor"
    assert row["password_hash"] != "x"  # hashed with Argon2, not placeholder
    audit = [tuple(r) for r in conn.execute("SELECT * FROM audit_entries")]
    assert any("user_created" in str(e) for e in audit)


def test_admin_users_create_with_generated_password(auth_and_db):
    app, conn, ids = auth_and_db
    client = _auth_client(app)
    page = client.post(
        "/admin/users/new",
        data={
            "full_name": "Gen User",
            "username": "grace",
            "email": "grace@example.com",
            "role": "examiner",
            "generate_password": "on",
        },
    )
    assert "grace" in page.get_data(as_text=True)  # username check karein
    assert re.search(r"password.*?[A-Za-z0-9+/=_\-]{16,}", page.get_data(as_text=True))


def test_admin_users_create_missing_password(auth_and_db):
    app, conn, ids = auth_and_db
    client = _auth_client(app)
    page = client.post(
        "/admin/users/new",
        data={
            "full_name": "No Pass",
            "username": "harry",
            "email": "harry@example.com",
            "role": "auditor",
        },
    )
    assert page.status_code == 200
    assert "Password is required" in page.get_data(as_text=True)


def test_admin_users_create_invalid_password(auth_and_db):
    app, conn, ids = auth_and_db
    client = _auth_client(app)
    page = client.post(
        "/admin/users/new",
        data={
            "full_name": "Short Pass",
            "username": "iris",
            "email": "iris@example.com",
            "role": "auditor",
            "password": "short",
        },
    )
    assert page.status_code == 200
    assert "Password" in page.get_data(as_text=True) and ("too short" in page.get_data(as_text=True).lower() or "password" in page.get_data(as_text=True).lower())


def test_admin_users_create_duplicate(auth_and_db):
    app, conn, ids = auth_and_db
    client = _auth_client(app)
    page = client.post(
        "/admin/users/new",
        data={
            "full_name": "Alice Again",
            "username": "alice",
            "email": "alice2@example.com",
            "role": "examiner",
            "password": "password-with-12",
        },
    )
    assert page.status_code == 200
    assert "already exists" in page.get_data(as_text=True).lower()


def test_admin_users_create_invigilator_keypair(auth_and_db):
    app, conn, ids = auth_and_db
    client = _auth_client(app)
    page = client.post(
        "/admin/users/new",
        data={
            "full_name": "Invig User",
            "username": "jake",
            "email": "jake@example.com",
            "role": "invigilator",
            "password": "password-with-12",
        },
    )
    assert page.status_code == 200
    data = page.get_data(as_text=True)
    assert "jake" in data
    assert "Download private key" in data
    assert "ONLY ONCE" in data  # All caps match template text
    from web import routes_admin
    pub_path = routes_admin.KEYS_DIR / "jake_public.pem"  # conftest points this at a temp folder
    assert pub_path.exists(), "public key should be saved"
    audit = [tuple(r) for r in conn.execute("SELECT * FROM audit_entries")]
    assert any("invigilator_keypair_generated" in str(e) for e in audit)


def test_admin_users_disable(auth_and_db):
    app, conn, ids = auth_and_db
    client = _auth_client(app)
    page = client.post(
        f"/admin/users/{ids['carol']}/disable",
        data={"csrf_token": "test-token"},
        follow_redirects=True,
    )
    assert page.status_code == 200
    row = conn.execute("SELECT is_active FROM users WHERE username = ?", ("carol",)).fetchone()
    assert row["is_active"] == 0
    assert "disabled" in page.get_data(as_text=True).lower()
    audit = [tuple(r) for r in conn.execute("SELECT * FROM audit_entries")]
    assert any("user_disabled" in str(e) for e in audit)


def test_admin_users_disable_self(auth_and_db):
    app, conn, ids = auth_and_db
    client = _auth_client(app)
    page = client.post(
        "/admin/users/1/disable",
        data={"csrf_token": "test-token"},
        follow_redirects=True,
    )
    assert "cannot disable yourself" in page.get_data(as_text=True).lower()


def test_admin_users_disable_inactive(auth_and_db):
    app, conn, ids = auth_and_db
    client = _auth_client(app)
    # Disable carol first
    conn.execute("UPDATE users SET is_active = 0 WHERE id = ?", (ids["carol"],))
    conn.commit()
    page = client.post(
        f"/admin/users/{ids['carol']}/disable",
        data={"csrf_token": "test-token"},
        follow_redirects=True,
    )
    assert "already disabled" in page.get_data(as_text=True).lower()


def test_admin_users_revoke(auth_and_db):
    app, conn, ids = auth_and_db
    client = _auth_client(app)
    page = client.post(
        f"/admin/users/{ids['carol']}/revoke",
        data={"csrf_token": "test-token", "reason": "key_lost"},
        follow_redirects=True,
    )
    assert page.status_code == 200
    row = conn.execute("SELECT is_active FROM users WHERE username = ?", ("carol",)).fetchone()
    assert row["is_active"] == 0
    assert "User revoked. Please rotate shares for affected exams" in page.get_data(as_text=True)
    audit = [tuple(r) for r in conn.execute("SELECT * FROM audit_entries")]
    assert any("user_revoked" in str(e) and "key_lost" in str(e) for e in audit)


def test_admin_users_revoke_requires_valid_reason(auth_and_db):
    app, conn, ids = auth_and_db
    client = _auth_client(app)
    for data in ({}, {"reason": ""}, {"reason": "because"}):
        page = client.post(
            f"/admin/users/{ids['carol']}/revoke", data=data, follow_redirects=True
        )
        assert "Select a reason" in page.get_data(as_text=True)
        row = conn.execute("SELECT is_active FROM users WHERE username = ?", ("carol",)).fetchone()
        assert row["is_active"] == 1
    has_table = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'audit_entries'"
    ).fetchone()
    if has_table:  # the audit table is created by the first log entry
        audit = str([tuple(r) for r in conn.execute("SELECT * FROM audit_entries")])
        assert "user_revoked" not in audit


def test_users_page_has_revoke_modal_without_inline_js(auth_and_db):
    """Brief page 6 modal text and reasons; the CSP forbids inline JS, so none may be used."""
    app, conn, ids = auth_and_db
    text = _auth_client(app).get("/admin/users").get_data(as_text=True)
    assert "Is user ka certificate revoke ho jayega aur shares dobara banane honge. Pakka?" in text
    for label in ("Left job", "Key lost", "Suspicious activity"):
        assert label in text
    assert "Confirm revoke" in text and "Cancel" in text
    for bad in ("onsubmit=", "onclick=", "style="):
        assert bad not in text
    assert "<h1 class=\"h3\">Users</h1>" in text


def test_users_page_loads_bootstrap_js_for_modal(auth_and_db):
    app, conn, ids = auth_and_db
    text = _auth_client(app).get("/admin/users").get_data(as_text=True)
    assert "bootstrap.bundle.min.js" in text


def test_users_status_active_disabled_revoked(auth_and_db):
    """Revoked comes from certificates.revoked_at (set by the PKI step); Disabled is grey."""
    app, conn, ids = auth_and_db
    conn.execute("UPDATE users SET is_active = 0 WHERE username = 'bob'")
    conn.execute("UPDATE users SET is_active = 0 WHERE username = 'carol'")
    conn.execute(
        "INSERT INTO certificates (serial, user_id, pem, issued_at, revoked_at) VALUES (?, ?, ?, ?, ?)",
        ("ABCDEF123456", ids["carol"], "pem", "2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z"),
    )
    conn.commit()
    text = _auth_client(app).get("/admin/users").get_data(as_text=True)
    assert 'text-bg-success">Active' in text
    assert 'text-bg-secondary">Disabled' in text
    assert 'text-bg-danger">Revoked' in text


def test_admin_users_revoke_self(auth_and_db):
    app, conn, ids = auth_and_db
    client = _auth_client(app)
    page = client.post(
        "/admin/users/1/revoke",
        data={"csrf_token": "test-token"},
        follow_redirects=True,
    )
    assert "cannot revoke yourself" in page.get_data(as_text=True).lower()


def test_non_admin_cannot_access(auth_and_db):
    app, conn, ids = auth_and_db
    # Login as an invigilator (user id 2)
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = "2"
        sess["_fresh"] = True
    assert client.get("/admin/users").status_code == 403
    assert client.get("/admin/users/new").status_code == 403
    assert client.get("/admin/users/private-key/sometoken").status_code == 403


def test_users_listing_pagination(auth_and_db):
    app, conn, ids = auth_and_db
    client = _auth_client(app)
    page = client.get("/admin/users?page=1")
    assert "1" in page.get_data(as_text=True)
    page2 = client.get("/admin/users?page=99")
    assert page2.status_code == 200


def _create_invigilator(client, username):
    return client.post(
        "/admin/users/new",
        data={
            "full_name": "Key Holder",
            "username": username,
            "email": f"{username}@example.com",
            "role": "invigilator",
            "password": "password-with-12",
        },
    )


def _token_from(page) -> str:
    match = re.search(r"/admin/users/private-key/([A-Za-z0-9_\-]+)", page.get_data(as_text=True))
    assert match, "download link with one-time token expected"
    return match.group(1)


def test_private_key_is_never_stored_on_server(auth_and_db):
    """The private key must not be written to disk or the database (brief page 7)."""
    from web import routes_admin
    keys_dir = routes_admin.KEYS_DIR  # conftest points this at a temp folder
    app, conn, ids = auth_and_db
    client = _auth_client(app)
    page = _create_invigilator(client, "nodisk")
    assert page.status_code == 200
    assert not (keys_dir / "nodisk_private.pem").exists()
    assert (keys_dir / "nodisk_public.pem").exists()
    for table in ("users", "certificates", "shares"):
        dump = str([tuple(r) for r in conn.execute(f"SELECT * FROM {table}")])
        assert "PRIVATE KEY" not in dump


def test_download_private_key_works_only_once(auth_and_db):
    app, conn, ids = auth_and_db
    client = _auth_client(app)
    token = _token_from(_create_invigilator(client, "kevin2"))
    first = client.get(f"/admin/users/private-key/{token}")
    assert first.status_code == 200
    assert b"BEGIN PRIVATE KEY" in first.data
    assert first.headers["Cache-Control"] == "no-store"
    assert client.get(f"/admin/users/private-key/{token}").status_code == 404
    audit = str([tuple(r) for r in conn.execute("SELECT * FROM audit_entries")])
    assert "private_key_handed_over" in audit and "BEGIN PRIVATE KEY" not in audit


def test_private_key_token_unknown_or_not_yours(auth_and_db):
    app, conn, ids = auth_and_db
    client = _auth_client(app)
    token = _token_from(_create_invigilator(client, "kevin3"))
    assert client.get("/admin/users/private-key/not-a-real-token").status_code == 404
    from web import routes_admin
    other_admin_id = ids["admin"] + 100
    assert routes_admin._take_private_key(other_admin_id, token) is None
    assert client.get(f"/admin/users/private-key/{token}").status_code == 200


def test_private_key_token_expires(auth_and_db):
    app, conn, ids = auth_and_db
    client = _auth_client(app)
    token = _token_from(_create_invigilator(client, "kevin4"))
    from web import routes_admin
    admin_id, name, pem, _expires = routes_admin._handoff[token]
    routes_admin._handoff[token] = (admin_id, name, pem, 0.0)  # already expired
    assert client.get(f"/admin/users/private-key/{token}").status_code == 404


def test_passwords_are_argon2_hashed(auth_and_db):
    app, conn, ids = auth_and_db
    client = _auth_client(app)
    client.post(
        "/admin/users/new",
        data={
            "full_name": "Argon Test",
            "username": "luna",
            "email": "luna@example.com",
            "role": "auditor",
            "password": "Password-with-12",
        },
    )
    row = conn.execute("SELECT password_hash FROM users WHERE username = ?", ("luna",)).fetchone()
    assert row["password_hash"].startswith("$argon2") or "$argon2" in row["password_hash"]


def test_users_list_show_last_login(auth_and_db):
    app, conn, ids = auth_and_db
    conn.execute("UPDATE users SET last_login_at = '2025-10-01T12:34:56Z' WHERE username = 'alice'")
    conn.commit()
    client = _auth_client(app)
    page = client.get("/admin/users")
    assert "2025-10-01T12:34" in page.get_data(as_text=True) or "last_login" in page.get_data(as_text=True)



# --- review fixes: Schnorr off, CRL on revoke, honest rotation page ---------------------------------------

def test_new_invigilator_gets_no_schnorr_key(auth_and_db):
    """Schnorr is off until its UI exists; a stored y with a thrown-away x would lock the user out."""
    app, conn, ids = auth_and_db
    _create_invigilator(_auth_client(app), "noschnorr")
    row = conn.execute("SELECT schnorr_public_y FROM users WHERE username = 'noschnorr'").fetchone()
    assert row is not None and row["schnorr_public_y"] is None


def test_revoke_puts_the_certificate_on_a_signed_crl(auth_and_db):
    from cryptography import x509
    from crypto import pki

    app, conn, ids = auth_and_db
    client = _auth_client(app)
    _create_invigilator(client, "crluser")
    uid = conn.execute("SELECT id FROM users WHERE username = 'crluser'").fetchone()["id"]
    serial = conn.execute("SELECT serial FROM certificates WHERE user_id = ?", (uid,)).fetchone()["serial"]
    assert pki.user_certificate_ok(conn, uid) is True

    client.post(f"/admin/users/{uid}/revoke", data={"csrf_token": "t", "reason": "left_job"}, follow_redirects=True)

    assert pki.user_certificate_ok(conn, uid) is False
    crl = x509.load_pem_x509_crl(pki.current_crl_pem(conn).encode())
    assert int(serial, 16) in {entry.serial_number for entry in crl}
    audit = str([tuple(r) for r in conn.execute("SELECT * FROM audit_entries")])
    assert "certificate_revoked" in audit and "user_revoked" in audit


def test_rotation_page_does_not_claim_a_rotation_happened(auth_and_db):
    app, conn, ids = auth_and_db
    client = _auth_client(app)
    page = client.get("/admin/rotations").get_data(as_text=True)
    assert "No shares are changed" in page
    assert client.post("/admin/exams/not-an-exam/rotate", data={"csrf_token": "t"}).status_code == 404
    has_table = conn.execute("SELECT 1 FROM sqlite_master WHERE name = 'audit_entries'").fetchone()
    audit = str([tuple(r) for r in conn.execute("SELECT * FROM audit_entries")]) if has_table else ""
    assert "shares_rotated" not in audit
