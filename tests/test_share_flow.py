"""Plan 4.6: share submission flow, one-time nonces, window enforcement and paper release.

Uses the real paper_service, keywrap, Feldman and signing modules with a temporary paper database.
"""
import hashlib
import io
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from audit.hashchain import verify_hashchain
from crypto.services import paper_service
from web import exam_store, share_flow
from web.app import create_app
from web.db import get_connection

TOTP_KEY = "11" * 32
PAPER = b"Q1. Explain a stack. [5 marks]\nQ2. Define a queue. [5 marks]\n"
USERS = ["inv1", "inv2", "inv3", "inv4", "inv5"]


def private_pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def public_pem(key):
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


@pytest.fixture(scope="module")
def rsa_keys():
    return {name: rsa.generate_private_key(public_exponent=65537, key_size=3072) for name in USERS}


@pytest.fixture(scope="module")
def signing_key():
    return ed25519.Ed25519PrivateKey.generate()


class Env:
    def __init__(self, app, conn, ids, rsa_keys, signing, public_path):
        self.app, self.conn, self.ids = app, conn, ids
        self.rsa, self.signing, self.public_path = rsa_keys, signing, public_path
        self.pending = app.extensions["examvault_pending"]
        self._clients = {}

    def client(self, name):
        if name not in self._clients:
            client = self.app.test_client()
            with client.session_transaction() as sess:
                sess["_user_id"] = str(self.ids[name])
                sess["_fresh"] = True
            self._clients[name] = client
        return self._clients[name]


@pytest.fixture
def env(tmp_path, monkeypatch, rsa_keys, signing_key):
    monkeypatch.setattr(paper_service, "DATABASE_PATH", tmp_path / "paper.db")
    public_path = tmp_path / "examiner_public.pem"
    public_path.write_bytes(public_pem(signing_key.public_key()))
    app = create_app(
        {
            "TESTING": True,
            "SKIP_DOTENV": True,
            "SECRET_KEY": "test-secret-key-not-for-production",
            "TOTP_ENCRYPTION_KEY": TOTP_KEY,
            "DATABASE_PATH": str(tmp_path / "test.db"),
            "AUDIT_SIGNING_KEY_PATH": str(tmp_path / "keys" / "audit.pem"),
            "EXAMINER_PUBLIC_KEY_PATH": str(public_path),
            "WTF_CSRF_ENABLED": False,
            "RATELIMIT_ENABLED": False,
        }
    )
    conn = get_connection(app.config["DATABASE_PATH"])
    for name in USERS + ["outsider"]:
        conn.execute(
            "INSERT INTO users (username, role, password_hash) VALUES (?, 'invigilator', 'x')", (name,)
        )
    conn.execute("INSERT INTO users (username, role, password_hash) VALUES ('admin1', 'admin', 'x')")
    conn.commit()
    ids = {row["username"]: row["id"] for row in conn.execute("SELECT id, username FROM users")}
    yield Env(app, conn, ids, rsa_keys, signing_key, public_path)
    conn.close()


def make_exam(env, start=timedelta(minutes=-5), end=timedelta(hours=1)):
    now = datetime.now(timezone.utc)
    holders = [env.rsa[name].public_key() for name in USERS]
    result = paper_service.create_exam(PAPER, holders, env.signing, now + start, now + end)
    exam_store.register_shares(
        env.conn, result["exam_id"], result["commitments"], [env.ids[n] for n in USERS], result["wrapped_shares"]
    )
    return result["exam_id"]


def get_nonce(client, exam_id):
    page = client.get(f"/invigilator/submit-share/{exam_id}")
    assert page.status_code == 200
    return re.search(r'name="nonce" value="([^"]+)"', page.get_data(as_text=True)).group(1)


def post_share(client, exam_id, key_pem, nonce):
    return client.post(
        f"/invigilator/submit-share/{exam_id}",
        data={"nonce": nonce, "keyfile": (io.BytesIO(key_pem), "key.pem")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )


def submit_as(env, name, exam_id, key_name=None):
    client = env.client(name)
    return post_share(client, exam_id, private_pem(env.rsa[key_name or name]), get_nonce(client, exam_id))


def audit_text(env):
    try:
        return str([tuple(r) for r in env.conn.execute("SELECT * FROM audit_entries ORDER BY id")])
    except Exception:
        return ""


def threshold_of(exam_id):
    return int(exam_store.get_exam(exam_id)["threshold"])


def test_holder_sees_exam_page_and_others_are_blocked(env):
    exam_id = make_exam(env)
    page = env.client("inv1").get(f"/invigilator/exam/{exam_id}")
    assert page.status_code == 200 and exam_id.encode() in page.data and b"Window open" in page.data
    assert b'id="countdown"' in page.data and b"/static/countdown.js" in page.data
    assert env.client("outsider").get(f"/invigilator/exam/{exam_id}").status_code == 404
    assert env.client("admin1").get(f"/invigilator/exam/{exam_id}").status_code == 403
    assert env.client("inv1").get("/invigilator/exam/does-not-exist").status_code == 404
    script = env.app.test_client().get("/static/countdown.js")
    assert script.status_code == 200 and b"countdown" in script.data


def test_register_shares_stores_only_wrapped_blobs(env):
    exam_id = make_exam(env)
    rows = env.conn.execute(
        "SELECT wrapped_share_blob, share_index FROM shares WHERE exam_id = ?", (exam_id,)
    ).fetchall()
    assert len(rows) == 5 and {r["share_index"] for r in rows} == {1, 2, 3, 4, 5}
    assert all(b"BEGIN" not in bytes(r["wrapped_share_blob"]) for r in rows)


def test_submit_before_window_is_refused(env):
    exam_id = make_exam(env, timedelta(minutes=30), timedelta(minutes=90))
    page = env.client("inv1").get(f"/invigilator/exam/{exam_id}")
    assert b"Window opens in" in page.data
    response = submit_as(env, "inv1", exam_id)
    assert b"Window not open yet" in response.data
    assert env.pending.count(exam_id) == 0 and "window_before" in audit_text(env)


def test_submit_after_window_is_refused(env):
    exam_id = make_exam(env, timedelta(minutes=-5), timedelta(seconds=3))
    client = env.client("inv1")
    nonce = get_nonce(client, exam_id)
    time.sleep(3.5)
    response = post_share(client, exam_id, private_pem(env.rsa["inv1"]), nonce)
    assert b"Window closed" in response.data
    assert env.pending.count(exam_id) == 0 and "window_closed" in audit_text(env)


def test_valid_share_is_accepted_and_keys_are_not_stored(env):
    exam_id = make_exam(env)
    response = submit_as(env, "inv1", exam_id)
    assert b"Share verified and accepted" in response.data
    assert env.pending.count(exam_id) == 1 and env.pending.has(exam_id, env.ids["inv1"])
    row = env.conn.execute("SELECT accepted FROM share_submissions WHERE exam_id = ?", (exam_id,)).fetchone()
    assert row["accepted"] == 1
    audit = audit_text(env)
    assert "share_accepted" in audit and "PRIVATE" not in audit and "BEGIN" not in audit
    assert b"PRIVATE KEY" not in Path(env.app.config["DATABASE_PATH"]).read_bytes()


def test_wrong_private_key_is_refused(env):
    exam_id = make_exam(env)
    response = submit_as(env, "inv1", exam_id, key_name="inv2")
    assert b"Share invalid" in response.data
    assert env.pending.count(exam_id) == 0 and "share_invalid" in audit_text(env)


def test_garbage_key_file_is_refused(env):
    exam_id = make_exam(env)
    client = env.client("inv1")
    response = post_share(client, exam_id, b"this is not a key", get_nonce(client, exam_id))
    assert b"Invalid key file" in response.data and env.pending.count(exam_id) == 0


def test_replayed_nonce_is_refused(env):
    exam_id = make_exam(env)
    client = env.client("inv1")
    nonce = get_nonce(client, exam_id)
    pem = private_pem(env.rsa["inv1"])
    assert b"Share verified and accepted" in post_share(client, exam_id, pem, nonce).data
    with client.session_transaction() as sess:  # an attacker replays the captured request
        sess["share_nonce"] = {"exam": exam_id, "nonce": nonce, "timestamp": str(int(time.time()))}
    again = post_share(client, exam_id, pem, nonce)
    assert b"already used" in again.data and env.pending.count(exam_id) == 1


def test_wrong_nonce_is_refused(env):
    exam_id = make_exam(env)
    client = env.client("inv1")
    get_nonce(client, exam_id)
    response = post_share(client, exam_id, private_pem(env.rsa["inv1"]), "wrong-nonce")
    assert b"Request expired" in response.data and env.pending.count(exam_id) == 0


def test_same_holder_cannot_submit_twice(env):
    exam_id = make_exam(env)
    assert b"Share verified and accepted" in submit_as(env, "inv1", exam_id).data
    second = submit_as(env, "inv1", exam_id)
    assert b"Share already submitted" in second.data and env.pending.count(exam_id) == 1


def test_core_refuses_a_user_who_is_not_a_holder(env):
    exam_id = make_exam(env)
    with pytest.raises(share_flow.ShareRefused) as info:
        share_flow.submit_share(
            env.conn, env.pending, exam_id=exam_id, user_id=env.ids["outsider"], username="outsider",
            key_pem=private_pem(env.rsa["inv1"]), nonce="n-outsider",
            load_admin_public_key=lambda: env.signing.public_key(),
        )
    assert info.value.reason == "not_holder" and "not_holder" in audit_text(env)


def test_below_threshold_does_not_release(env):
    exam_id = make_exam(env)
    for name in USERS[: threshold_of(exam_id) - 1]:
        assert b"Share verified and accepted" in submit_as(env, name, exam_id).data
    assert not exam_store.is_released(env.conn, exam_id)
    assert b"Not available yet" in env.client("inv1").get(f"/invigilator/copy/{exam_id}").data


def test_threshold_releases_the_paper_in_memory_only(env):
    captured = []
    env.app.extensions["examvault_release_handlers"].append(lambda eid, data: captured.append((eid, data)))
    exam_id = make_exam(env)
    needed = threshold_of(exam_id)
    last = None
    for name in USERS[:needed]:
        last = submit_as(env, name, exam_id)
    assert b"Paper released" in last.data
    assert captured == [(exam_id, PAPER)]
    row = env.conn.execute("SELECT paper_sha256 FROM exam_release WHERE exam_id = ?", (exam_id,)).fetchone()
    assert row["paper_sha256"] == hashlib.sha256(PAPER).hexdigest()
    assert env.pending.count(exam_id) == 0
    assert b"Examiner signature: valid" in env.client("inv1").get(f"/invigilator/copy/{exam_id}").data
    audit = audit_text(env)
    assert "paper_released" in audit and PAPER.decode() not in audit
    assert verify_hashchain(env.conn)
    if needed < len(USERS):
        late = submit_as(env, USERS[needed], exam_id)
        assert b"Paper already released" in late.data


def test_missing_examiner_key_keeps_the_paper_locked(env, tmp_path):
    env.app.config["EXAMINER_PUBLIC_KEY_PATH"] = str(tmp_path / "missing.pem")
    exam_id = make_exam(env)
    needed = threshold_of(exam_id)
    last = None
    for name in USERS[:needed]:
        last = submit_as(env, name, exam_id)
    assert b"release failed" in last.data
    assert not exam_store.is_released(env.conn, exam_id) and "release_failed" in audit_text(env)


def test_wrong_examiner_key_blocks_release(env, tmp_path):
    other = tmp_path / "other_public.pem"
    other.write_bytes(public_pem(ed25519.Ed25519PrivateKey.generate().public_key()))
    env.app.config["EXAMINER_PUBLIC_KEY_PATH"] = str(other)
    exam_id = make_exam(env)
    last = None
    for name in USERS[: threshold_of(exam_id)]:
        last = submit_as(env, name, exam_id)
    assert b"release failed" in last.data and not exam_store.is_released(env.conn, exam_id)


def test_dashboard_lists_the_exam_for_an_invigilator(env):
    exam_id = make_exam(env)
    page = env.client("inv2").get("/dashboard")
    assert page.status_code == 200 and b"Window open" in page.data  # KPI shows window open now
    assert exam_id.encode() in page.data
    # The exam card must link to the exam page (checks the link, not the button's wording)
    assert f"/invigilator/exam/{exam_id}".encode() in page.data


def test_pending_store_forgets_expired_entries():
    store = share_flow.PendingShares()
    store.add("e1", 1, b"blob", object(), time.time() - 1)
    assert store.count("e1") == 0 and not store.has("e1", 1)
    store.add("e1", 1, b"blob", object(), time.time() + 60)
    assert store.count("e1") == 1
    store.clear("e1")
    assert store.count("e1") == 0



# --- review fixes: real timestamp, replay window, CRL-based refusal ------------------------------------

def test_submit_page_timestamp_is_real_server_time(env, monkeypatch):
    import time as _time

    monkeypatch.delenv("TEST_TIMESTAMP", raising=False)
    exam_id = make_exam(env)
    client = env.client(USERS[0])
    get_nonce(client, exam_id)
    with client.session_transaction() as sess:
        issued = int(sess["share_nonce"]["timestamp"])
    assert abs(issued - int(_time.time())) < 10  # not a random number


def test_old_submit_page_nonce_is_refused_after_five_minutes(env, monkeypatch):
    import time as _time

    monkeypatch.delenv("TEST_TIMESTAMP", raising=False)
    exam_id = make_exam(env)
    client = env.client(USERS[0])
    nonce = get_nonce(client, exam_id)
    with client.session_transaction() as sess:
        data = dict(sess["share_nonce"])
        data["timestamp"] = str(int(_time.time()) - 3600)
        sess["share_nonce"] = data
    page = post_share(client, exam_id, private_pem(env.rsa[USERS[0]]), nonce)
    assert "Request expired" in page.get_data(as_text=True)
    assert "nonce_expired" in audit_text(env)
    assert env.conn.execute("SELECT COUNT(*) FROM share_submissions").fetchone()[0] == 0


def test_invigilator_with_schnorr_key_is_not_blocked_while_schnorr_is_off(env):
    """A stored schnorr_public_y must not stop share submission until the Schnorr UI exists."""
    exam_id = make_exam(env)
    env.conn.execute("UPDATE users SET schnorr_public_y = '12345' WHERE username = ?", (USERS[0],))
    env.conn.commit()
    page = submit_as(env, USERS[0], exam_id)
    assert "ZKP key possession proof failed" not in page.get_data(as_text=True)
    assert env.conn.execute("SELECT COUNT(*) FROM share_submissions").fetchone()[0] == 1


def test_revoked_certificate_is_refused_through_the_crl(env):
    from crypto import pki

    exam_id = make_exam(env)
    name = USERS[0]
    serial, pem = pki.issue_certificate(name, "invigilator", public_pem(env.rsa[name].public_key()))
    env.conn.execute(
        "INSERT INTO certificates (serial, user_id, pem, issued_at) VALUES (?, ?, ?, ?)",
        (serial, env.ids[name], pem, "2026-10-25T00:00:00"),
    )
    env.conn.commit()
    pki.revoke(env.conn, serial, "Left job", actor="admin1")
    page = submit_as(env, name, exam_id)
    assert "revoked" in page.get_data(as_text=True).lower()
    assert "revoked_certificate" in audit_text(env)
    assert env.conn.execute("SELECT COUNT(*) FROM share_submissions").fetchone()[0] == 0