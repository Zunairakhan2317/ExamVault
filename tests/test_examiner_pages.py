"""Examiner pages 10-12, placeholders 13 and 20, k-of-n in create_exam and the audit fail-closed rule."""
import hashlib
import io
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from crypto.services import paper_service
from web import exam_store
from web.app import create_app
from web.audit_log import log_event
from web.db import get_connection

PAPER = b"Q1. Explain a stack. [5 marks]\nQ2. Define a queue. [5 marks]\n"
HOLDERS = ["inv1", "inv2", "inv3", "inv4", "inv5"]


def pem_public(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


@pytest.fixture(scope="module")
def rsa_keys():
    return {name: rsa.generate_private_key(public_exponent=65537, key_size=3072) for name in HOLDERS}


@pytest.fixture(scope="module")
def signing_key():
    return ed25519.Ed25519PrivateKey.generate()


class Env:
    def __init__(self, app, conn, ids, keys_dir, signing):
        self.app, self.conn, self.ids, self.keys_dir, self.signing = app, conn, ids, keys_dir, signing
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
    keys_dir = tmp_path / "demo_keys"
    keys_dir.mkdir()
    for name, key in rsa_keys.items():
        (keys_dir / f"{name}_public.pem").write_bytes(pem_public(key))
    (keys_dir / "examiner_signing.pem").write_bytes(
        signing_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    (keys_dir / "examiner_signing_public.pem").write_bytes(pem_public(signing_key))
    app = create_app(
        {
            "TESTING": True, "SKIP_DOTENV": True, "SECRET_KEY": "test-secret-key-not-for-production",
            "TOTP_ENCRYPTION_KEY": "11" * 32, "DATABASE_PATH": str(tmp_path / "test.db"),
            "AUDIT_SIGNING_KEY_PATH": str(tmp_path / "audit_keys" / "audit.pem"),
            "KEYS_DIR": str(keys_dir), "WTF_CSRF_ENABLED": False, "RATELIMIT_ENABLED": False,
        }
    )
    conn = get_connection(app.config["DATABASE_PATH"])
    rows = [(n, "invigilator") for n in HOLDERS] + [
        ("exm1", "examiner"), ("exm2", "examiner"), ("adm1", "admin"), ("aud1", "auditor"),
        ("inv_off", "invigilator"),
    ]
    for name, role in rows:
        conn.execute("INSERT INTO users (username, role, password_hash) VALUES (?, ?, 'x')", (name, role))
    conn.execute("UPDATE users SET is_active = 0 WHERE username = 'inv_off'")
    conn.commit()
    ids = {r["username"]: r["id"] for r in conn.execute("SELECT id, username FROM users")}
    yield Env(app, conn, ids, keys_dir, signing_key)
    conn.close()


def window(start=timedelta(minutes=30), length=timedelta(hours=2)):
    base = datetime.now(timezone.utc) + start
    return base.strftime("%Y-%m-%dT%H:%M"), (base + length).strftime("%Y-%m-%dT%H:%M")


def form(env, holders=HOLDERS, **overrides):
    start, end = window()
    data = {
        "exam_title": "Data Structures Final", "subject": "CS201", "window_start": start, "window_end": end,
        "k": "3", "n": "5", "variants": "current", "holder": [str(env.ids[h]) for h in holders],
        "paper": (io.BytesIO(PAPER), "paper.txt"),
    }
    data.update(overrides)
    return data


def upload(env, **kwargs):
    return env.client("exm1").post(
        "/examiner/upload", data=form(env, **kwargs), content_type="multipart/form-data"
    )


def exam_rows():
    db = paper_service._connect_database()
    db.row_factory = sqlite3.Row
    try:
        return db.execute("SELECT exam_id, exam_title, subject, threshold, num_holders FROM exams").fetchall()
    finally:
        db.close()


def make_exam(env, title="Data Structures Final", start=timedelta(minutes=30), end=timedelta(hours=2)):
    now = datetime.now(timezone.utc)
    holders = [rsa_pub(env, n) for n in HOLDERS]
    result = paper_service.create_exam(
        PAPER, holders, env.signing, now + start, now + end, exam_title=title, subject="CS201", threshold=3
    )
    exam_store.register_shares(
        env.conn, result["exam_id"], result["commitments"], [env.ids[n] for n in HOLDERS], result["wrapped_shares"]
    )
    return result["exam_id"]


def rsa_pub(env, name):
    return serialization.load_pem_public_key((env.keys_dir / f"{name}_public.pem").read_bytes())


# ---------- access control ----------

@pytest.mark.parametrize("path", ["/examiner/upload", "/examiner/exams", "/examiner/variants"])
def test_examiner_pages_are_examiner_only(env, path):
    assert env.client("exm1").get(path).status_code == 200
    for other in ("adm1", "inv1", "aud1"):
        assert env.client(other).get(path).status_code == 403
    assert env.app.test_client().get(path).status_code in (301, 302, 401)


def test_upload_post_and_detail_are_examiner_only(env):
    exam_id = make_exam(env)
    for other in ("adm1", "inv1", "aud1"):
        assert env.client(other).post("/examiner/upload", data=form(env)).status_code == 403
        assert env.client(other).get(f"/examiner/exams/{exam_id}").status_code == 403


def test_leak_analyzer_is_for_examiner_and_auditor(env):
    assert env.client("exm1").get("/tracing/analyze").status_code == 200
    assert env.client("aud1").get("/tracing/analyze").status_code == 200
    assert env.client("inv1").get("/tracing/analyze").status_code == 403
    assert env.client("adm1").get("/tracing/analyze").status_code == 403


# ---------- page 10: upload ----------

def test_upload_page_has_the_brief_elements(env):
    text = env.client("exm1").get("/examiner/upload").get_data(as_text=True)
    for expected in (
        'name="csrf_token"', "Title", "Subject", "Start date-time", "End date-time",
        "Time server ke UTC clock se chalta hai", "PDF ya text, max 10 MB", "Use current variants file",
        "Review variants", "Kisi bhi k holders se paper khulega", "Encrypt, sign and split key",
    ):
        assert expected in text
    assert 'name="k"' in text and 'value="3"' in text and 'value="5"' in text
    for name in HOLDERS:
        assert name in text
    assert "inv_off" not in text and "adm1" not in text and "exm1</label>" not in text
    assert "style=" not in text and "onclick=" not in text


def test_valid_upload_creates_and_shows_the_success_card(env):
    response = upload(env)
    assert response.status_code == 200
    text = response.get_data(as_text=True)
    for expected in ("Exam ID", "Paper hash", "Signature: valid", "k-of-n: 3 of 5", "Shares issued: 5", "View exam"):
        assert expected in text
    for step in ("Hash", "Sign", "Encrypt", "Split key", "Wrap shares", "Done"):
        assert step in text
    assert hashlib.sha256(PAPER).hexdigest()[:16] in text
    (row,) = exam_rows()
    assert (row["exam_title"], row["subject"], row["threshold"], row["num_holders"]) == ("Data Structures Final", "CS201", 3, 5)
    shares = env.conn.execute("SELECT COUNT(*) FROM shares WHERE exam_id = ?", (row["exam_id"],)).fetchone()[0]
    assert shares == 5
    audit = str([tuple(r) for r in env.conn.execute("SELECT * FROM audit_entries")])
    assert "exam_created" in audit and "PRIVATE" not in audit and PAPER.decode()[:10] not in audit


def test_upload_uses_the_chosen_k_and_n(env):
    response = upload(env, holders=HOLDERS[:2], k="2", n="2")
    assert "k-of-n: 2 of 2" in response.get_data(as_text=True)
    assert exam_rows()[0]["threshold"] == 2


def test_empty_k_and_n_fall_back_to_defaults(env):
    assert "k-of-n: 3 of 5" in upload(env, k="", n="").get_data(as_text=True)


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"k": "6"}, "k cannot be greater than n"),
        ({"k": "1"}, "k must be at least 2"),
        ({"k": "abc"}, "k and n must be whole numbers"),
        ({"window_end": "2000-01-01T00:00"}, "End time must be after start time"),
        ({"window_start": "nonsense"}, "Valid start and end date-times are required"),
        ({"exam_title": "  "}, "Exam title and subject are required"),
        ({"paper": (io.BytesIO(b"x"), "paper.exe")}, "Only PDF or text files are allowed"),
        ({"paper": (io.BytesIO(b"x" * (10 * 1024 * 1024 + 1)), "big.pdf")}, "File too large"),
        ({"paper": (io.BytesIO(b""), "empty.txt")}, "The paper file is empty"),
        ({"holders": HOLDERS[:4]}, "Select exactly 5 holders"),
        ({"holders": HOLDERS[:4] + ["adm1"]}, "Select exactly 5 holders"),
        ({"holders": HOLDERS[:4] + ["inv_off"]}, "Select exactly 5 holders"),
        ({"holders": HOLDERS[:4] + ["exm2"]}, "Select exactly 5 holders"),
    ],
)
def test_upload_validation_errors_create_nothing(env, overrides, message):
    response = upload(env, **overrides)
    assert response.status_code == 400
    assert message in response.get_data(as_text=True)
    assert exam_rows() == []


def test_a_huge_request_body_gets_the_file_too_large_page(env):
    huge = (io.BytesIO(b"x" * (11 * 1024 * 1024)), "huge.pdf")
    response = upload(env, paper=huge)
    assert response.status_code == 413 and b"File too large" in response.data
    assert exam_rows() == []


def test_failed_upload_keeps_what_was_typed_and_the_holder_list(env):
    text = upload(env, k="9").get_data(as_text=True)
    assert "Data Structures Final" in text and "CS201" in text
    assert "inv3" in text and "checked" in text


def test_missing_signing_key_and_holder_key_are_friendly(env):
    (env.keys_dir / "inv2_public.pem").unlink()
    assert "Missing or bad holder key for inv2" in upload(env).get_data(as_text=True)
    (env.keys_dir / "examiner_signing.pem").unlink()
    (env.keys_dir / "inv2_public.pem").write_bytes(pem_public(rsa.generate_private_key(public_exponent=65537, key_size=3072)))
    assert "Examiner signing key is missing or invalid" in upload(env).get_data(as_text=True)
    assert exam_rows() == []


# ---------- page 11: my exams ----------

def test_my_exams_empty_state(env):
    text = env.client("exm1").get("/examiner/exams").get_data(as_text=True)
    assert "No exams yet. Upload your first exam." in text and "Upload new exam" in text


def test_my_exams_lists_status_k_of_n_and_shares(env):
    make_exam(env)
    make_exam(env, "Open Window", start=timedelta(minutes=-5))
    make_exam(env, "Old Exam", start=timedelta(hours=-3), end=timedelta(hours=-1))
    text = env.client("exm2").get("/examiner/exams").get_data(as_text=True)  # every examiner sees every exam
    for expected in ("Encrypted", "Window open", "Closed", "3 of 5", "0 / 3", "View", "Window", "k-of-n"):
        assert expected in text


def test_my_exams_marks_a_released_exam(env):
    exam_id = make_exam(env)
    exam_store.mark_released(env.conn, exam_id, "abc", "2026-10-09T10:00:00Z")
    text = env.client("exm1").get("/examiner/exams").get_data(as_text=True)
    assert "Released" in text and "3 / 3" in text


# ---------- page 12: exam detail ----------

def test_detail_page_works_on_a_fresh_database_without_audit_table(env):
    exam_id = make_exam(env)
    response = env.client("exm1").get(f"/examiner/exams/{exam_id}")
    assert response.status_code == 200
    text = response.get_data(as_text=True)
    for expected in ("Exam ID", "Paper hash", "Signature verified", "3 of 5", "Waiting for window to open",
                     "Open Leak Analyzer", "Share submitted", "No copies issued yet", "No log entries"):
        assert expected in text


def test_detail_unknown_exam_is_404(env):
    assert env.client("exm1").get("/examiner/exams/not-an-exam").status_code == 404


def test_detail_events_are_limited_to_this_exam_and_to_ten(env):
    exam_id, other_id = make_exam(env), make_exam(env, "Other")
    for i in range(12):
        log_event(env.conn, "exm1", "exam_created", {"exam_id": exam_id, "n": i})
    log_event(env.conn, "intruder", "login_failed", {"exam_id": other_id})
    text = env.client("exm1").get(f"/examiner/exams/{exam_id}").get_data(as_text=True)
    assert text.count("exam_created") == 10 and "intruder" not in text


def test_detail_shows_released_banner_and_holder_status(env):
    exam_id = make_exam(env, start=timedelta(minutes=-5))
    env.conn.execute(
        "INSERT INTO share_submissions (exam_id, user_id, share_index, submitted_at, proof_nonce, accepted) "
        "VALUES (?, ?, 1, '2026-10-09T10:00:00Z', 'n1', 1)", (exam_id, env.ids["inv1"]),
    )
    env.conn.commit()
    exam_store.mark_released(env.conn, exam_id, "abc", "2026-10-09T10:05:00Z")
    text = env.client("exm1").get(f"/examiner/exams/{exam_id}").get_data(as_text=True)
    assert "Paper released at 2026-10-09T10:05:00Z" in text and "2026-10-09T10:00:00Z" in text
    assert "Waiting for window to open" not in text


def test_detail_flags_a_wrong_examiner_key(env, tmp_path):
    exam_id = make_exam(env)
    other = tmp_path / "other_public.pem"
    other.write_bytes(pem_public(ed25519.Ed25519PrivateKey.generate()))
    env.app.config["EXAMINER_PUBLIC_KEY_PATH"] = str(other)
    assert "Signature invalid" in env.client("exm1").get(f"/examiner/exams/{exam_id}").get_data(as_text=True)
    env.app.config["EXAMINER_PUBLIC_KEY_PATH"] = str(tmp_path / "missing.pem")
    assert "Signature not checked" in env.client("exm1").get(f"/examiner/exams/{exam_id}").get_data(as_text=True)


def test_titles_are_escaped_everywhere(env):
    exam_id = make_exam(env, '<script>alert("x")</script>')
    client = env.client("exm1")
    for path in ("/examiner/exams", f"/examiner/exams/{exam_id}", f"/tracing/analyze?exam_id={exam_id}"):
        text = client.get(path).get_data(as_text=True)
        assert "<script>alert" not in text and "&lt;script&gt;" in text


# ---------- placeholders (pages 13 and 20) ----------

def test_placeholders_render_without_crashing(env):
    assert b"Variants review" in env.client("exm1").get("/examiner/variants").data
    assert b"Leak Analyzer" in env.client("aud1").get("/tracing/analyze?exam_id=unknown").data


# ---------- audit fail-closed ----------

def tamper_audit_chain(env):
    log_event(env.conn, "x", "one", {})
    log_event(env.conn, "x", "two", {})
    for (name,) in env.conn.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'").fetchall():
        env.conn.execute(f"DROP TRIGGER {name}")
    env.conn.execute("UPDATE audit_entries SET details = '{\"edited\": true}' WHERE id = 1")
    env.conn.commit()


def test_tampered_chain_blocks_upload_with_a_friendly_banner(env):
    tamper_audit_chain(env)
    response = upload(env)
    text = response.get_data(as_text=True)
    assert response.status_code == 503
    assert "Audit log check failed" in text and "Traceback" not in text
    assert exam_rows() == []


def test_tampered_chain_blocks_audited_routes_without_a_500(env):
    tamper_audit_chain(env)
    env.app.config["PROPAGATE_EXCEPTIONS"] = False
    response = env.app.test_client().post("/login", data={"username": "nobody", "password": "x" * 12})
    assert response.status_code == 503 and b"Audit log check failed" in response.data


def test_clean_database_without_daily_roots_is_not_treated_as_tampered(env):
    log_event(env.conn, "x", "one", {})
    assert upload(env).status_code == 200  # no Merkle roots exist yet, which is not tampering


# ---------- create_exam additions ----------

def test_create_exam_threshold_rules(env):
    holders = [rsa_pub(env, n) for n in HOLDERS]
    now = datetime.now(timezone.utc)
    args = (PAPER, holders, env.signing, now, now + timedelta(hours=1))
    assert paper_service.create_exam(*args)["threshold"] == 3  # default n//2+1
    assert paper_service.create_exam(*args, threshold=2)["threshold"] == 2
    with pytest.raises(ValueError, match="k cannot be greater than n"):
        paper_service.create_exam(*args, threshold=6)
    with pytest.raises(ValueError, match="at least 2"):
        paper_service.create_exam(*args, threshold=1)
    with pytest.raises(TypeError):
        paper_service.create_exam(*args, threshold=True)
    assert paper_service.create_exam(*args)["paper_hash"] == hashlib.sha256(PAPER).digest()


def test_verify_exam_record(env):
    exam_id = make_exam(env)
    assert paper_service.verify_exam_record(exam_id, env.signing.public_key())
    assert not paper_service.verify_exam_record(exam_id, ed25519.Ed25519PrivateKey.generate().public_key())
    assert not paper_service.verify_exam_record("missing", env.signing.public_key())
    with paper_service._connect_database() as db:
        db.execute("UPDATE exams SET threshold = 2 WHERE exam_id = ?", (exam_id,))
    assert not paper_service.verify_exam_record(exam_id, env.signing.public_key())


# ---------- local time -> UTC (the "window never opens" bug) ----------

def stored_window():
    db = paper_service._connect_database()
    try:
        return db.execute("SELECT release_window_start, release_window_end FROM exams").fetchone()
    finally:
        db.close()


def utc_text(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_browser_converted_utc_time_decides_the_window(env):
    """Typed local time says 2099, but the browser sent the real UTC instant: that one is stored."""
    now = datetime.now(timezone.utc)
    response = upload(
        env, window_start="2099-01-01T10:00", window_end="2099-01-01T11:00",
        window_start_utc=utc_text(now - timedelta(minutes=5)), window_end_utc=utc_text(now + timedelta(hours=2)),
    )
    assert response.status_code == 200
    start, _end = stored_window()
    assert start.startswith(utc_text(now - timedelta(minutes=5))[:16])
    listing = env.client("exm1").get("/examiner/exams").get_data(as_text=True)
    assert "Window open" in listing  # not "Encrypted/Waiting": the window really is open now


def test_pakistan_local_time_no_longer_shifts_the_window_by_five_hours(env):
    """17:30 in Pakistan (UTC+5) is 12:30 UTC; the browser sends 12:30Z, so the window opens on time."""
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    local_start = (now + timedelta(hours=5) - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M")
    local_end = (now + timedelta(hours=7)).strftime("%Y-%m-%dT%H:%M")
    upload(
        env, window_start=local_start, window_end=local_end,
        window_start_utc=utc_text(now - timedelta(minutes=1)), window_end_utc=utc_text(now + timedelta(hours=2)),
    )
    assert "Window open" in env.client("exm1").get("/examiner/exams").get_data(as_text=True)


def test_without_javascript_the_typed_time_is_read_as_utc(env):
    start, end = window()
    upload(env)
    stored_start, stored_end = stored_window()
    assert stored_start.startswith(start) and stored_end.startswith(end)


@pytest.mark.parametrize("bad", ["garbage", "2026-10-10T10:00:00"])  # second one has no timezone
def test_invalid_browser_utc_value_is_refused(env, bad):
    response = upload(env, window_start_utc=bad, window_end_utc=bad)
    assert response.status_code == 400
    assert "Valid start and end date-times are required" in response.get_data(as_text=True)
    assert exam_rows() == []


def test_upload_page_has_the_utc_helper_fields(env):
    text = env.client("exm1").get("/examiner/upload").get_data(as_text=True)
    for expected in ('name="window_start_utc"', 'name="window_end_utc"', "window_start_preview", "upload.js"):
        assert expected in text
    make_exam(env)  # the table (and its header) only shows once an exam exists
    assert "Window (UTC)" in env.client("exm1").get("/examiner/exams").get_data(as_text=True)


def test_browser_conversion_in_pakistan_time_zone():
    import os, shutil, subprocess
    from pathlib import Path
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    js = Path(__file__).resolve().parents[1] / "web" / "static" / "upload.js"
    script = (
        "const u=require(process.argv[1]);"
        "console.log(JSON.stringify([u.toUtcIso('2026-10-10T17:30'),u.toUtcIso(''),u.toUtcIso('nope'),"
        "u.preview('2026-10-10T12:30:00Z')]));"
    )
    done = subprocess.run(
        [node, "-e", script, str(js)], capture_output=True, text=True, timeout=30,
        env={**os.environ, "TZ": "Asia/Karachi"},
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == '["2026-10-10T12:30:00Z","","","UTC: 2026-10-10 12:30:00"]'
