from auth.passwords import verify_password
from demo import seed_users
from web.db import get_connection

PASSWORD = "Tr1cky-Exam-Vault!"


def test_seed_creates_hashed_users_once(tmp_path, monkeypatch):
    db_path = str(tmp_path / "seed.db")
    monkeypatch.setenv("DATABASE_PATH", db_path)
    monkeypatch.setattr(seed_users.getpass, "getpass", lambda _prompt: PASSWORD)
    seed_users.main()
    seed_users.main()  # running twice must not duplicate users
    conn = get_connection(db_path)
    rows = conn.execute("SELECT username, role, password_hash, totp_secret_encrypted FROM users").fetchall()
    conn.close()
    assert len(rows) == 8
    assert {r["role"] for r in rows} == {"admin", "examiner", "invigilator", "auditor"}
    for row in rows:
        assert row["password_hash"] != PASSWORD and verify_password(row["password_hash"], PASSWORD)
        assert row["totp_secret_encrypted"] is None