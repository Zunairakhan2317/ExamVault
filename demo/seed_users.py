"""Create the demo staff accounts (plan Section 9, demo step 1).

Run:  python -m demo.seed_users
All demo accounts share one password that you type at the prompt (never stored in code).
Each account enrols its own 2FA on first login.
"""
from __future__ import annotations

import getpass
import os

from dotenv import load_dotenv

from auth.passwords import check_policy, hash_password
from web.db import get_connection, init_db

USERS = [
    ("admin1", "admin"),
    ("examiner1", "examiner"),
    ("inv1", "invigilator"),
    ("inv2", "invigilator"),
    ("inv3", "invigilator"),
    ("inv4", "invigilator"),
    ("inv5", "invigilator"),
    ("auditor1", "auditor"),
]


def main() -> None:
    """Insert the demo users (existing usernames are left untouched)."""
    load_dotenv()
    path = os.environ.get("DATABASE_PATH", "data/examvault.db")
    password = getpass.getpass("Demo password for all accounts (min 12 characters): ")
    check_policy(password)
    conn = get_connection(path)
    init_db(conn)
    for username, role in USERS:
        conn.execute(
            "INSERT OR IGNORE INTO users (username, role, password_hash) VALUES (?, ?, ?)",
            (username, role, hash_password(password)),
        )
    conn.commit()
    conn.close()
    print(f"Demo users ready: {', '.join(name for name, _ in USERS)}")


if __name__ == "__main__":
    main()