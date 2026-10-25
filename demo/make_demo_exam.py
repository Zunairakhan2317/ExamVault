"""Create a demo exam for the share submission flow (plan Section 9, demo steps 2 and 3).

Run (after python -m demo.seed_users):
    python -m demo.make_demo_exam --start-in-minutes 0 --duration-minutes 120

What it does: makes an RSA-3072 keypair for every invigilator and an Ed25519 signing keypair for the
examiner (files in the git-ignored keys/ folder, demo only), encrypts a sample paper with
crypto.services.paper_service.create_exam, and records which invigilator holds which wrapped share.
Invigilators later upload keys/<username>_private.pem on the submit page.
"""
from __future__ import annotations

import argparse
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from dotenv import load_dotenv

from crypto.services import paper_service
from web import exam_store
from web.audit_log import log_event
from web.db import get_connection, init_db

KEYS_DIR = Path("keys")
SAMPLE_PAPER = (
    b"ExamVault demo paper\n"
    b"Q1. Explain how a stack works. [5 marks]\n"
    b"Q2. Define a queue and give two uses. [5 marks]\n"
)


def _write_private(path: Path, pem: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def ensure_rsa_public_key(username: str, conn: sqlite3.Connection, user_id: int) -> rsa.RSAPublicKey:
    """Return the holder's RSA-3072 public key, creating the keypair files if needed."""
    private_path = KEYS_DIR / f"{username}_private.pem"
    public_path = KEYS_DIR / f"{username}_public.pem"

    if public_path.exists():
        key = serialization.load_pem_public_key(public_path.read_bytes())
        if not isinstance(key, rsa.RSAPublicKey):
            raise RuntimeError(f"{public_path} is not an RSA public key")
        return key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    _write_private(
        private_path,
        private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return private_key.public_key()


def ensure_signing_key() -> ed25519.Ed25519PrivateKey:
    """Return the examiner's Ed25519 signing key (public half saved for the release step)."""
    private_path = KEYS_DIR / "examiner_signing.pem"
    public_path = KEYS_DIR / "examiner_signing_public.pem"
    if private_path.exists():
        key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise RuntimeError(f"{private_path} is not an Ed25519 key")
    else:
        key = ed25519.Ed25519PrivateKey.generate()
        _write_private(
            private_path,
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ),
        )
    public_path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return key


def main(argv: list[str] | None = None) -> None:
    """Create one demo exam and print how to use it."""
    parser = argparse.ArgumentParser(description="Create an ExamVault demo exam")
    parser.add_argument("--start-in-minutes", type=int, default=0)
    parser.add_argument("--duration-minutes", type=int, default=120)
    parser.add_argument("--paper", type=Path, default=None, help="optional paper file (default: sample text)")
    args = parser.parse_args(argv)

    load_dotenv()
    conn = get_connection(os.environ.get("DATABASE_PATH", "data/examvault.db"))
    init_db(conn)
    holders = conn.execute(
        "SELECT id, username FROM users WHERE role = 'invigilator' AND is_active = 1 ORDER BY username"
    ).fetchall()
    if len(holders) < 2:
        raise SystemExit("Need at least 2 invigilators. Run: python -m demo.seed_users")
    public_keys = [ensure_rsa_public_key(row["username"], conn, row["id"]) for row in holders]
    signing_key = ensure_signing_key()
    start = datetime.now(timezone.utc) + timedelta(minutes=args.start_in_minutes)
    end = start + timedelta(minutes=args.duration_minutes)
    paper = args.paper.read_bytes() if args.paper else SAMPLE_PAPER
    result = paper_service.create_exam(paper, public_keys, signing_key, start, end)
    exam_store.register_shares(
        conn, result["exam_id"], result["commitments"], [row["id"] for row in holders], result["wrapped_shares"]
    )
    log_event(
        conn, "demo_script", "exam_created",
        {"exam_id": result["exam_id"], "threshold": result["threshold"], "holders": len(holders)},
    )
    conn.close()
    print(f"Exam id:    {result['exam_id']}")
    print(f"Threshold:  {result['threshold']} of {result['num_shares']} shares")
    print(f"Window UTC: {result['release_window_start']} to {result['release_window_end']}")
    print(f"Holders:    {', '.join(row['username'] for row in holders)}")
    print(f"Open:       http://localhost:5000/invigilator/exam/{result['exam_id']}")
    print("Each holder uploads keys/<username>_private.pem on the submit page (demo keys, git-ignored).")


if __name__ == "__main__":
    main()