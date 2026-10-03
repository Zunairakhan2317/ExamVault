"""Create and release encrypted exams using threshold-controlled paper keys."""

import hashlib
import json
import secrets
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from crypto.aes_gcm import decrypt, encrypt
from crypto.feldman import Q, commit, verify_share
from crypto.kdf import derive_aes_key, generate_master_secret
from crypto.keywrap import unwrap_share, wrap_share
from crypto.shamir import Point, _eval_poly, combine
from crypto.signing import sign_message, verify_signature

DATABASE_PATH = Path(__file__).resolve().parents[2] / "data" / "examvault.db"
_SHARE_X_BYTES = 4
_SHARE_Y_BYTES = (Q.bit_length() + 7) // 8
_SHARE_BYTES = _SHARE_X_BYTES + _SHARE_Y_BYTES


class ExamCreationResult(TypedDict):
    """Public exam metadata and encrypted shares returned by creation."""

    exam_id: str
    threshold: int
    num_shares: int
    release_window_start: str
    release_window_end: str
    commitments: list[int]
    wrapped_shares: list[bytes]
    signature: bytes


def _connect_database() -> sqlite3.Connection:
    """Open the ignored local exam database and ensure its storage tables exist."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    connection.execute(
        """CREATE TABLE IF NOT EXISTS exams (
            exam_id TEXT PRIMARY KEY,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            paper_hash BLOB NOT NULL,
            threshold INTEGER NOT NULL,
            num_holders INTEGER NOT NULL,
            release_window_start TEXT NOT NULL DEFAULT '',
            release_window_end TEXT NOT NULL DEFAULT '',
            commitments TEXT NOT NULL,
            signature BLOB NOT NULL
        )"""
    )
    existing_columns = {
        row[1] for row in connection.execute("PRAGMA table_info(exams)").fetchall()
    }
    if "release_window_start" not in existing_columns:
        connection.execute(
            "ALTER TABLE exams ADD COLUMN release_window_start TEXT NOT NULL DEFAULT ''"
        )
    if "release_window_end" not in existing_columns:
        connection.execute(
            "ALTER TABLE exams ADD COLUMN release_window_end TEXT NOT NULL DEFAULT ''"
        )
    connection.execute(
        """CREATE TABLE IF NOT EXISTS exam_shares (
            exam_id TEXT NOT NULL,
            x INTEGER NOT NULL,
            wrapped_blob BLOB NOT NULL,
            PRIMARY KEY (exam_id, x),
            FOREIGN KEY (exam_id) REFERENCES exams (exam_id)
        )"""
    )
    return connection


def _signature_payload(
    exam_id: str,
    nonce: bytes,
    ciphertext: bytes,
    paper_hash: bytes,
    threshold: int,
    num_holders: int,
    release_window_start: str,
    release_window_end: str,
    commitments: list[int],
) -> bytes:
    """Build canonical signed metadata binding the paper and its share policy."""
    metadata = {
        "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
        "commitments": [str(value) for value in commitments],
        "exam_id": exam_id,
        "nonce": nonce.hex(),
        "num_holders": num_holders,
        "paper_sha256": paper_hash.hex(),
        "release_window_end": release_window_end,
        "release_window_start": release_window_start,
        "threshold": threshold,
    }
    return b"ExamVault exam record v1\x00" + json.dumps(
        metadata, sort_keys=True, separators=(",", ":")
    ).encode("ascii")


def _normalize_utc_window_time(value: datetime, field_name: str) -> str:
    """Normalize a timezone-aware exam-window endpoint to canonical UTC text."""
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be a timezone-aware datetime")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _encode_share(share: Point) -> bytes:
    """Encode a Shamir point in a fixed-width format before holder wrapping."""
    x, y = share
    return x.to_bytes(_SHARE_X_BYTES, byteorder="big") + y.to_bytes(
        _SHARE_Y_BYTES, byteorder="big"
    )


def _decode_share(share_bytes: bytes) -> Point:
    """Decode a fixed-width share blob, rejecting malformed encodings."""
    if len(share_bytes) != _SHARE_BYTES:
        raise ValueError("Decrypted share has an invalid length")
    x = int.from_bytes(share_bytes[:_SHARE_X_BYTES], byteorder="big")
    y = int.from_bytes(share_bytes[_SHARE_X_BYTES:], byteorder="big")
    return x, y


def create_exam(
    paper_content: bytes,
    holders: list[rsa.RSAPublicKey],
    admin_private_key: ed25519.Ed25519PrivateKey,
    release_window_start: datetime,
    release_window_end: datetime,
) -> ExamCreationResult:
    """Encrypt and share a paper, signing its identity and UTC release window."""
    if not isinstance(paper_content, bytes):
        raise TypeError("paper_content must be bytes")
    if not isinstance(holders, list) or len(holders) < 2:
        raise ValueError("At least two RSA holder public keys are required")
    if not isinstance(admin_private_key, ed25519.Ed25519PrivateKey):
        raise TypeError("admin_private_key must be an Ed25519 private key")
    window_start = _normalize_utc_window_time(
        release_window_start, "release_window_start"
    )
    window_end = _normalize_utc_window_time(release_window_end, "release_window_end")
    if window_start >= window_end:
        raise ValueError("release_window_start must precede release_window_end")

    num_holders = len(holders)
    threshold = num_holders // 2 + 1
    exam_id = str(uuid.uuid4())
    master_secret = generate_master_secret()
    coefficients = [master_secret]
    coefficients.extend(secrets.randbelow(Q) for _ in range(threshold - 1))
    shares = [
        (x, _eval_poly(coefficients, x, Q))
        for x in range(1, num_holders + 1)
    ]
    commitments = commit(coefficients)

    aes_key = derive_aes_key(master_secret)
    nonce, ciphertext = encrypt(paper_content, aes_key, exam_id.encode("utf-8"))
    paper_hash = hashlib.sha256(paper_content).digest()
    wrapped_shares = [
        wrap_share(_encode_share(share), public_key)
        for share, public_key in zip(shares, holders, strict=True)
    ]
    payload = _signature_payload(
        exam_id,
        nonce,
        ciphertext,
        paper_hash,
        threshold,
        num_holders,
        window_start,
        window_end,
        commitments,
    )
    signature = sign_message(admin_private_key, payload)

    with closing(_connect_database()) as connection:
        with connection:
            connection.execute(
                """INSERT INTO exams (
                    exam_id, nonce, ciphertext, paper_hash, threshold,
                    num_holders, release_window_start, release_window_end,
                    commitments, signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    exam_id,
                    nonce,
                    ciphertext,
                    paper_hash,
                    threshold,
                    num_holders,
                    window_start,
                    window_end,
                    json.dumps([str(value) for value in commitments]),
                    signature,
                ),
            )
            connection.executemany(
                "INSERT INTO exam_shares (exam_id, x, wrapped_blob) VALUES (?, ?, ?)",
                [
                    (exam_id, share[0], wrapped_blob)
                    for share, wrapped_blob in zip(shares, wrapped_shares, strict=True)
                ],
            )

    return {
        "exam_id": exam_id,
        "threshold": threshold,
        "num_shares": num_holders,
        "release_window_start": window_start,
        "release_window_end": window_end,
        "commitments": commitments,
        "wrapped_shares": wrapped_shares,
        "signature": signature,
    }


def release_exam(
    exam_id: str,
    submitted_shares: list[bytes],
    holder_private_keys: list[rsa.RSAPrivateKey],
    admin_public_key: ed25519.Ed25519PublicKey,
) -> bytes:
    """Verify submitted holder shares and release the paper after threshold."""
    if not isinstance(exam_id, str):
        raise TypeError("exam_id must be a string")
    if not isinstance(submitted_shares, list) or not isinstance(holder_private_keys, list):
        raise TypeError("submitted_shares and holder_private_keys must be lists")
    if len(submitted_shares) != len(holder_private_keys):
        raise ValueError("Each submitted share must have a corresponding private key")
    if not isinstance(admin_public_key, ed25519.Ed25519PublicKey):
        raise TypeError("admin_public_key must be an Ed25519 public key")

    with closing(_connect_database()) as connection:
        record = connection.execute(
            """SELECT nonce, ciphertext, paper_hash, threshold, num_holders,
                      release_window_start, release_window_end, commitments, signature
               FROM exams WHERE exam_id = ?""",
            (exam_id,),
        ).fetchone()
        if record is None:
            raise ValueError("Unknown exam id")
        stored_shares = connection.execute(
            "SELECT x, wrapped_blob FROM exam_shares WHERE exam_id = ?",
            (exam_id,),
        ).fetchall()

    (
        nonce,
        ciphertext,
        paper_hash,
        threshold,
        num_holders,
        window_start,
        window_end,
        commitments_json,
        signature,
    ) = record
    commitments = [int(value) for value in json.loads(commitments_json)]
    payload = _signature_payload(
        exam_id,
        nonce,
        ciphertext,
        paper_hash,
        threshold,
        num_holders,
        window_start,
        window_end,
        commitments,
    )
    if not verify_signature(admin_public_key, payload, signature):
        raise ValueError("Exam metadata signature is invalid")
    if not window_start or not window_end:
        raise ValueError("Exam is missing a signed release window")
    now = datetime.now(timezone.utc)
    if not (
        datetime.fromisoformat(window_start.replace("Z", "+00:00"))
        <= now
        < datetime.fromisoformat(window_end.replace("Z", "+00:00"))
    ):
        raise ValueError("Exam is outside its release window")

    stored_blob_to_x = {bytes(wrapped_blob): x for x, wrapped_blob in stored_shares}
    accepted_shares: list[Point] = []
    accepted_x: set[int] = set()
    for wrapped_blob, private_key in zip(submitted_shares, holder_private_keys, strict=True):
        if not isinstance(wrapped_blob, bytes) or wrapped_blob not in stored_blob_to_x:
            continue
        try:
            share = _decode_share(unwrap_share(wrapped_blob, private_key))
        except (TypeError, ValueError, InvalidTag):
            continue
        x, y = share
        if (
            x != stored_blob_to_x[wrapped_blob]
            or x in accepted_x
            or not verify_share(x, y, commitments)
        ):
            continue
        accepted_shares.append(share)
        accepted_x.add(x)

    if len(accepted_shares) < threshold:
        raise ValueError("Insufficient valid shares to release exam")

    master_secret = combine(accepted_shares[:threshold], Q)
    aes_key = derive_aes_key(master_secret)
    try:
        paper_content = decrypt(nonce, ciphertext, aes_key, exam_id.encode("utf-8"))
    except InvalidTag as error:
        raise ValueError("Exam ciphertext authentication failed") from error
    if not secrets.compare_digest(hashlib.sha256(paper_content).digest(), paper_hash):
        raise ValueError("Released paper hash does not match signed metadata")
    return paper_content