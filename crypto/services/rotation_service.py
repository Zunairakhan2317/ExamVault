"""Share rotation service for handling invigilator revocations and re-issuing shares (Plan Phase 13)."""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from contextlib import closing
from typing import Any
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from crypto.aes_gcm import decrypt, encrypt
from crypto.feldman import Q, commit, verify_share
from crypto.kdf import derive_aes_key, generate_master_secret
from crypto.services import paper_service
from crypto.shamir import _eval_poly, combine
from crypto.keywrap import wrap_share
from crypto.signing import sign_message, verify_signature
from web import exam_store
from web.audit_log import log_event


def rotate_exam_shares(
    conn: sqlite3.Connection,
    exam_id: str,
    master_secret: bytes,
    active_invigilator_ids: list[int],
    active_public_keys: list[rsa.RSAPublicKey | Any],
    threshold: int,
    admin_username: str,
) -> dict[str, Any]:
    """
    Revokes old shares for an exam and redistributes new shares among currently active invigilators.
    """
    conn.execute("DELETE FROM shares WHERE exam_id = ? AND is_current = 1", (exam_id,))
    
    num_shares = len(active_invigilator_ids)
    if num_shares < threshold:
        raise ValueError(f"Active invigilator count ({num_shares}) is below threshold ({threshold}).")

    coefficients = [master_secret]
    coefficients.extend(secrets.randbelow(Q) for _ in range(threshold - 1))
    shares = [
        (x, _eval_poly(coefficients, x, Q))
        for x in range(1, num_shares + 1)
    ]
    commitments = commit(coefficients)

    def _encode_share(share):
        _SHARE_X_BYTES = 4
        _SHARE_Y_BYTES = (Q.bit_length() + 7) // 8
        x, y = share
        return x.to_bytes(_SHARE_X_BYTES, byteorder="big") + y.to_bytes(_SHARE_Y_BYTES, byteorder="big")

    wrapped_shares = [
        wrap_share(_encode_share(share), public_key)
        for share, public_key in zip(shares, active_public_keys, strict=True)
    ]

    exam_store.register_shares(
        conn, exam_id, commitments, active_invigilator_ids, wrapped_shares
    )

    log_event(
        conn,
        admin_username,
        "shares_rotated",
        {"exam_id": exam_id, "active_holders_count": num_shares, "threshold": threshold},
    )
    conn.commit()

    return {
        "exam_id": exam_id,
        "num_shares": num_shares,
        "threshold": threshold,
        "active_holders": active_invigilator_ids,
    }


def rotate_exam_with_quorum(
    conn: sqlite3.Connection,
    exam_id: str,
    approved_shares: list[tuple[int, int]],
    new_holder_ids: list[int],
    new_holder_public_keys: list[rsa.RSAPublicKey],
    new_threshold: int,
    signing_key: ed25519.Ed25519PrivateKey,
) -> dict[str, Any]:
    """Real share rotation with re-keying (plan 3.7, the "stronger option").

    Security properties:
    - The old paper key is rebuilt IN MEMORY ONLY from at least k verified shares approved by current holders.
    - The paper is decrypted and immediately re-encrypted under a brand-new master secret, and a brand-new
      polynomial is split among the new holder set. Shares of a revoked holder (even k of them collected
      earlier) are useless for the new ciphertext, and the old ciphertext is no longer stored.
    - The examiner signature is renewed over the new ciphertext, commitments and policy, and the signing key
      must be the one that signed the exam originally (otherwise nothing changes).
    - Old web shares become is_current = 0 and the generation counter goes up; old share submissions are
      marked not accepted. The paper database and the web database are updated together; if the second
      update fails the first is rolled back by hand.
    Raises ValueError with a safe message when anything is wrong; nothing is changed in that case.
    """
    if not isinstance(exam_id, str) or not exam_id:
        raise ValueError("Unknown exam id")
    if len(new_holder_ids) != len(new_holder_public_keys) or len(set(new_holder_ids)) != len(new_holder_ids):
        raise ValueError("Each new holder needs exactly one public key")
    num_new = len(new_holder_ids)
    if not isinstance(new_threshold, int) or isinstance(new_threshold, bool) or not 2 <= new_threshold <= num_new:
        raise ValueError("Require 2 <= threshold <= number of holders")
    if not isinstance(signing_key, ed25519.Ed25519PrivateKey):
        raise TypeError("signing_key must be an Ed25519 private key")

    with closing(paper_service._connect_database()) as paper_db:
        record = paper_db.execute(
            """SELECT nonce, ciphertext, paper_hash, threshold, num_holders, release_window_start,
                      release_window_end, commitments, signature FROM exams WHERE exam_id = ?""",
            (exam_id,),
        ).fetchone()
        old_share_rows = paper_db.execute(
            "SELECT x, wrapped_blob FROM exam_shares WHERE exam_id = ?", (exam_id,)
        ).fetchall()
    if record is None:
        raise ValueError("Unknown exam id")
    nonce, ciphertext, paper_hash, old_k, old_n, start, end, commitments_json, old_signature = record
    old_commitments = [int(value) for value in json.loads(commitments_json)]

    old_payload = paper_service._signature_payload(
        exam_id, nonce, ciphertext, paper_hash, old_k, old_n, start, end, old_commitments
    )
    if not verify_signature(signing_key.public_key(), old_payload, old_signature):
        raise ValueError("The signing key does not match this exam")

    distinct: dict[int, int] = {}
    for x, y in approved_shares:
        if verify_share(x, y, old_commitments):
            distinct.setdefault(x, y)
    if len(distinct) < old_k:
        raise ValueError("Not enough valid approved shares to rotate")
    old_secret = combine(sorted(distinct.items())[:old_k], Q)
    try:
        plaintext = decrypt(nonce, ciphertext, derive_aes_key(old_secret), exam_id.encode("utf-8"))
    except InvalidTag as error:
        raise ValueError("The approved shares do not rebuild this paper's key") from error
    if not secrets.compare_digest(hashlib.sha256(plaintext).digest(), bytes(paper_hash)):
        raise ValueError("Decrypted paper does not match the signed hash")

    new_secret = generate_master_secret()
    coefficients = [new_secret] + [secrets.randbelow(Q) for _ in range(new_threshold - 1)]
    new_points = [(x, _eval_poly(coefficients, x, Q)) for x in range(1, num_new + 1)]
    new_commitments = commit(coefficients)
    new_nonce, new_ciphertext = encrypt(plaintext, derive_aes_key(new_secret), exam_id.encode("utf-8"))
    wrapped = [
        wrap_share(paper_service._encode_share(point), public_key)
        for point, public_key in zip(new_points, new_holder_public_keys, strict=True)
    ]
    new_payload = paper_service._signature_payload(
        exam_id, new_nonce, new_ciphertext, paper_hash, new_threshold, num_new, start, end, new_commitments
    )
    new_signature = sign_message(signing_key, new_payload)
    commitments_text = json.dumps([str(value) for value in new_commitments])

    generation = int(conn.execute("SELECT COALESCE(MAX(generation), 0) FROM shares WHERE exam_id = ?", (exam_id,)).fetchone()[0]) + 1

    with closing(paper_service._connect_database()) as paper_db:
        with paper_db:
            paper_db.execute(
                """UPDATE exams SET nonce = ?, ciphertext = ?, threshold = ?, num_holders = ?,
                          commitments = ?, signature = ? WHERE exam_id = ?""",
                (new_nonce, new_ciphertext, new_threshold, num_new, commitments_text, new_signature, exam_id),
            )
            paper_db.execute("DELETE FROM exam_shares WHERE exam_id = ?", (exam_id,))
            paper_db.executemany(
                "INSERT INTO exam_shares (exam_id, x, wrapped_blob) VALUES (?, ?, ?)",
                [(exam_id, point[0], blob) for point, blob in zip(new_points, wrapped, strict=True)],
            )
    try:
        with conn:
            conn.execute("UPDATE shares SET is_current = 0 WHERE exam_id = ?", (exam_id,))
            for index, (holder_id, blob) in enumerate(zip(new_holder_ids, wrapped, strict=True), start=1):
                conn.execute(
                    "INSERT INTO shares (exam_id, holder_user_id, wrapped_share_blob, share_index, "
                    "feldman_commitments_json, generation, is_current) VALUES (?, ?, ?, ?, ?, ?, 1)",
                    (exam_id, int(holder_id), bytes(blob), index, commitments_text, generation),
                )
            conn.execute("UPDATE share_submissions SET accepted = 0 WHERE exam_id = ?", (exam_id,))
    except Exception:
        with closing(paper_service._connect_database()) as paper_db:  # put the paper database back as it was
            with paper_db:
                paper_db.execute(
                    """UPDATE exams SET nonce = ?, ciphertext = ?, threshold = ?, num_holders = ?,
                              commitments = ?, signature = ? WHERE exam_id = ?""",
                    (nonce, ciphertext, old_k, old_n, commitments_json, old_signature, exam_id),
                )
                paper_db.execute("DELETE FROM exam_shares WHERE exam_id = ?", (exam_id,))
                paper_db.executemany(
                    "INSERT INTO exam_shares (exam_id, x, wrapped_blob) VALUES (?, ?, ?)",
                    [(exam_id, x, bytes(blob)) for x, blob in old_share_rows],
                )
        raise
    return {"exam_id": exam_id, "generation": generation, "threshold": new_threshold, "holders": num_new}
