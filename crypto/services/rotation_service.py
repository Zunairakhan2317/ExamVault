"""Share rotation service for handling invigilator revocations and re-issuing shares (Plan Phase 13)."""
from __future__ import annotations

import secrets
import sqlite3
from typing import Any
from cryptography.hazmat.primitives.asymmetric import rsa

from crypto.feldman import Q, commit
from crypto.shamir import _eval_poly
from crypto.keywrap import wrap_share
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