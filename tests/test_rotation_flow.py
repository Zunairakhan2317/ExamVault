"""Rotation ceremony (plan 3.7): admin opens it, k current holders approve, the server rotates."""
from __future__ import annotations

import time
from contextlib import closing
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from crypto.services import paper_service
from web import exam_store, rotation_flow, share_flow
from web.db import get_connection, init_db

PAPER = b"Question 1: Explain the CIA triad. (5 marks)"


def _private_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    )


def _public_pem(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


@pytest.fixture(scope="module")
def holder_keys():
    return [rsa.generate_private_key(public_exponent=65537, key_size=3072) for _ in range(5)]


@pytest.fixture
def w(tmp_path, monkeypatch, holder_keys):
    """3-of-4 exam held by inv0..inv3; inv4 is an invigilator with a key file but no share."""
    monkeypatch.setattr(paper_service, "DATABASE_PATH", tmp_path / "paper.db")
    conn = get_connection(tmp_path / "web.db")
    init_db(conn)
    keys_dir = tmp_path / "holder_keys"  # not "keys": conftest already creates tmp_path / "keys"
    keys_dir.mkdir()
    ids = []
    for index, key in enumerate(holder_keys):
        cursor = conn.execute(
            "INSERT INTO users (username, role, password_hash) VALUES (?, 'invigilator', 'x')", (f"inv{index}",)
        )
        ids.append(cursor.lastrowid)
        (keys_dir / f"inv{index}_public.pem").write_bytes(_public_pem(key))
    conn.commit()
    signer = ed25519.Ed25519PrivateKey.generate()
    now = datetime.now(timezone.utc)
    result = paper_service.create_exam(
        PAPER, [k.public_key() for k in holder_keys[:4]], signer,
        now - timedelta(minutes=1), now + timedelta(hours=1), threshold=3,
    )
    exam_store.register_shares(conn, result["exam_id"], result["commitments"], ids[:4], result["wrapped_shares"])
    world = {
        "conn": conn, "ids": ids, "keys": holder_keys, "keys_dir": keys_dir, "signer": signer,
        "exam_id": result["exam_id"], "ceremonies": rotation_flow.RotationCeremonies(),
        "pending": share_flow.PendingShares(),
    }
    yield world
    conn.close()


def _revoke(w, index):
    w["conn"].execute("UPDATE users SET is_active = 0 WHERE id = ?", (w["ids"][index],))
    w["conn"].commit()


def _start(w, extras=(), threshold=None):
    return rotation_flow.start_ceremony(
        w["conn"], w["ceremonies"], exam_id=w["exam_id"], admin_username="admin1", keys_dir=w["keys_dir"],
        extra_holder_ids=[w["ids"][i] for i in extras], new_threshold=threshold,
    )


def _approve(w, index, key_index=None, signer="ok"):
    key = w["keys"][index if key_index is None else key_index]
    load = (lambda: w["signer"]) if signer == "ok" else signer
    return rotation_flow.approve(
        w["conn"], w["ceremonies"], w["pending"], exam_id=w["exam_id"], user_id=w["ids"][index],
        username=f"inv{index}", key_pem=_private_pem(key), keys_dir=w["keys_dir"], load_signing_key=load,
    )


def _stored_blobs(exam_id):
    with closing(paper_service._connect_database()) as db:
        return [bytes(r[1]) for r in db.execute("SELECT x, wrapped_blob FROM exam_shares WHERE exam_id = ? ORDER BY x", (exam_id,))]


def test_full_ceremony_after_revoking_a_holder(w):
    _revoke(w, 3)
    ceremony = _start(w)
    assert ceremony.quorum == 3 and ceremony.new_threshold == 3 and len(ceremony.new_holder_ids) == 3
    w["pending"].add(w["exam_id"], w["ids"][0], b"old-blob", object(), time.time() + 600)

    assert _approve(w, 0)["outcome"] == "approved"
    assert _approve(w, 1) == {"outcome": "approved", "received": 2, "needed": 3}
    done = _approve(w, 2)

    assert done["outcome"] == "rotated" and done["generation"] == 2
    assert w["ceremonies"].get(w["exam_id"]) is None  # in-memory shares are gone
    assert w["pending"].count(w["exam_id"]) == 0  # submissions made with old shares are void
    released = paper_service.release_exam(
        w["exam_id"], _stored_blobs(w["exam_id"]), [w["keys"][i] for i in (0, 1, 2)], w["signer"].public_key()
    )
    assert released == PAPER
    assert exam_store.get_share_row(w["conn"], w["exam_id"], w["ids"][3]) is None  # the leaver holds nothing now


def test_revoked_holder_cannot_approve(w):
    _start(w)
    _revoke(w, 3)
    with pytest.raises(share_flow.ShareRefused) as caught:
        _approve(w, 3)
    assert caught.value.reason == "revoked_certificate"
    assert w["ceremonies"].get(w["exam_id"]).approvals == {}


def test_holder_with_a_revoked_certificate_cannot_approve(w):
    _start(w)
    w["conn"].execute(
        "INSERT INTO certificates (serial, user_id, pem, issued_at, revoked_at) VALUES ('S1', ?, 'pem', 'now', 'now')",
        (w["ids"][1],),
    )
    w["conn"].commit()
    with pytest.raises(share_flow.ShareRefused) as caught:
        _approve(w, 1)
    assert caught.value.reason == "revoked_certificate"


def test_quorum_impossible_refuses_to_start(w):
    _revoke(w, 2)
    _revoke(w, 3)
    with pytest.raises(share_flow.ShareRefused) as caught:
        _start(w)
    assert caught.value.reason == "quorum_impossible"


def test_wrong_private_key_cannot_approve(w):
    _start(w)
    with pytest.raises(share_flow.ShareRefused) as caught:
        _approve(w, 0, key_index=1)  # inv0 uploads inv1's key
    assert caught.value.reason == "share_invalid"


def test_double_approval_is_refused_before_quorum(w):
    _start(w)
    _approve(w, 0)
    with pytest.raises(share_flow.ShareRefused) as caught:
        _approve(w, 0)
    assert caught.value.reason == "already_approved"


def test_non_holder_and_missing_ceremony_are_refused(w):
    with pytest.raises(share_flow.ShareRefused) as no_ceremony:
        _approve(w, 0)
    assert no_ceremony.value.reason == "no_ceremony"
    _start(w)
    with pytest.raises(share_flow.ShareRefused) as outsider:
        _approve(w, 4)
    assert outsider.value.reason == "not_a_holder"


def test_extra_holder_and_lower_threshold(w):
    _revoke(w, 3)
    ceremony = _start(w, extras=[4], threshold=2)
    assert len(ceremony.new_holder_ids) == 4 and ceremony.new_threshold == 2
    for index in (0, 1, 2):
        result = _approve(w, index)
    assert result["outcome"] == "rotated" and result["holders"] == 4 and result["threshold"] == 2
    blobs = _stored_blobs(w["exam_id"])
    released = paper_service.release_exam(
        w["exam_id"], [blobs[0], blobs[3]], [w["keys"][0], w["keys"][4]], w["signer"].public_key()
    )
    assert released == PAPER


def test_bad_start_parameters_are_refused(w):
    (w["keys_dir"] / "inv4_public.pem").unlink()
    with pytest.raises(share_flow.ShareRefused) as no_key:
        _start(w, extras=[4])
    assert no_key.value.reason == "bad_extra_holder"
    with pytest.raises(share_flow.ShareRefused) as bad_k:
        _start(w, threshold=1)
    assert bad_k.value.reason == "bad_threshold"
    _start(w)
    with pytest.raises(share_flow.ShareRefused) as twice:
        _start(w)
    assert twice.value.reason == "already_open"


def test_cancel_and_expiry_forget_the_approvals(w):
    _start(w)
    _approve(w, 0)
    assert rotation_flow.cancel_ceremony(w["conn"], w["ceremonies"], w["exam_id"], "admin1") is True
    assert w["ceremonies"].get(w["exam_id"]) is None
    _start(w)
    assert w["ceremonies"].get(w["exam_id"], now=time.time() + rotation_flow.CEREMONY_TTL_SECONDS + 5) is None


def test_missing_signing_key_changes_nothing_and_can_be_retried(w):
    _revoke(w, 3)
    _start(w)
    _approve(w, 0)
    _approve(w, 1)
    before = _stored_blobs(w["exam_id"])

    def broken():
        raise OSError("no key")

    with pytest.raises(share_flow.ShareRefused) as caught:
        _approve(w, 2, signer=broken)
    assert caught.value.reason == "signing_key_unavailable"
    assert _stored_blobs(w["exam_id"]) == before
    assert _approve(w, 2)["outcome"] == "rotated"  # the same holder retries once the key is back


def test_released_exam_cannot_be_rotated(w):
    exam_store.mark_released(w["conn"], w["exam_id"], "0" * 64, "now")
    with pytest.raises(share_flow.ShareRefused) as caught:
        _start(w)
    assert caught.value.reason == "already_released"


def test_admin_overview_flags_exams_that_need_rotation(w):
    assert rotation_flow.admin_overview(w["conn"], w["ceremonies"], w["keys_dir"])[0]["needs_rotation"] is False
    _revoke(w, 3)
    row = rotation_flow.admin_overview(w["conn"], w["ceremonies"], w["keys_dir"])[0]
    assert row["needs_rotation"] is True and row["usable_count"] == 3 and row["can_start"] is True
    assert [c["username"] for c in row["extras"]] == ["inv4"]
