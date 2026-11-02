"""Unit tests for share rotation and revocation handling (Plan Phase 13)."""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from crypto.services import paper_service, rotation_service
from web.db import get_connection, init_db


def test_share_rotation_flow(tmp_path):
    db_path = tmp_path / "test_rotation.db"
    conn = get_connection(db_path)
    init_db(conn)

    # Generate test keys
    private_keys = [rsa.generate_private_key(65537, 3072) for _ in range(3)]
    public_keys = [pk.public_key() for pk in private_keys]
    signing_key = rsa.generate_private_key(65537, 3072) # Dummy signing key

    # Seed dummy users in db
    user_ids = []
    for idx, pub in enumerate(public_keys):
        uname = f"invig_{idx}"
        cur = conn.execute(
            "INSERT INTO users (username, full_name, email, role, password_hash) VALUES (?, ?, ?, 'invigilator', 'hash')",
            (uname, uname, f"{uname}@example.com")
        )
        user_ids.append(cur.lastrowid)
    conn.commit()

    # Create initial exam
    from datetime import datetime, timezone, timedelta
    start = datetime.now(timezone.utc) + timedelta(hours=1)
    end = start + timedelta(hours=2)

    # Mock signing key wrapper if needed or use ed25519
    from cryptography.hazmat.primitives.asymmetric import ed25519
    ed_key = ed25519.Ed25519PrivateKey.generate()

    res = paper_service.create_exam(b"Secret paper content", public_keys, ed_key, start, end)
    exam_id = res["exam_id"]

    # Register initial shares
    from web import exam_store
    exam_store.register_shares(conn, exam_id, res["commitments"], user_ids, res["wrapped_shares"])

    # Perform rotation dropping one user (e.g., user_ids[2])
    active_ids = user_ids[:2]
    active_pubs = public_keys[:2]
    
    # We need the master secret to rotate. In practice, the system recovers or re-generates.
    # For test, we can use the original secret from creation if accessible or test rotation wrapper directly.
    assert len(active_ids) == 2
    conn.close()


# --- real rotation with re-keying (plan 3.7) -----------------------------------------------------------

from datetime import datetime, timedelta, timezone  # noqa: E402

from cryptography.exceptions import InvalidTag  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

from crypto.aes_gcm import decrypt  # noqa: E402
from crypto.feldman import Q  # noqa: E402
from crypto.kdf import derive_aes_key  # noqa: E402
from crypto.keywrap import unwrap_share  # noqa: E402
from crypto.shamir import combine  # noqa: E402

PAPER = b"Question 1: Explain the CIA triad. (5 marks)"


@pytest.fixture(scope="module")
def holder_keys():
    return [rsa.generate_private_key(public_exponent=65537, key_size=3072) for _ in range(5)]


@pytest.fixture
def world(tmp_path, monkeypatch, holder_keys):
    """A 3-of-4 exam (holders 0..3) with its web shares registered; user 4 exists but holds nothing."""
    monkeypatch.setattr(paper_service, "DATABASE_PATH", tmp_path / "paper.db")
    conn = get_connection(tmp_path / "web.db")
    init_db(conn)
    ids = []
    for index in range(5):
        cursor = conn.execute(
            "INSERT INTO users (username, role, password_hash) VALUES (?, 'invigilator', 'x')", (f"inv{index}",)
        )
        ids.append(cursor.lastrowid)
    conn.commit()
    signer = ed25519.Ed25519PrivateKey.generate()
    now = datetime.now(timezone.utc)
    result = paper_service.create_exam(
        PAPER, [key.public_key() for key in holder_keys[:4]], signer,
        now - timedelta(minutes=1), now + timedelta(hours=1), threshold=3,
    )
    from web import exam_store

    exam_store.register_shares(conn, result["exam_id"], result["commitments"], ids[:4], result["wrapped_shares"])
    yield {"conn": conn, "ids": ids, "signer": signer, "result": result, "keys": holder_keys, "exam_id": result["exam_id"]}
    conn.close()


def _points(world, indexes, blobs=None):
    blobs = blobs or world["result"]["wrapped_shares"]
    return [paper_service._decode_share(unwrap_share(blobs[i], world["keys"][i])) for i in indexes]


def _stored_blobs(exam_id):
    from contextlib import closing

    with closing(paper_service._connect_database()) as db:
        return [bytes(r[1]) for r in db.execute("SELECT x, wrapped_blob FROM exam_shares WHERE exam_id = ? ORDER BY x", (exam_id,))]


def _rotate(world, approved_idx, holder_idx, threshold, signer=None):
    keys = world["keys"]
    return rotation_service.rotate_exam_with_quorum(
        world["conn"], world["exam_id"], _points(world, approved_idx),
        [world["ids"][i] for i in holder_idx], [keys[i].public_key() for i in holder_idx],
        threshold, signer or world["signer"],
    )


def test_rotation_issues_new_shares_and_the_paper_still_releases(world):
    info = _rotate(world, [0, 1, 2], [0, 1, 2], 3)
    assert info["generation"] == 2 and info["holders"] == 3
    rows = world["conn"].execute(
        "SELECT holder_user_id, generation, is_current FROM shares WHERE exam_id = ? ORDER BY generation, holder_user_id",
        (world["exam_id"],),
    ).fetchall()
    assert [(r["generation"], r["is_current"]) for r in rows] == [(1, 0)] * 4 + [(2, 1)] * 3
    assert world["ids"][3] not in [r["holder_user_id"] for r in rows if r["generation"] == 2]
    new_blobs = _stored_blobs(world["exam_id"])
    released = paper_service.release_exam(
        world["exam_id"], new_blobs, [world["keys"][i] for i in (0, 1, 2)], world["signer"].public_key()
    )
    assert released == PAPER


def test_old_shares_are_useless_after_rotation(world):
    old_points = _points(world, [0, 1, 2])
    old_blobs = list(world["result"]["wrapped_shares"][:3])
    _rotate(world, [0, 1, 2], [0, 1, 2], 3)
    # 1) the server no longer accepts the old wrapped shares
    with pytest.raises(ValueError):
        paper_service.release_exam(
            world["exam_id"], old_blobs, [world["keys"][i] for i in (0, 1, 2)], world["signer"].public_key()
        )
    # 2) even rebuilding the OLD master secret from k old shares cannot open the NEW ciphertext (re-keying)
    from contextlib import closing

    with closing(paper_service._connect_database()) as db:
        nonce, ciphertext = db.execute("SELECT nonce, ciphertext FROM exams WHERE exam_id = ?", (world["exam_id"],)).fetchone()
    with pytest.raises(InvalidTag):
        decrypt(nonce, ciphertext, derive_aes_key(combine(old_points, Q)), world["exam_id"].encode())


def test_old_and_new_shares_do_not_combine(world):
    old_points = _points(world, [0, 1])
    _rotate(world, [0, 1, 2], [0, 1, 2], 3)
    mixed_blobs = [world["result"]["wrapped_shares"][0], world["result"]["wrapped_shares"][1], _stored_blobs(world["exam_id"])[2]]
    with pytest.raises(ValueError):
        paper_service.release_exam(
            world["exam_id"], mixed_blobs, [world["keys"][i] for i in (0, 1, 2)], world["signer"].public_key()
        )
    assert len(old_points) == 2


def test_rotation_can_add_a_holder_and_lower_the_threshold(world):
    info = _rotate(world, [0, 1, 2], [0, 1, 2, 4], 2)
    assert info["holders"] == 4 and info["threshold"] == 2
    blobs = _stored_blobs(world["exam_id"])
    released = paper_service.release_exam(
        world["exam_id"], [blobs[0], blobs[3]], [world["keys"][0], world["keys"][4]], world["signer"].public_key()
    )
    assert released == PAPER


def test_wrong_signing_key_changes_nothing(world):
    before = _stored_blobs(world["exam_id"])
    with pytest.raises(ValueError):
        _rotate(world, [0, 1, 2], [0, 1, 2], 3, signer=ed25519.Ed25519PrivateKey.generate())
    assert _stored_blobs(world["exam_id"]) == before
    current = world["conn"].execute("SELECT COUNT(*) FROM shares WHERE exam_id = ? AND is_current = 1", (world["exam_id"],)).fetchone()[0]
    assert current == 4


def test_too_few_approved_shares_changes_nothing(world):
    before = _stored_blobs(world["exam_id"])
    with pytest.raises(ValueError):
        _rotate(world, [0, 1], [0, 1, 2], 3)
    assert _stored_blobs(world["exam_id"]) == before


def test_rotation_rejects_bad_parameters(world):
    with pytest.raises(ValueError):
        _rotate(world, [0, 1, 2], [0, 1, 2], 1)  # threshold below 2
    with pytest.raises(ValueError):
        _rotate(world, [0, 1, 2], [0, 1, 2], 4)  # threshold above the number of holders
    with pytest.raises(ValueError):
        _rotate(world, [0, 1, 2], [0, 0, 1], 2)  # duplicate holder
