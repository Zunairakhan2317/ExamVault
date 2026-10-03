"""End-to-end tests for encrypted exam creation and threshold release."""

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from crypto.feldman import Q
from crypto.services import paper_service


@pytest.fixture(scope="module")
def holder_private_keys() -> list[rsa.RSAPrivateKey]:
    """Create RSA-3072 holder keys used for wrapped Shamir shares."""
    return [
        rsa.generate_private_key(public_exponent=65537, key_size=3072)
        for _ in range(3)
    ]


@pytest.fixture(scope="module")
def admin_keys() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Create the Ed25519 key pair that authenticates exam metadata."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


@pytest.fixture(autouse=True)
def isolated_database(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Keep each test's exam records in a temporary SQLite database."""
    monkeypatch.setattr(paper_service, "DATABASE_PATH", tmp_path / "exams.sqlite3")


@pytest.fixture
def active_release_window() -> tuple[datetime, datetime]:
    """Provide timezone-aware UTC endpoints surrounding the current time."""
    now = datetime.now(timezone.utc)
    return now - timedelta(minutes=1), now + timedelta(hours=1)


def test_exam_releases_with_threshold_valid_shares(
    holder_private_keys: list[rsa.RSAPrivateKey],
    admin_keys: tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey],
    active_release_window: tuple[datetime, datetime],
) -> None:
    """Two valid holder shares release the authenticated original paper."""
    paper_content = b"Confidential final exam paper contents"
    admin_private_key, admin_public_key = admin_keys
    exam = paper_service.create_exam(
        paper_content,
        [key.public_key() for key in holder_private_keys],
        admin_private_key,
        *active_release_window,
    )

    released = paper_service.release_exam(
        exam["exam_id"],
        exam["wrapped_shares"][:2],
        holder_private_keys[:2],
        admin_public_key,
    )

    assert exam["threshold"] == 2
    assert released == paper_content


def test_tampered_share_does_not_count_toward_threshold(
    holder_private_keys: list[rsa.RSAPrivateKey],
    admin_keys: tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey],
    active_release_window: tuple[datetime, datetime],
) -> None:
    """A modified wrapped share is rejected, leaving fewer than threshold."""
    admin_private_key, admin_public_key = admin_keys
    exam = paper_service.create_exam(
        b"Tamper-resistant exam contents",
        [key.public_key() for key in holder_private_keys],
        admin_private_key,
        *active_release_window,
    )
    tampered_blob = bytearray(exam["wrapped_shares"][0])
    tampered_blob[-1] ^= 1

    with pytest.raises(ValueError, match="Insufficient valid shares"):
        paper_service.release_exam(
            exam["exam_id"],
            [bytes(tampered_blob), exam["wrapped_shares"][1]],
            holder_private_keys[:2],
            admin_public_key,
        )


def test_release_fails_with_insufficient_shares(
    holder_private_keys: list[rsa.RSAPrivateKey],
    admin_keys: tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey],
    active_release_window: tuple[datetime, datetime],
) -> None:
    """Fewer valid shares than the configured threshold cannot release a paper."""
    admin_private_key, admin_public_key = admin_keys
    exam = paper_service.create_exam(
        b"Threshold-protected contents",
        [key.public_key() for key in holder_private_keys],
        admin_private_key,
        *active_release_window,
    )

    with pytest.raises(ValueError, match="Insufficient valid shares"):
        paper_service.release_exam(
            exam["exam_id"],
            exam["wrapped_shares"][:1],
            holder_private_keys[:1],
            admin_public_key,
        )


def test_window_metadata_tampering_invalidates_admin_signature(
    holder_private_keys: list[rsa.RSAPrivateKey],
    admin_keys: tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey],
    active_release_window: tuple[datetime, datetime],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Changing persisted release-window metadata invalidates its signature."""
    admin_private_key, admin_public_key = admin_keys
    exam = paper_service.create_exam(
        b"Signed release-window contents",
        [key.public_key() for key in holder_private_keys],
        admin_private_key,
        *active_release_window,
    )
    database_path = paper_service.DATABASE_PATH
    original_start = datetime.fromisoformat(
        exam["release_window_start"].replace("Z", "+00:00")
    )
    tampered_start = (original_start + timedelta(seconds=1)).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")
    with sqlite3.connect(database_path) as database:
        database.execute(
            "UPDATE exams SET release_window_start = ? WHERE exam_id = ?",
            (tampered_start, exam["exam_id"]),
        )

    with pytest.raises(ValueError, match="metadata signature is invalid"):
        paper_service.release_exam(
            exam["exam_id"],
            exam["wrapped_shares"][:2],
            holder_private_keys[:2],
            admin_public_key,
        )


def test_release_is_rejected_before_signed_window(
    holder_private_keys: list[rsa.RSAPrivateKey],
    admin_keys: tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey],
) -> None:
    """Valid shares cannot release an exam before its signed UTC window opens."""
    admin_private_key, admin_public_key = admin_keys
    window_start = datetime.now(timezone.utc) + timedelta(hours=1)
    exam = paper_service.create_exam(
        b"Not-yet-releasable contents",
        [key.public_key() for key in holder_private_keys],
        admin_private_key,
        window_start,
        window_start + timedelta(hours=1),
    )

    with pytest.raises(ValueError, match="outside its release window"):
        paper_service.release_exam(
            exam["exam_id"],
            exam["wrapped_shares"][:2],
            holder_private_keys[:2],
            admin_public_key,
        )


def test_create_exam_rejects_naive_or_reversed_window(
    holder_private_keys: list[rsa.RSAPrivateKey],
    admin_keys: tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey],
) -> None:
    """Exam windows must be timezone-aware and have positive duration."""
    admin_private_key, _ = admin_keys
    holders = [key.public_key() for key in holder_private_keys]
    now = datetime.now(timezone.utc)

    with pytest.raises(ValueError, match="timezone-aware"):
        paper_service.create_exam(
            b"invalid window", holders, admin_private_key,
            now.replace(tzinfo=None), now,
        )
    with pytest.raises(ValueError, match="must precede"):
        paper_service.create_exam(
            b"invalid window", holders, admin_private_key, now, now,
        )


def test_exam_shares_sample_polynomial_coefficients_from_full_field(
    holder_private_keys: list[rsa.RSAPrivateKey],
    admin_keys: tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey],
    active_release_window: tuple[datetime, datetime],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exam share polynomials allow zero coefficients from the complete field."""
    requested_ranges: list[int] = []

    def sample_zero(upper_bound: int) -> int:
        requested_ranges.append(upper_bound)
        return 0

    monkeypatch.setattr(paper_service.secrets, "randbelow", sample_zero)
    exam = paper_service.create_exam(
        b"Uniform-field exam shares",
        [key.public_key() for key in holder_private_keys],
        admin_keys[0],
        *active_release_window,
    )

    assert requested_ranges == [Q]
    assert exam["commitments"][1:] == [1]


def test_paper_ciphertext_edit_invalidates_admin_signature(
    holder_private_keys: list[rsa.RSAPrivateKey],
    admin_keys: tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey],
    active_release_window: tuple[datetime, datetime],
) -> None:
    """Editing the stored encrypted paper invalidates its signed metadata."""
    admin_private_key, admin_public_key = admin_keys
    exam = paper_service.create_exam(
        b"Signed exam paper contents",
        [key.public_key() for key in holder_private_keys],
        admin_private_key,
        *active_release_window,
    )
    with sqlite3.connect(paper_service.DATABASE_PATH) as database:
        ciphertext = bytearray(
            database.execute(
                "SELECT ciphertext FROM exams WHERE exam_id = ?",
                (exam["exam_id"],),
            ).fetchone()[0]
        )
        ciphertext[0] ^= 1
        database.execute(
            "UPDATE exams SET ciphertext = ? WHERE exam_id = ?",
            (bytes(ciphertext), exam["exam_id"]),
        )

    with pytest.raises(ValueError, match="metadata signature is invalid"):
        paper_service.release_exam(
            exam["exam_id"],
            exam["wrapped_shares"][:2],
            holder_private_keys[:2],
            admin_public_key,
        )


def test_exam_id_change_invalidates_admin_signature(
    holder_private_keys: list[rsa.RSAPrivateKey],
    admin_keys: tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey],
    active_release_window: tuple[datetime, datetime],
) -> None:
    """Changing the stored exam identifier invalidates its signed metadata."""
    admin_private_key, admin_public_key = admin_keys
    exam = paper_service.create_exam(
        b"Exam identifier binding",
        [key.public_key() for key in holder_private_keys],
        admin_private_key,
        *active_release_window,
    )
    changed_exam_id = f"{exam['exam_id']}-changed"
    with sqlite3.connect(paper_service.DATABASE_PATH) as database:
        database.execute(
            "UPDATE exams SET exam_id = ? WHERE exam_id = ?",
            (changed_exam_id, exam["exam_id"]),
        )

    with pytest.raises(ValueError, match="metadata signature is invalid"):
        paper_service.release_exam(
            changed_exam_id,
            exam["wrapped_shares"][:2],
            holder_private_keys[:2],
            admin_public_key,
        )


def test_duplicate_share_index_does_not_meet_threshold(
    holder_private_keys: list[rsa.RSAPrivateKey],
    admin_keys: tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey],
    active_release_window: tuple[datetime, datetime],
) -> None:
    """Submitting the same holder share twice counts its index only once."""
    admin_private_key, admin_public_key = admin_keys
    exam = paper_service.create_exam(
        b"Duplicate share index check",
        [key.public_key() for key in holder_private_keys],
        admin_private_key,
        *active_release_window,
    )

    with pytest.raises(ValueError, match="Insufficient valid shares"):
        paper_service.release_exam(
            exam["exam_id"],
            [exam["wrapped_shares"][0], exam["wrapped_shares"][0]],
            [holder_private_keys[0], holder_private_keys[0]],
            admin_public_key,
        )


def test_existing_exam_database_schema_is_migrated_in_place(
    holder_private_keys: list[rsa.RSAPrivateKey],
    admin_keys: tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey],
    active_release_window: tuple[datetime, datetime],
) -> None:
    """Existing exam records retain their table while new window columns are added."""
    with sqlite3.connect(paper_service.DATABASE_PATH) as database:
        database.execute(
            """CREATE TABLE exams (
                exam_id TEXT PRIMARY KEY,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                paper_hash BLOB NOT NULL,
                threshold INTEGER NOT NULL,
                num_holders INTEGER NOT NULL,
                commitments TEXT NOT NULL,
                signature BLOB NOT NULL
            )"""
        )

    paper_content = b"Existing database migration check"
    exam = paper_service.create_exam(
        paper_content,
        [key.public_key() for key in holder_private_keys],
        admin_keys[0],
        *active_release_window,
    )
    with sqlite3.connect(paper_service.DATABASE_PATH) as database:
        columns = {
            row[1] for row in database.execute("PRAGMA table_info(exams)").fetchall()
        }

    assert "release_window_start" in columns
    assert "release_window_end" in columns
    assert paper_service.release_exam(
        exam["exam_id"],
        exam["wrapped_shares"][:2],
        holder_private_keys[:2],
        admin_keys[1],
    ) == paper_content