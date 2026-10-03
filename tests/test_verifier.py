"""Tests for complete audit-chain and daily-root verification."""

import json
import sqlite3
from datetime import date
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit.daily_root import compute_daily_root, configure_audit_signing_keys
from audit.hashchain import add_audit_entry
from audit.verifier import main, verify_full_chain


def _signed_database() -> tuple[
    sqlite3.Connection,
    Ed25519PrivateKey,
    str,
]:
    """Create a temporary in-memory database with two signed audit entries."""
    private_key = Ed25519PrivateKey.generate()
    configure_audit_signing_keys(private_key, private_key.public_key())
    database = sqlite3.connect(":memory:")
    target_date = date.today().isoformat()
    add_audit_entry(database, "login", "accepted", "admin-1")
    add_audit_entry(database, "share_submit", "accepted", "holder-2")
    compute_daily_root(database, target_date)
    return database, private_key, target_date


def test_untampered_full_chain_returns_green_status() -> None:
    """Valid row hashes, daily Merkle root, and Ed25519 signature pass."""
    database, _, _ = _signed_database()

    report = verify_full_chain(database)

    assert report["status"] == "green"
    assert report["valid"]
    assert report["hashchain_valid"]
    assert report["daily_roots_valid"]
    assert report["signatures_valid"]
    assert report["altered_entry_indices"] == []


def test_manually_edited_audit_row_returns_red_with_entry_id() -> None:
    """Editing a row while bypassing its trigger reports that exact entry ID."""
    database, _, _ = _signed_database()
    database.execute("DROP TRIGGER audit_entries_no_update")
    database.execute("UPDATE audit_entries SET details = 'tampered' WHERE id = 2")

    report = verify_full_chain(database)

    assert report["status"] == "red"
    assert not report["hashchain_valid"]
    assert report["altered_entry_indices"] == [2]
    assert not report["daily_roots_valid"]


def test_altering_entry_hash_returns_red_with_exact_id() -> None:
    """Changing an entry hash identifies that row and the consequent bad link."""
    database, _, _ = _signed_database()
    database.execute("DROP TRIGGER audit_entries_no_update")
    database.execute(
        "UPDATE audit_entries SET entry_hash = ? WHERE id = 1",
        ("f" * 64,),
    )

    report = verify_full_chain(database)

    assert report["status"] == "red"
    assert report["altered_entry_indices"] == [1]
    assert report["broken_link_indices"] == [2]


def test_reordered_audit_entries_are_detected() -> None:
    """Permuting entry IDs is detected by row hashes, chain links, and daily root."""
    private_key = Ed25519PrivateKey.generate()
    configure_audit_signing_keys(private_key, private_key.public_key())
    database = sqlite3.connect(":memory:")
    for event in ("login", "share_submit", "download"):
        add_audit_entry(database, event, "accepted", "holder-1")
    compute_daily_root(database, date.today().isoformat())

    database.execute("DROP TRIGGER audit_entries_no_update")
    database.execute("UPDATE audit_entries SET id = id + 10")
    database.execute(
        """UPDATE audit_entries
           SET id = CASE id WHEN 11 THEN 2 WHEN 12 THEN 3 WHEN 13 THEN 1 END"""
    )

    report = verify_full_chain(database)

    assert report["status"] == "red"
    assert not report["hashchain_valid"]
    assert report["first_broken_index"] == 1


def test_first_broken_index_is_none_for_clean_chain() -> None:
    """A fully valid chain reports no first broken index."""
    database, _, _ = _signed_database()
    report = verify_full_chain(database)
    assert report["status"] == "green"
    assert report["first_broken_index"] is None
    assert report["altered_entry_indices"] == []
    assert report["broken_link_indices"] == []
    assert report["missing_entry_indices"] == []


def test_altering_entry_5_reports_first_broken_index_5() -> None:
    """Tampering entry 5 reports index 5 as the first (and only) broken entry."""
    private_key = Ed25519PrivateKey.generate()
    configure_audit_signing_keys(private_key, private_key.public_key())
    database = sqlite3.connect(":memory:")
    for event in ("login", "share_submit", "download", "release", "edit"):
        add_audit_entry(database, event, "accepted", "holder-1")
    target_date = date.today().isoformat()
    compute_daily_root(database, target_date)

    database.execute("DROP TRIGGER audit_entries_no_update")
    database.execute("UPDATE audit_entries SET details = 'tampered' WHERE id = 5")

    report = verify_full_chain(database)
    assert report["first_broken_index"] == 5
    assert report["status"] == "red"
    assert report["altered_entry_indices"] == [5]
    assert report["broken_link_indices"] == []
    assert report["missing_entry_indices"] == []


def test_deleting_entry_3_reports_first_broken_index_of_first_affected_entry() -> None:
    """Deleting entry 3 reports the missing entry (3) as the first broken index,
    since it is the lowest index among altered/missing/broken entries."""
    private_key = Ed25519PrivateKey.generate()
    configure_audit_signing_keys(private_key, private_key.public_key())
    database = sqlite3.connect(":memory:")
    for i, event in enumerate(
        ("login", "share_submit", "download", "release", "edit"), start=1
    ):
        add_audit_entry(database, event, "accepted", "holder-1")
    target_date = date.today().isoformat()
    compute_daily_root(database, target_date)

    database.execute("DROP TRIGGER audit_entries_no_update")
    database.execute("DROP TRIGGER audit_entries_no_delete")
    database.execute("DELETE FROM audit_entries WHERE id = 3")

    report = verify_full_chain(database)
    assert report["first_broken_index"] == 3
    assert report["status"] == "red"
    assert report["broken_link_indices"] == [4]
    assert report["missing_entry_indices"] == [3]
    assert report["altered_entry_indices"] == [3]


def test_cli_reports_green_and_returns_success(
    tmp_path: Path,
    capsys: object,
) -> None:
    """The CLI loads a trusted PEM key, verifies a database, and exits zero."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    configure_audit_signing_keys(private_key, public_key)
    database_path = tmp_path / "audit.sqlite3"
    target_date = date.today().isoformat()
    with sqlite3.connect(database_path) as database:
        add_audit_entry(database, "login", "accepted", "admin-1")
        compute_daily_root(database, target_date)

    public_key_path = tmp_path / "audit-public.pem"
    public_key_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    exit_code = main(
        [
            "--database",
            str(database_path),
            "--public-key",
            str(public_key_path),
        ]
    )

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "green"


def test_cli_returns_failure_for_tampered_database(
    tmp_path: Path,
    capsys: object,
) -> None:
    """The CLI emits a red report and nonzero exit code for altered audit data."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    configure_audit_signing_keys(private_key, public_key)
    database_path = tmp_path / "audit.sqlite3"
    with sqlite3.connect(database_path) as database:
        add_audit_entry(database, "login", "accepted", "admin-1")
        compute_daily_root(database, date.today().isoformat())
        database.execute("DROP TRIGGER audit_entries_no_update")
        database.execute("UPDATE audit_entries SET details = 'tampered' WHERE id = 1")

    public_key_path = tmp_path / "audit-public.pem"
    public_key_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    exit_code = main(
        [
            "--database",
            str(database_path),
            "--public-key",
            str(public_key_path),
        ]
    )

    assert exit_code == 1
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "red"
    assert output["altered_entry_indices"] == [1]