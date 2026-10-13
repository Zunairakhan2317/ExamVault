"""Verify the audit hash chain and signed daily Merkle roots."""

import argparse
import json
import sqlite3
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from audit.daily_root import (
    configure_audit_verification_key,
    verify_daily_root,
)
from audit.hashchain import _entry_hash, verify_hashchain
from audit.merkle import build_merkle_tree, get_merkle_root


def _inspect_hashchain(db_conn: sqlite3.Connection) -> dict[str, Any]:
    """Recompute row digests and links while identifying affected audit IDs."""
    try:
        rows = db_conn.execute(
            """SELECT id, timestamp, event_type, details, actor, prev_hash, entry_hash
               FROM audit_entries ORDER BY id ASC"""
        ).fetchall()
    except sqlite3.Error as error:
        return {
            "valid": False,
            "altered_entry_indices": [],
            "broken_link_indices": [],
            "missing_entry_indices": [],
            "entry_dates": [],
            "error": str(error),
        }

    altered_entry_indices: set[int] = set()
    broken_link_indices: set[int] = set()
    missing_entry_indices: set[int] = set()
    entry_dates: set[str] = set()
    expected_id = 1
    previous_stored_hash = "0" * 64

    for row in rows:
        entry_id, timestamp, event_type, details, actor, prev_hash, stored_hash = row
        if not isinstance(entry_id, int):
            continue
        if entry_id > expected_id:
            missing_entry_indices.update(range(expected_id, entry_id))
        elif entry_id < expected_id:
            altered_entry_indices.add(entry_id)
        expected_id = entry_id + 1

        if not all(
            isinstance(value, str)
            for value in (timestamp, event_type, details, actor, prev_hash, stored_hash)
        ):
            altered_entry_indices.add(entry_id)
            previous_stored_hash = str(stored_hash)
            continue

        if timestamp[:10]:
            entry_dates.add(timestamp[:10])
        if prev_hash != previous_stored_hash:
            broken_link_indices.add(entry_id)
        try:
            calculated_hash = _entry_hash(
                entry_id,
                timestamp,
                event_type,
                details,
                actor,
                prev_hash,
            )
        except (TypeError, ValueError):
            altered_entry_indices.add(entry_id)
        else:
            if stored_hash != calculated_hash:
                altered_entry_indices.add(entry_id)
        previous_stored_hash = stored_hash

    if not rows:
        try:
            db_conn.execute("SELECT 1 FROM audit_entries LIMIT 1")
        except sqlite3.Error as error:
            return {
                "valid": False,
                "altered_entry_indices": [],
                "broken_link_indices": [],
                "missing_entry_indices": [],
                "entry_dates": [],
                "error": str(error),
            }

    altered = sorted(altered_entry_indices | missing_entry_indices)
    broken_links = sorted(broken_link_indices)
    is_valid = not altered and not broken_links and verify_hashchain(db_conn)
    return {
        "valid": is_valid,
        "altered_entry_indices": altered,
        "broken_link_indices": broken_links,
        "missing_entry_indices": sorted(missing_entry_indices),
        "entry_dates": sorted(entry_dates),
    }


def _inspect_daily_roots(
    db_conn: sqlite3.Connection,
    entry_dates: list[str],
) -> dict[str, Any]:
    """Recompute stored daily roots and verify their configured signatures."""
    # The current UTC day is still "open": a root signed now would stop matching with the next log entry,
    # so only COMPLETED days must already have a signed root.
    today = datetime.now(timezone.utc).date().isoformat()
    completed_days = sorted(day for day in set(entry_dates) if day < today)
    try:
        root_rows = db_conn.execute(
            "SELECT target_date, merkle_root, entry_count FROM merkle_roots ORDER BY target_date"
        ).fetchall()
    except sqlite3.Error as error:
        # No roots table yet: that is only a problem once a COMPLETED day exists that should have been sealed.
        return {
            "valid": not completed_days,
            "signature_valid": not completed_days,
            "missing_dates": completed_days,
            "invalid_dates": [],
            "error": str(error),
        }

    roots_by_date = {str(target_date): (str(root), int(count)) for target_date, root, count in root_rows}
    missing_dates = sorted(set(completed_days) - set(roots_by_date))
    invalid_dates: list[str] = []
    signatures_valid = True
    for target_date, (stored_root, stored_count) in roots_by_date.items():
        try:
            leaves = [
                str(row[0])
                for row in db_conn.execute(
                    """SELECT entry_hash FROM audit_entries
                       WHERE substr(timestamp, 1, 10) = ? ORDER BY id ASC""",
                    (target_date,),
                ).fetchall()
            ]
            calculated_root = (
                get_merkle_root(build_merkle_tree(leaves)) if leaves else None
            )
            root_matches = calculated_root == stored_root and len(leaves) == stored_count
            signature_matches = verify_daily_root(db_conn, target_date)
        except (TypeError, ValueError, sqlite3.Error):
            root_matches = False
            signature_matches = False
        if not root_matches or not signature_matches:
            invalid_dates.append(target_date)
        if not signature_matches:
            signatures_valid = False

    return {
        "valid": not missing_dates and not invalid_dates,
        "signature_valid": signatures_valid and not missing_dates,
        "missing_dates": missing_dates,
        "invalid_dates": sorted(invalid_dates),
    }


def verify_full_chain(db_conn: sqlite3.Connection) -> dict[str, Any]:
    """Verify audit row hashes, daily Merkle roots, and their Ed25519 signatures."""
    if not isinstance(db_conn, sqlite3.Connection):
        raise TypeError("db_conn must be an sqlite3.Connection")

    chain_report = _inspect_hashchain(db_conn)
    daily_report = _inspect_daily_roots(db_conn, chain_report["entry_dates"])
    is_valid = bool(chain_report["valid"] and daily_report["valid"])

    # Compute the first broken index (lowest index of any altered, missing or broken-link entry)
    all_broken_indices = (
        chain_report["altered_entry_indices"] +
        chain_report["missing_entry_indices"] +
        chain_report["broken_link_indices"]
    )
    first_broken_index = min(all_broken_indices) if all_broken_indices else None

    return {
        "status": "green" if is_valid else "red",
        "valid": is_valid,
        "hashchain_valid": chain_report["valid"],
        "daily_roots_valid": daily_report["valid"],
        "signatures_valid": daily_report["signature_valid"],
        "altered_entry_indices": chain_report["altered_entry_indices"],
        "broken_link_indices": chain_report["broken_link_indices"],
        "missing_entry_indices": chain_report["missing_entry_indices"],
        "missing_daily_root_dates": daily_report["missing_dates"],
        "invalid_daily_root_dates": daily_report["invalid_dates"],
        "first_broken_index": first_broken_index,
    }


def main(argv: Sequence[str] | None = None) -> int:
    """Run full audit verification from a SQLite file and trusted Ed25519 public key."""
    parser = argparse.ArgumentParser(description="Verify ExamVault's audit chain and daily roots")
    parser.add_argument(
        "--database",
        type=Path,
        default=Path("data/examvault.db"),
        help="SQLite database path (default: data/examvault.db)",
    )
    parser.add_argument(
        "--public-key",
        type=Path,
        required=True,
        help="trusted Ed25519 audit public key in PEM format",
    )
    arguments = parser.parse_args(argv)

    try:
        loaded_key = serialization.load_pem_public_key(
            arguments.public_key.read_bytes()
        )
        if not isinstance(loaded_key, Ed25519PublicKey):
            raise ValueError("public key must be Ed25519")
        configure_audit_verification_key(loaded_key)
        with sqlite3.connect(arguments.database) as connection:
            report = verify_full_chain(connection)
    except (OSError, ValueError, sqlite3.Error) as error:
        report = {
            "status": "red",
            "valid": False,
            "error": str(error),
        }

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())