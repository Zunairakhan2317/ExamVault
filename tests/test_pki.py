"""
tests/test_pki.py

Unit tests for the PKI and Certificate Revocation List (CRL) module.
Verifies CA generation, certificate issuance, signature validation, and revocation checks.
"""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from crypto.pki import (
    get_or_create_root_ca,
    issue_certificate,
    verify_certificate,
    build_crl,
)


def test_root_ca_creation():
    """Root CA private key and certificate are successfully generated and loaded."""
    priv, cert = get_or_create_root_ca()
    assert priv is not None
    assert cert is not None
    assert "ExamVault Root CA" in cert.subject.rfc4514_string()


def test_issue_and_verify_certificate():
    """A certificate issued by the CA for a user passes verification."""
    # Generate a sample user RSA keypair
    user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    user_pub_pem = user_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    serial_hex, cert_pem = issue_certificate("test_invigilator", "invigilator", user_pub_pem)
    assert serial_hex is not None
    assert cert_pem is not None

    # Verify the certificate without CRL
    assert verify_certificate(cert_pem) is True


def test_revocation_via_crl():
    """A revoked certificate fails verification against the CRL."""
    user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    user_pub_pem = user_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    serial_hex, cert_pem = issue_certificate("revoked_user", "invigilator", user_pub_pem)
    
    # Extract serial number integer from hex string
    serial_int = int(serial_hex, 16)

    # Build CRL containing this serial number
    crl_pem = build_crl([serial_int])

    # Verification against this CRL must fail
    assert verify_certificate(cert_pem, crl_pem=crl_pem) is False



# --- Plan 6.5 / 6.6: revoke(), signed CRL, and the per-user certificate check -------------------------

import sqlite3


@pytest.fixture
def audit_events(monkeypatch):
    """Capture audit writes instead of hitting a real audit chain."""
    events: list[tuple] = []
    import web.audit_log as audit_log

    monkeypatch.setattr(audit_log, "log_event", lambda c, actor, action, details=None: events.append((actor, action, details)))
    return events


@pytest.fixture
def cert_db(audit_events):
    """In-memory certificates table."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE certificates (serial TEXT PRIMARY KEY, user_id INTEGER NOT NULL, pem TEXT NOT NULL, "
        "issued_at TEXT NOT NULL, revoked_at TEXT)"
    )
    return conn


def _issue(conn, username: str, user_id: int) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    serial, pem = issue_certificate(username, "invigilator", pub)
    conn.execute("INSERT INTO certificates VALUES (?, ?, ?, ?, NULL)", (serial, user_id, pem, "2026-10-25T00:00:00"))
    conn.commit()
    return serial


def test_revoke_signs_a_crl_and_blocks_only_that_user(cert_db, audit_events):
    from cryptography import x509
    from crypto import pki

    alice, bob = _issue(cert_db, "alice", 1), _issue(cert_db, "bob", 2)
    assert pki.user_certificate_ok(cert_db, 1) and pki.user_certificate_ok(cert_db, 2)

    crl_pem = pki.revoke(cert_db, alice, "Left job", actor="admin")

    assert pki.user_certificate_ok(cert_db, 1) is False
    assert pki.user_certificate_ok(cert_db, 2) is True
    crl = x509.load_pem_x509_crl(crl_pem.encode())
    assert {entry.serial_number for entry in crl} == {int(alice, 16)}
    assert crl.is_signature_valid(get_or_create_root_ca()[1].public_key())
    assert audit_events[-1][1] == "certificate_revoked"
    assert int(bob, 16) not in {entry.serial_number for entry in crl}


def test_user_without_certificate_is_not_blocked(cert_db):
    from crypto import pki

    assert pki.user_certificate_ok(cert_db, 42) is True


def test_wrong_crl_file_is_ignored_and_rebuilt_from_database(cert_db):
    from crypto import pki

    _issue(cert_db, "alice", 1)
    bob = _issue(cert_db, "bob", 2)
    pki.CRL_PATH.write_text(build_crl([int(bob, 16)]))  # hand-made CRL that revokes the wrong person
    assert pki.user_certificate_ok(cert_db, 2) is True  # database is the source of truth
    assert pki.user_certificate_ok(cert_db, 1) is True


def test_revoke_rejects_unknown_serial_and_empty_reason(cert_db):
    from crypto import pki

    alice = _issue(cert_db, "alice", 1)
    with pytest.raises(ValueError):
        pki.revoke(cert_db, "0xdeadbeef", "Left job")
    with pytest.raises(ValueError):
        pki.revoke(cert_db, alice, "  ")
    assert pki.user_certificate_ok(cert_db, 1) is True
