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