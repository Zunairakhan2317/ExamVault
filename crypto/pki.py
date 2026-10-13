"""
crypto/pki.py

Provides internal Root CA operations, X.509 certificate issuance, validation, 
and Certificate Revocation Lists (CRL) using the Python `cryptography` library.
Security Property: Ensures that only users with valid, unrevoked certificates 
can participate in authenticated flows (login, share submission, and copy downloads).
"""

from __future__ import annotations

import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives import serialization

KEYS_DIR = Path("keys")
KEYS_DIR.mkdir(parents=True, exist_ok=True)

CA_PRIVATE_KEY_PATH = KEYS_DIR / "ca_private.pem"
CA_CERT_PATH = KEYS_DIR / "ca_cert.pem"


def get_or_create_root_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """
    Loads or generates the internal Self-Signed Root CA private key and certificate.
    """
    if CA_PRIVATE_KEY_PATH.exists() and CA_CERT_PATH.exists():
        priv_pem = CA_PRIVATE_KEY_PATH.read_bytes()
        cert_pem = CA_CERT_PATH.read_bytes()
        private_key = serialization.load_pem_private_key(priv_pem, password=None)
        cert = x509.load_pem_x509_certificate(cert_pem)
        return private_key, cert

    # Generate new CA RSA 3072 private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ExamVault Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "ExamVault Root CA"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    CA_PRIVATE_KEY_PATH.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    CA_CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    return private_key, cert


def issue_certificate(username: str, role: str, public_key_pem: bytes) -> tuple[str, str]:
    """
    Issues an X.509 certificate for a user signed by the Root CA (valid for 1 year).
    Returns (serial_number_hex, certificate_pem).
    """
    ca_priv, ca_cert = get_or_create_root_ca()
    
    user_pub_key = serialization.load_pem_public_key(public_key_pem)
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, username),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, role),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    serial = x509.random_serial_number()

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(user_pub_key)
        .serial_number(serial)
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(ca_priv, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    return hex(serial), cert_pem


def verify_certificate(cert_pem: str, crl_pem: str | None = None) -> bool:
    """
    Verifies a user certificate against the Root CA and optional CRL.
    """
    try:
        _, ca_cert = get_or_create_root_ca()
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))

        # Verify validity dates safely
        now = datetime.datetime.now(datetime.timezone.utc)
        nb = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        na = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        
        if not (nb <= now <= na):
            return False

        # Verify signature using CA public key with explicit PKCS1v15 padding
        ca_pub = ca_cert.public_key()
        from cryptography.hazmat.primitives.asymmetric import padding
        ca_pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )

        # Check CRL if provided
        if crl_pem:
            crl = x509.load_pem_x509_crl(crl_pem.encode("utf-8"))
            if crl.get_revoked_certificate_by_serial_number(cert.serial_number):
                return False

        return True
    except Exception:
        return False


def build_crl(revoked_serials: list[int]) -> str:
    """
    Generates a signed Certificate Revocation List (CRL) containing the given revoked serial numbers.
    """
    ca_priv, ca_cert = get_or_create_root_ca()
    now = datetime.datetime.now(datetime.timezone.utc)

    builder = x509.CertificateRevocationListBuilder().issuer_name(
        ca_cert.subject
    ).last_update(now).next_update(now + datetime.timedelta(days=1))

    for serial in revoked_serials:
        revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(now)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked_cert)

    crl = builder.sign(ca_priv, hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.PEM).decode("utf-8")