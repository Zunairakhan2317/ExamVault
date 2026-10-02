"""Tests for Ed25519 message signatures."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from crypto.signing import generate_keypair, sign_message, verify_signature


def test_valid_signature_verifies() -> None:
    """A signature verifies for the exact message and matching public key."""
    private_key, public_key = generate_keypair()
    message = b"paper-hash|exam-2026-001|2026-10-02T09:00Z/10:00Z"

    signature = sign_message(private_key, message)

    assert isinstance(private_key, Ed25519PrivateKey)
    assert isinstance(public_key, Ed25519PublicKey)
    assert verify_signature(public_key, message, signature)


def test_tampered_message_fails_verification() -> None:
    """Changing signed content invalidates its Ed25519 signature."""
    private_key, public_key = generate_keypair()
    message = b"original exam record"
    signature = sign_message(private_key, message)

    assert not verify_signature(public_key, b"tampered exam record", signature)


def test_wrong_key_fails_verification() -> None:
    """A different public key cannot validate the original signer’s signature."""
    private_key, _ = generate_keypair()
    _, wrong_public_key = generate_keypair()
    message = b"authenticated record"
    signature = sign_message(private_key, message)

    assert not verify_signature(wrong_public_key, message, signature)