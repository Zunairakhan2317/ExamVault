"""Ed25519 signing helpers for ExamVault integrity and authenticity."""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate an Ed25519 key pair for authenticating ExamVault records."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def sign_message(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
    """Sign a message to provide authenticity and tamper detection."""
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be an Ed25519 private key")
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    return private_key.sign(message)


def verify_signature(
    public_key: Ed25519PublicKey,
    message: bytes,
    signature: bytes,
) -> bool:
    """Check a message signature, returning False if authenticity fails."""
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("public_key must be an Ed25519 public key")
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    if not isinstance(signature, bytes):
        raise TypeError("signature must be bytes")

    try:
        public_key.verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True