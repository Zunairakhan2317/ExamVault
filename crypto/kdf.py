"""Master-secret generation and AES key derivation for ExamVault."""

import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_MASTER_SECRET_BITS = 256
_MASTER_SECRET_BYTES = _MASTER_SECRET_BITS // 8
_AES_KEY_BYTES = 32
_HKDF_INFO = b"examvault-paper-key"


def generate_master_secret() -> int:
    """Generate a uniformly random 256-bit master secret using the OS CSPRNG."""
    return secrets.randbits(_MASTER_SECRET_BITS)


def derive_aes_key(master_secret: int) -> bytes:
    """Derive a stable AES-256 key from a valid master secret using HKDF-SHA256."""
    if (
        not isinstance(master_secret, int)
        or isinstance(master_secret, bool)
        or not 0 <= master_secret < 2**_MASTER_SECRET_BITS
    ):
        raise ValueError("master_secret must be an unsigned 256-bit integer")

    secret_bytes = master_secret.to_bytes(_MASTER_SECRET_BYTES, byteorder="big")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_AES_KEY_BYTES,
        salt=None,
        info=_HKDF_INFO,
    ).derive(secret_bytes)