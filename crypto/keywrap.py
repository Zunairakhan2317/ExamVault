"""Hybrid encryption for securely storing ExamVault shares."""

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_AES_KEY_BYTES = 32
_NONCE_BYTES = 12
_GCM_TAG_BYTES = 16
_RSA_KEY_BITS = 3072


def _oaep_padding() -> padding.OAEP:
    """Create the OAEP-SHA256 parameters used to protect share-encryption keys."""
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def wrap_share(share_bytes: bytes, holder_public_key: rsa.RSAPublicKey) -> bytes:
    """Encrypt a share with AES-GCM and wrap its fresh key using holder RSA-3072."""
    if not isinstance(share_bytes, bytes):
        raise TypeError("share_bytes must be bytes")
    if not isinstance(holder_public_key, rsa.RSAPublicKey):
        raise TypeError("holder_public_key must be an RSA public key")
    if holder_public_key.key_size != _RSA_KEY_BITS:
        raise ValueError("holder_public_key must be RSA-3072")

    aes_key = AESGCM.generate_key(bit_length=_AES_KEY_BYTES * 8)
    nonce = os.urandom(_NONCE_BYTES)
    encrypted_share = AESGCM(aes_key).encrypt(nonce, share_bytes, None)
    wrapped_key = holder_public_key.encrypt(aes_key, _oaep_padding())
    return wrapped_key + nonce + encrypted_share


def unwrap_share(blob: bytes, holder_private_key: rsa.RSAPrivateKey) -> bytes:
    """Unwrap a stored share using its holder's RSA-3072 private key."""
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not isinstance(holder_private_key, rsa.RSAPrivateKey):
        raise TypeError("holder_private_key must be an RSA private key")
    if holder_private_key.key_size != _RSA_KEY_BITS:
        raise ValueError("holder_private_key must be RSA-3072")

    wrapped_key_bytes = holder_private_key.key_size // 8
    minimum_blob_bytes = wrapped_key_bytes + _NONCE_BYTES + _GCM_TAG_BYTES
    if len(blob) < minimum_blob_bytes:
        raise ValueError("blob is too short to contain a wrapped share")

    wrapped_key = blob[:wrapped_key_bytes]
    nonce_start = wrapped_key_bytes
    nonce_end = nonce_start + _NONCE_BYTES
    nonce = blob[nonce_start:nonce_end]
    encrypted_share = blob[nonce_end:]

    aes_key = holder_private_key.decrypt(wrapped_key, _oaep_padding())
    if len(aes_key) != _AES_KEY_BYTES:
        raise ValueError("unwrapped AES key has an invalid length")
    return AESGCM(aes_key).decrypt(nonce, encrypted_share, None)