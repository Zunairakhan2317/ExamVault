"""AES-GCM encryption for ExamVault exam paper protection.

Uses the `cryptography` library's AESGCM implementation.
Nonce is exactly 12 bytes (standard for GCM), generated fresh on every encrypt call.
AAD (Additional Authenticated Data) is the exam identifier, bound into the authentication tag.
"""

import os
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(plaintext: bytes, key: bytes, aad: bytes) -> Tuple[bytes, bytes]:
    """Encrypt plaintext using AES-256-GCM.

    Args:
        plaintext: The data to encrypt.
        key: The encryption key. Must be exactly 32 bytes (256 bits).
        aad: Additional authenticated data (e.g. exam ID). Not encrypted but
            integrity-protected.

    Returns:
        A tuple (nonce, ciphertext) where ``nonce`` is a 12-byte random
        value and ``ciphertext`` is the authenticated encryption output.

    Raises:
        ValueError: If ``key`` is not exactly 32 bytes.
    """
    if len(key) != 32:
        raise ValueError("Key must be exactly 32 bytes (256 bits for AES-256-GCM)")

    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def decrypt(nonce: bytes, ciphertext: bytes, key: bytes, aad: bytes) -> bytes:
    """Decrypt ciphertext using AES-256-GCM.

    Args:
        nonce: The 12-byte nonce from the corresponding encrypt call.
        ciphertext: The authenticated encryption output.
        key: The encryption key. Must be exactly 32 bytes (256 bits).
        aad: Additional authenticated data (e.g. exam ID). Must match the AAD
            used during encryption.

    Returns:
        The decrypted plaintext.

    Raises:
        ValueError: If ``key`` is not exactly 32 bytes.
        cryptography.exceptions.InvalidTag: If the ciphertext, nonce, or AAD
            is invalid (tampered ciphertext, wrong key, or wrong AAD).
    """
    if len(key) != 32:
        raise ValueError("Key must be exactly 32 bytes (256 bits for AES-256-GCM)")

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    return plaintext