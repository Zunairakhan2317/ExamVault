"""Tests for crypto/aes_gcm.py.

Covers the AES-256-GCM encrypt/decrypt round trip and the tamper-detection
guarantees that ExamVault relies on for tamper-evident records.
"""

import os

import pytest
from cryptography.exceptions import InvalidTag

from crypto.aes_gcm import decrypt, encrypt


def test_round_trip() -> None:
    """A freshly encrypted value decrypts back to the original plaintext."""
    key = os.urandom(32)
    plaintext = b"ExamVault secret paper content"
    aad = b"exam-2026-001"

    nonce, ciphertext = encrypt(plaintext, key, aad)
    recovered = decrypt(nonce, ciphertext, key, aad)

    assert recovered == plaintext
    assert nonce != ciphertext


def test_nonce_is_fresh_and_12_bytes() -> None:
    """Every encrypt call must produce a unique 12-byte nonce."""
    key = os.urandom(32)
    plaintext = b"same input"
    aad = b"aad"

    nonce1, _ = encrypt(plaintext, key, aad)
    nonce2, _ = encrypt(plaintext, key, aad)

    assert len(nonce1) == 12
    assert len(nonce2) == 12
    assert nonce1 != nonce2


def test_tampered_ciphertext_raises_invalid_tag() -> None:
    """Flipping a ciphertext byte must fail decryption."""
    key = os.urandom(32)
    plaintext = b"sensitive content"
    aad = b"exam-id"

    nonce, ciphertext = encrypt(plaintext, key, aad)
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0x01

    with pytest.raises(InvalidTag):
        decrypt(nonce, bytes(tampered), key, aad)


def test_wrong_key_raises_invalid_tag() -> None:
    """A different key must not decrypt the ciphertext."""
    plaintext = b"important"
    aad = b"exam-id"

    nonce, ciphertext = encrypt(plaintext, os.urandom(32), aad)

    with pytest.raises(InvalidTag):
        decrypt(nonce, ciphertext, os.urandom(32), aad)


def test_wrong_aad_raises_invalid_tag() -> None:
    """Changing the AAD must invalidate the authentication tag."""
    key = os.urandom(32)
    plaintext = b"important"
    aad = b"exam-id"

    nonce, ciphertext = encrypt(plaintext, key, aad)

    with pytest.raises(InvalidTag):
        decrypt(nonce, ciphertext, key, b"different-aad")


def test_short_key_raises_value_error() -> None:
    """A key that is not exactly 32 bytes must be rejected before use."""
    short_key = os.urandom(16)
    plaintext = b"important"
    aad = b"exam-id"

    with pytest.raises(ValueError):
        encrypt(plaintext, short_key, aad)

    with pytest.raises(ValueError):
        decrypt(b"\x00" * 12, b"cipher", short_key, aad)


def test_long_key_raises_value_error() -> None:
    """A key longer than 32 bytes must be rejected."""
    long_key = os.urandom(64)
    plaintext = b"important"
    aad = b"exam-id"

    with pytest.raises(ValueError):
        encrypt(plaintext, long_key, aad)

    with pytest.raises(ValueError):
        decrypt(b"\x00" * 12, b"cipher", long_key, aad)