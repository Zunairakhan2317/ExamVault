"""Tests for master-secret generation and HKDF key derivation."""

import pytest

from crypto import kdf


def test_generate_master_secret_uses_256_random_bits(monkeypatch: pytest.MonkeyPatch) -> None:
    """Master secrets come from secrets.randbits with a 256-bit bound."""
    generated = 0xA5 * (1 << 248)
    requested_bits: list[int] = []

    def fake_randbits(bits: int) -> int:
        requested_bits.append(bits)
        return generated

    monkeypatch.setattr(kdf.secrets, "randbits", fake_randbits)

    assert kdf.generate_master_secret() == generated
    assert requested_bits == [256]
    assert 0 <= generated < 2**256


def test_derive_aes_key_is_stable_and_32_bytes() -> None:
    """The same master secret deterministically derives a 32-byte AES key."""
    master_secret = 0x123456789ABCDEF

    first_key = kdf.derive_aes_key(master_secret)
    second_key = kdf.derive_aes_key(master_secret)

    assert len(first_key) == 32
    assert first_key == second_key


@pytest.mark.parametrize("master_secret", [-1, 2**256, True, "1"])
def test_derive_aes_key_rejects_invalid_master_secret(master_secret: object) -> None:
    """Invalid master-secret values are rejected before key derivation."""
    with pytest.raises(ValueError):
        kdf.derive_aes_key(master_secret)  # type: ignore[arg-type]