"""Tests for Argon2id password hashing and policy enforcement."""

import pytest

from auth.passwords import (
    COMMON_PASSWORDS,
    MIN_LENGTH,
    check_policy,
    hash_password,
    needs_rehash,
    verify_password,
)


def test_hashing_uses_fresh_salts_and_both_hashes_verify() -> None:
    """Independent salted hashes verify the same password."""
    password = "Correct-Horse-47!"

    first_hash = hash_password(password)
    second_hash = hash_password(password)

    assert first_hash != second_hash
    assert verify_password(first_hash, password)
    assert verify_password(second_hash, password)


def test_verify_password_correct_wrong_and_empty_inputs() -> None:
    """Only the correct non-empty password verifies."""
    stored_hash = hash_password("Correct-Horse-47!")

    assert verify_password(stored_hash, "Correct-Horse-47!")
    assert not verify_password(stored_hash, "Wrong-Horse-47!")
    assert not verify_password(stored_hash, "")


@pytest.mark.parametrize("stored_hash", ["not-a-hash", "", "$argon2id$v=19$broken"])
def test_verify_password_invalid_hash_fails_closed(stored_hash: str) -> None:
    """Corrupt or empty encoded hashes return False without raising."""
    assert not verify_password(stored_hash, "Correct-Horse-47!")


def test_hash_password_rejects_empty_password() -> None:
    """Hashing rejects an empty password."""
    with pytest.raises(ValueError):
        hash_password("")


def test_policy_accepts_plan_example_password() -> None:
    """The plan's representative password meets the two policy rules."""
    check_policy("Tr1cky-Exam-Vault!")


def test_policy_accepts_long_lowercase_password() -> None:
    """A long lowercase password is accepted when it is not common."""
    check_policy("thisisalonglowercasepassword")


def test_policy_rejects_short_password() -> None:
    """Passwords shorter than the minimum length are rejected."""
    with pytest.raises(ValueError, match="at least"):
        check_policy("A1!bcdefghi")


def test_policy_rejects_common_password() -> None:
    """Known common passwords are rejected case-insensitively."""
    assert len(COMMON_PASSWORDS) >= 25
    with pytest.raises(ValueError, match="common"):
        check_policy("Password123456")


def test_needs_rehash_for_fresh_and_invalid_hashes() -> None:
    """Fresh Argon2id hashes need no upgrade; malformed hashes do."""
    fresh_hash = hash_password("Correct-Horse-47!")

    assert not needs_rehash(fresh_hash)
    assert needs_rehash("not-a-hash")
