"""Tests for TOTP windows, replay defense, provisioning, and secret encryption."""

import pyotp
import pytest
from cryptography.exceptions import InvalidTag
from urllib.parse import unquote

from auth.totp import (
    DIGITS,
    NONCE_SIZE,
    STEP_SECONDS,
    current_step,
    new_secret,
    protect_secret,
    provisioning_uri,
    qr_png_bytes,
    unprotect_secret,
    verify_code,
)

TEST_SECRET = "JBSWY3DPEHPK3PXP"
TEST_KEY = b"k" * 32
TEST_NOW = 1_700_000_000.0
TEST_STEP = int(TEST_NOW // STEP_SECONDS)


def _code_for_step(step: int, secret: str = TEST_SECRET) -> str:
    """Generate a deterministic test code for an exact TOTP counter."""
    return pyotp.TOTP(secret, digits=DIGITS, interval=STEP_SECONDS).at(
        step * STEP_SECONDS
    )


def test_new_secret_returns_base32_secret() -> None:
    """Enrollment secrets are random base32 values suitable for TOTP."""
    secret = new_secret()

    assert isinstance(secret, str)
    assert len(secret) >= 16
    assert secret.isascii()
    assert secret.isalnum()


def test_current_step_uses_thirty_second_counters() -> None:
    """TOTP step calculation matches integer 30-second intervals."""
    assert current_step(now=0) == 0
    assert current_step(now=59) == 1


def test_current_step_accepts_exact_step_boundary() -> None:
    """An exact interval boundary starts the next step."""
    assert current_step(now=STEP_SECONDS) == 1


def test_current_step_uses_supplied_timestamp() -> None:
    """A provided timestamp makes step calculation deterministic."""
    assert current_step(now=TEST_NOW) == TEST_STEP


def test_current_step_constant_matches_pyotp_interval() -> None:
    """The module's advertised step and digit constants are the configured TOTP values."""
    assert STEP_SECONDS == 30
    assert DIGITS == 6
    assert NONCE_SIZE == 12


def test_current_step_none_uses_clock() -> None:
    """An omitted timestamp returns a valid current step from the system clock."""
    assert isinstance(current_step(), int)


def test_current_code_verifies_and_returns_its_step() -> None:
    """A current-step code verifies and returns the counter the caller must store."""
    code = _code_for_step(TEST_STEP)

    assert verify_code(TEST_SECRET, code, None, now=TEST_NOW) == (True, TEST_STEP)


def test_previous_and_next_step_codes_verify() -> None:
    """The accepted window includes exactly one adjacent step on either side."""
    previous_code = _code_for_step(TEST_STEP - 1)
    next_code = _code_for_step(TEST_STEP + 1)

    assert verify_code(TEST_SECRET, previous_code, None, now=TEST_NOW) == (
        True,
        TEST_STEP - 1,
    )
    assert verify_code(TEST_SECRET, next_code, None, now=TEST_NOW) == (
        True,
        TEST_STEP + 1,
    )


def test_codes_two_steps_outside_window_fail() -> None:
    """Codes two steps away from the current counter are rejected."""
    before_window = _code_for_step(TEST_STEP - 2)
    after_window = _code_for_step(TEST_STEP + 2)

    assert verify_code(TEST_SECRET, before_window, None, now=TEST_NOW) == (False, None)
    assert verify_code(TEST_SECRET, after_window, None, now=TEST_NOW) == (False, None)


def test_wrong_and_malformed_codes_fail_without_raising() -> None:
    """Wrong codes and malformed code inputs fail closed."""
    valid_code = _code_for_step(TEST_STEP)
    wrong_code = ("0" if valid_code[0] != "0" else "1") + valid_code[1:]
    invalid_inputs: list[object] = [
        wrong_code,
        "12345",
        "1234567",
        "12a456",
        "",
        None,
        "１２３４５６",
    ]

    for invalid_code in invalid_inputs:
        assert verify_code(TEST_SECRET, invalid_code, None, now=TEST_NOW) == (False, None)  # type: ignore[arg-type]


def test_code_with_spaces_is_accepted() -> None:
    """ASCII spaces are removed before validating a six-digit code."""
    code = _code_for_step(TEST_STEP)
    spaced_code = f"{code[:3]} {code[3:]}"

    assert verify_code(TEST_SECRET, spaced_code, None, now=TEST_NOW) == (
        True,
        TEST_STEP,
    )


def test_replay_of_previously_used_step_is_rejected() -> None:
    """A code accepted once cannot be accepted again for the same step."""
    code = _code_for_step(TEST_STEP)
    assert verify_code(TEST_SECRET, code, None, now=TEST_NOW) == (True, TEST_STEP)

    assert verify_code(TEST_SECRET, code, TEST_STEP, now=TEST_NOW) == (False, None)


def test_older_step_than_last_used_fails_and_newer_step_passes() -> None:
    """Replay defense rejects older counters but permits a fresh later counter."""
    older_code = _code_for_step(TEST_STEP - 1)
    newer_code = _code_for_step(TEST_STEP + 1)

    assert verify_code(TEST_SECRET, older_code, TEST_STEP, now=TEST_NOW) == (False, None)
    assert verify_code(TEST_SECRET, newer_code, TEST_STEP, now=TEST_NOW) == (
        True,
        TEST_STEP + 1,
    )


def test_invalid_base32_secret_fails_without_raising() -> None:
    """Malformed base32 secrets fail closed during code generation."""
    assert verify_code("not a valid base32 secret!", "123456", None, now=TEST_NOW) == (
        False,
        None,
    )


def test_provisioning_uri_contains_issuer_username_and_secret() -> None:
    """Authenticator setup URI identifies the ExamVault account and shared secret."""
    uri = provisioning_uri(TEST_SECRET, "alice@example.test")

    assert "ExamVault" in uri
    assert "alice@example.test" in unquote(uri)
    assert TEST_SECRET in uri


def test_qr_png_bytes_have_png_signature() -> None:
    """Enrollment QR output is a PNG image byte stream."""
    uri = provisioning_uri(TEST_SECRET, "alice@example.test")

    assert qr_png_bytes(uri).startswith(b"\x89PNG")


def test_protected_totp_secret_round_trips() -> None:
    """AES-GCM protection recovers the original TOTP secret for its account."""
    blob = protect_secret(TEST_SECRET, TEST_KEY, "alice")

    assert len(blob) > NONCE_SIZE
    assert unprotect_secret(blob, TEST_KEY, "alice") == TEST_SECRET


def test_wrong_key_username_and_tampered_blob_raise_invalid_tag() -> None:
    """AES-GCM detects wrong key, wrong account binding, and modified ciphertext."""
    blob = protect_secret(TEST_SECRET, TEST_KEY, "alice")
    tampered_blob = bytearray(blob)
    tampered_blob[-1] ^= 1

    with pytest.raises(InvalidTag):
        unprotect_secret(blob, b"w" * 32, "alice")
    with pytest.raises(InvalidTag):
        unprotect_secret(blob, TEST_KEY, "bob")
    with pytest.raises(InvalidTag):
        unprotect_secret(bytes(tampered_blob), TEST_KEY, "alice")


def test_short_protected_blob_raises_value_error() -> None:
    """A blob too short to contain nonce and authenticated ciphertext is rejected."""
    with pytest.raises(ValueError):
        unprotect_secret(b"x" * 5, TEST_KEY, "alice")


def test_protecting_same_secret_uses_fresh_nonce() -> None:
    """Repeated storage encryption produces distinct nonce-prefixed blobs."""
    first_blob = protect_secret(TEST_SECRET, TEST_KEY, "alice")
    second_blob = protect_secret(TEST_SECRET, TEST_KEY, "alice")

    assert first_blob[:NONCE_SIZE] != second_blob[:NONCE_SIZE]
    assert first_blob != second_blob
