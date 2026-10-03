"""Tests for issuing and validating refreshed Shamir shares."""

import pytest

from crypto.feldman import Q
from crypto.rotation import rotate_shares, verify_share_validity


def test_rotation_generates_a_new_set_of_shares() -> None:
    """A fresh polynomial produces new shares while preserving the secret."""
    secret = 123456789
    old_state = rotate_shares(secret, threshold=3, num_shares=5)
    new_state = rotate_shares(secret, threshold=3, num_shares=5)

    assert old_state["secret"] == new_state["secret"] == secret
    assert old_state["shares"] != new_state["shares"]
    assert old_state["coefficients"] != new_state["coefficients"]
    assert all(
        verify_share_validity(share, new_state["coefficients"], new_state["prime"])
        for share in new_state["shares"]
    )


def test_old_shares_fail_against_new_rotation_state() -> None:
    """Shares issued before a polynomial refresh fail the new polynomial check."""
    old_state = rotate_shares(987654321, threshold=3, num_shares=5)
    new_state = rotate_shares(987654321, threshold=3, num_shares=5)

    assert all(
        not verify_share_validity(share, new_state["coefficients"], new_state["prime"])
        for share in old_state["shares"]
    )


def test_new_shares_fail_against_old_rotation_state() -> None:
    """Shares issued after refresh fail the previous polynomial check."""
    old_state = rotate_shares(314159265, threshold=3, num_shares=5)
    new_state = rotate_shares(314159265, threshold=3, num_shares=5)

    assert all(
        not verify_share_validity(share, old_state["coefficients"], old_state["prime"])
        for share in new_state["shares"]
    )


def test_rotation_samples_coefficients_from_full_field(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Zero is a permitted random polynomial coefficient during rotation."""
    requested_ranges: list[int] = []

    def sample_zero(upper_bound: int) -> int:
        requested_ranges.append(upper_bound)
        return 0

    monkeypatch.setattr("crypto.rotation.secrets.randbelow", sample_zero)
    state = rotate_shares(old_secret=42, threshold=2, num_shares=3)

    assert requested_ranges == [Q]
    assert state["coefficients"] == [42, 0]
    assert state["shares"] == [(1, 42), (2, 42), (3, 42)]