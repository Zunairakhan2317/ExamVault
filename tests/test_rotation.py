"""Tests for issuing and validating refreshed Shamir shares."""

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