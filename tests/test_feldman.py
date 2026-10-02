"""Tests for Feldman verifiable secret sharing commitments."""

from crypto.feldman import G, P, Q, commit, verify_share
from crypto.shamir import _eval_poly


def test_honest_shares_verify() -> None:
    """Shares evaluated modulo Q satisfy their coefficient commitments."""
    coeffs = [123456789, 987654321, 1122334455]
    commitments = commit(coeffs)

    assert P.bit_length() == 2048
    assert Q == (P - 1) // 2
    assert G == 4
    for x in range(1, 6):
        y = _eval_poly(coeffs, x, Q)
        assert verify_share(x, y, commitments)


def test_modified_share_fails() -> None:
    """Changing a valid share value invalidates its commitment proof."""
    coeffs = [123456789, 987654321, 1122334455]
    commitments = commit(coeffs)
    x = 3
    y = _eval_poly(coeffs, x, Q)

    assert not verify_share(x, (y + 1) % Q, commitments)


def test_share_with_wrong_index_fails() -> None:
    """A valid share value paired with a different index is rejected."""
    coeffs = [123456789, 987654321, 1122334455]
    commitments = commit(coeffs)
    original_x = 2
    y = _eval_poly(coeffs, original_x, Q)

    assert not verify_share(original_x + 1, y, commitments)