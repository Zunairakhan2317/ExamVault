"""Refresh Shamir shares by issuing shares from a fresh polynomial."""

import secrets
from typing import TypedDict

from crypto.feldman import Q
from crypto.shamir import Point, _eval_poly


class RotationState(TypedDict):
    """Publicly inspectable rotation state for validating issued shares."""

    secret: int
    threshold: int
    num_shares: int
    prime: int
    coefficients: list[int]
    shares: list[Point]


def rotate_shares(
    old_secret: int,
    threshold: int,
    num_shares: int,
) -> RotationState:
    """Issue shares from a fresh polynomial while preserving the master secret.

    The returned coefficients support validation of the new shares. Existing
    shares from a prior polynomial do not validate against this rotation state.
    """
    if not isinstance(old_secret, int) or isinstance(old_secret, bool) or not 0 <= old_secret < Q:
        raise ValueError("old_secret must be an integer in [0, Q-1]")
    if (
        not isinstance(threshold, int)
        or isinstance(threshold, bool)
        or not isinstance(num_shares, int)
        or isinstance(num_shares, bool)
        or not 2 <= threshold <= num_shares
    ):
        raise ValueError("Require 2 <= threshold <= num_shares")
    if num_shares >= Q:
        raise ValueError("num_shares must be less than the field prime")

    coefficients = [old_secret]
    coefficients.extend(secrets.randbelow(Q - 1) + 1 for _ in range(threshold - 1))
    shares = [
        (x, _eval_poly(coefficients, x, Q))
        for x in range(1, num_shares + 1)
    ]
    return {
        "secret": old_secret,
        "threshold": threshold,
        "num_shares": num_shares,
        "prime": Q,
        "coefficients": coefficients,
        "shares": shares,
    }


def verify_share_validity(
    share: Point,
    coefficients: list[int],
    prime: int,
) -> bool:
    """Check that a share lies on the supplied polynomial over the given field."""
    if (
        not isinstance(prime, int)
        or isinstance(prime, bool)
        or prime <= 2
        or not isinstance(share, tuple)
        or len(share) != 2
        or not isinstance(coefficients, list)
        or not coefficients
    ):
        return False

    x, y = share
    if (
        not isinstance(x, int)
        or isinstance(x, bool)
        or not 1 <= x < prime
        or not isinstance(y, int)
        or isinstance(y, bool)
        or not 0 <= y < prime
        or any(not isinstance(coefficient, int) or isinstance(coefficient, bool) for coefficient in coefficients)
    ):
        return False
    return _eval_poly(coefficients, x, prime) == y