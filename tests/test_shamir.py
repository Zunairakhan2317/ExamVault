"""Tests for crypto/shamir.py.

Properties verified:
- Every k‑subset of the n shares correctly reconstructs the secret.
- Any k‑1 shares give a value different from the original secret.
- For a concrete 3‑of‑5 split, all C(5,3)=10 subsets recover the secret.
- Input validation: k > n, k < 2, duplicate x values raise ValueError.
"""

import itertools
import secrets

import pytest

from crypto.shamir import combine, split

def test_round_trip_k_subsets() -> None:
    """For random parameters, any k shares out of n recover the secret."""
    prime = 2_147_483_647  # a large Mersenne prime (2^31‑1)
    secret = secrets.randbelow(prime - 1) + 1
    n = 10
    k = 4

    shares = split(secret, k, n, prime)

    # Test every possible k‑subset
    for subset in itertools.combinations(shares, k):
        reconstructed = combine(list(subset), prime)
        assert reconstructed == secret, \
            f"Failed for subset {subset}: got {reconstructed}, expected {secret}"

def test_k_minus_1_fails() -> None:
    """Any k‑1 shares should NOT reconstruct the original secret."""
    prime = 1_019  # a moderate prime
    secret = secrets.randbelow(prime - 1) + 1
    n = 7
    k = 3

    shares = split(secret, k, n, prime)

    # Test every possible (k‑1)-subset
    for subset in itertools.combinations(shares, k - 1):
        reconstructed = combine(list(subset), prime)
        # With only k‑1 points, the polynomial is not uniquely determined;
        # the reconstructed value should differ from the secret with overwhelming probability.
        assert reconstructed != secret, \
            f"(k‑1)-subset {subset} incorrectly yielded the secret {secret}"

def test_all_10_subsets_3_of_5() -> None:
    """For a concrete 3‑of‑5 split, all 10 subsets must recover the secret."""
    prime = 997  # small prime for easy arithmetic
    secret = 123
    n = 5
    k = 3

    shares = split(secret, k, n, prime)

    subsets = list(itertools.combinations(shares, k))
    assert len(subsets) == 10, "Expected C(5,3)=10 subsets"

    for subset in subsets:
        reconstructed = combine(list(subset), prime)
        assert reconstructed == secret, \
            f"Subset {subset} failed: got {reconstructed}, expected {secret}"


def test_every_3_subset_recovers_and_every_2_subset_fails_for_3_of_5(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """For a deterministic 3-of-5 polynomial, all triples recover but no pair does."""
    prime = 997
    secret = 123
    coefficients = iter((7, 1))
    monkeypatch.setattr(
        "crypto.shamir.secrets.randbelow",
        lambda upper_bound: next(coefficients),
    )

    shares = split(secret, k=3, n=5, prime=prime)

    for subset in itertools.combinations(shares, 3):
        assert combine(list(subset), prime) == secret
    for subset in itertools.combinations(shares, 2):
        assert combine(list(subset), prime) != secret

def test_input_validation_k_too_small() -> None:
    """k < 2 should raise ValueError."""
    secret = 42
    prime = 101
    with pytest.raises(ValueError):
        split(secret, k=1, n=5, prime=prime)

def test_input_validation_k_too_large() -> None:
    """k > n should raise ValueError."""
    secret = 42
    prime = 101
    with pytest.raises(ValueError):
        split(secret, k=6, n=5, prime=prime)

def test_duplicate_x_raises() -> None:
    """If shares contain duplicate x, combine should raise ValueError."""
    prime = 101
    # Construct two shares with same x but different y
    shares = [(1, 2), (1, 3)]
    with pytest.raises(ValueError):
        combine(shares, prime)

def test_secret_out_of_range() -> None:
    """Secret must be in [0, prime-1]."""
    prime = 101
    with pytest.raises(ValueError):
        split(secret=prime, k=2, n=3, prime=prime)  # secret == prime
    with pytest.raises(ValueError):
        split(secret=-1, k=2, n=3, prime=prime)   # negative


def test_polynomial_coefficients_are_sampled_from_full_field(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Zero is a valid random coefficient, preserving uniform field sampling."""
    prime = 101
    requested_ranges: list[int] = []

    def sample_zero(upper_bound: int) -> int:
        requested_ranges.append(upper_bound)
        return 0

    monkeypatch.setattr("crypto.shamir.secrets.randbelow", sample_zero)
    shares = split(secret=42, k=3, n=4, prime=prime)

    assert requested_ranges == [prime, prime]
    assert all(y == 42 for _, y in shares)
