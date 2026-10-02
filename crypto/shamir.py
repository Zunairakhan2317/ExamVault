"""Shamir's Secret Sharing (SSS) over a prime field.

Provides ``split`` and ``combine`` functions for threshold secret sharing.
The implementation uses only the standard library ``secrets`` module for
random coefficients and modular arithmetic.

All arithmetic is performed modulo a prime ``p`` (Z_p).  The secret is an
integer ``0 <= secret < p``.  Shares are tuples ``(x, y)`` with ``x`` uniquely
identifying the share; ``y = f(x) mod p`` where ``f`` is a random polynomial
of degree ``k-1`` whose constant term is the secret.
"""

import secrets
from typing import List, Tuple

Point = Tuple[int, int]  # (x, y) share


def _modinv(a: int, p: int) -> int:
    """Modular inverse of a modulo prime p using the extended Euclidean algorithm.

    Returns x such that a * x ≡ 1 (mod p).  Raises ValueError if inverse does
    not exist (i.e. a % p == 0).
    """
    if a % p == 0:
        raise ValueError("Cannot invert 0 modulo p")
    # Python 3.8+ supports pow(a, -1, p) but we implement manually for clarity.
    # Extended GCD
    if a < 0:
        a = a % p
    g, x, _ = _extended_gcd(a, p)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % p


def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Return (gcd, x, y) such that a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def split(secret: int, k: int, n: int, prime: int) -> List[Point]:
    """Generate n shares of secret using a (k, n) Shamir threshold scheme.

    The polynomial ``f(x) = secret + a1*x + a2*x^2 + ... + a_{k-1}*x^{k-1}
    (mod prime)`` is used, where the coefficients a1..a_{k-1} are chosen
    uniformly at random from ``[0, prime-1]``.

    Args:
        secret: The integer secret to secret-share.  Must satisfy
            ``0 <= secret < prime``.
        k: The threshold; any k shares can reconstruct the secret.  Must satisfy
            ``2 <= k <= n``.
        n: The total number of shares to generate.
        prime: A prime modulus ``p``.  All arithmetic is done modulo ``p``.

    Returns:
        A list of ``n`` tuples ``(x_i, y_i)``, where each ``x_i`` is a distinct
        non‑zero value modulo ``prime`` and ``y_i = f(x_i) mod p``.

    Raises:
        ValueError: If ``k < 2``, ``k > n``, ``secret`` is outside the valid
            range, or if generating distinct ``x`` values fails (extremely unlikely).
    """
    if not (2 <= k <= n):
        raise ValueError(f"Require 2 <= k (= {k}) <= n (= {n})")
    if not (0 <= secret < prime):
        raise ValueError(f"secret must be in [0, {prime - 1}], got {secret}")

    # Generate k-1 random coefficients (a1 … a_{k-1})
    coeffs: List[int] = [secrets.randbelow(prime - 1) + 1 for _ in range(k - 1)]
    # Ensure constant term is the secret; we prepend it so polynomial is:
    # f(x) = secret + a1*x + a2*x^2 + ... + a_{k-1}*x^{k-1}
    coeffs = [secret] + coeffs

    # Pick n distinct x values in [1, prime-1] (avoid x=0 to keep shares simple)
    # We'll just use 1 … n as long as n < prime; otherwise sample randomly.
    if n >= prime:
        raise ValueError("n must be less than prime to guarantee distinct x values")
    x_vals = list(range(1, n + 1))  # guaranteed distinct and non-zero mod prime

    # Evaluate polynomial at each x
    shares: List[Point] = []
    for xi in x_vals:
        yi = _eval_poly(coeffs, xi, prime)
        shares.append((xi, yi))
    return shares


def _eval_poly(coeffs: List[int], x: int, p: int) -> int:
    """Evaluate polynomial with given coefficients at point x modulo p.

    coeffs[0] + coeffs[1]*x + coeffs[2]*x^2 + ... (mod p)
    """
    result = 0
    # Horner's method for efficiency
    for c in reversed(coeffs):
        result = (result * x + c) % p
    return result


def combine(shares: List[Point], prime: int) -> int:
    """Reconstruct the secret from k shares using Lagrange interpolation.

    The secret is f(0) computed via Lagrange basis polynomials modulo ``prime``.

    Args:
        shares: A list of at least ``k `` tuples ``(x_i, y_i)``.  All ``x_i``
            must be distinct and non‑zero modulo ``prime``.
        prime: The prime modulus used in the original ``split`` call.

    Returns:
        The reconstructed secret integer ``f(0) mod prime``.

    Raises:
        ValueError: If fewer than 2 shares are provided, if duplicate x values
            are detected, or if any x is 0 modulo prime.
    """
    if len(shares) < 2:
        raise ValueError("At least 2 shares are required to combine")

    # Validate distinct x values and non-zero
    xs = [s[0] for s in shares]
    if len(xs) != len(set(xs)):
        raise ValueError("Duplicate x values detected among shares")
    for x in xs:
        if x % prime == 0:
            raise ValueError("x value must be non-zero modulo prime")

    secret = 0
    n = len(shares)
    for i, (xi, yi) in enumerate(shares):
        # Compute Lagrange basis polynomial L_i(0) = \prod_{j≠i} (0 - x_j) / (x_i - x_j)
        num = 1  # numerator product
        den = 1  # denominator product
        for j, (xj, _) in enumerate(shares):
            if i == j:
                continue
            num = (num * (0 - xj)) % prime
            den = (den * (xi - xj)) % prime
        # modular inverse of denominator
        den_inv = _modinv(den, prime)
        term = (yi * num * den_inv) % prime
        secret = (secret + term) % prime
    return secret