"""Feldman verifiable secret sharing commitments over RFC 3526 group 14."""

from collections.abc import Sequence

P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
Q = (P - 1) // 2
G = 4


def commit(coeffs: Sequence[int]) -> list[int]:
    """Commit to Shamir polynomial coefficients without revealing them.

    Coefficients are normalized modulo ``Q`` and the returned group elements
    let recipients verify shares while keeping the polynomial coefficients
    secret.
    """
    if not coeffs:
        raise ValueError("At least one polynomial coefficient is required")
    if any(not isinstance(coefficient, int) or isinstance(coefficient, bool) for coefficient in coeffs):
        raise ValueError("Polynomial coefficients must be integers")
    return [pow(G, coefficient % Q, P) for coefficient in coeffs]


def verify_share(x: int, y: int, commitments: Sequence[int]) -> bool:
    """Verify that a share matches committed Shamir coefficients.

    Returns ``False`` for invalid coordinates or commitments. A successful
    result confirms the share satisfies the Feldman commitment equation in
    the subgroup of order ``Q``.
    """
    if not isinstance(x, int) or isinstance(x, bool) or not 1 <= x < Q:
        return False
    if not isinstance(y, int) or isinstance(y, bool) or not 0 <= y < Q:
        return False
    if not commitments:
        return False
    if any(
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 1 <= value < P
        or pow(value, Q, P) != 1
        for value in commitments
    ):
        return False

    expected = 1
    x_power = 1
    for value in commitments:
        expected = (expected * pow(value, x_power, P)) % P
        x_power = (x_power * x) % Q
    return pow(G, y, P) == expected