"""Dynamic multi-variant code generation based on uploaded exam structure (Plan 5.2)."""
from __future__ import annotations

import secrets


def hamming_distance(b1: list[int], b2: list[int]) -> int:
    """Calculate distance between two assignment vectors."""
    return sum(c1 != c2 for c1, c2 in zip(b1, b2))


def generate_dynamic_codes(num_users: int, slots: list[dict], min_distance: int = 1) -> list[list[int]]:
    """
    Generates assignment vectors for each user based on the available variant options per slot.
    Supports dynamic number of variants per slot (e.g. 2, 3, or more choices).
    """
    codes: list[list[int]] = []
    for _ in range(num_users):
        user_code = []
        for slot in slots:
            num_variants = len(slot["variants"])
            chosen_variant_idx = secrets.randbelow(num_variants)
            user_code.append(chosen_variant_idx)
        codes.append(user_code)
    return codes