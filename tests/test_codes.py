"""Unit tests for dynamic code generation."""
from __future__ import annotations

from tracing.codes import generate_dynamic_codes


def test_generate_dynamic_codes():
    dummy_slots = [
        {"slot_id": 1, "variants": ["A", "B"]},
        {"slot_id": 2, "variants": ["X", "Y", "Z"]},
    ]
    codes = generate_dynamic_codes(num_users=3, slots=dummy_slots)
    assert len(codes) == 3
    assert len(codes[0]) == 2
    assert 0 <= codes[0][1] < 3