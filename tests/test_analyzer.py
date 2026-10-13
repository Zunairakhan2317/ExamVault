"""Unit tests for Leak Analyzer and fuzzy variant extraction (Plan Layer 3)."""
from __future__ import annotations

from tracing.analyzer import extract_leaked_word, analyze_leak
from tracing.tardos import generate_bias_vector, generate_codeword


def test_analyzer_extraction():
    slots = [
        {"slot_id": 1, "variants": ["Alpha variant text here", "Beta variant text here"]},
        {"slot_id": 2, "variants": ["Gamma option string", "Delta option string"]}
    ]
    leaked = "alpha variant text here delta option string"
    word = extract_leaked_word(leaked, slots, threshold=0.6)
    assert len(word) == 2
    assert word[0] == 0  # Matched variant 0 ("Alpha...")
    assert word[1] == 1  # Matched variant 1 ("Delta...")


def test_analyze_leak_ranking():
    slots = [{"slot_id": 1, "variants": ["Text option A", "Text option B"]}]
    biases = generate_bias_vector(1)
    suspects = [[0], [1], [0]]
    usernames = ["alice", "bob", "carol"]
    
    leaked = "text option a"
    results = analyze_leak(leaked, slots, usernames, suspects, biases, threshold=0.5)
    
    assert len(results) == 3
    # Alice and Carol have code [0], which matches leaked word [0], so they should score highest
    assert results[0]["username"] in ["alice", "carol"]