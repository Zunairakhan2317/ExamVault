"""Unit tests for Tardos bias vectors and accusation scoring."""
from __future__ import annotations

from tracing.tardos import compute_scores, generate_bias_vector, generate_codeword


def test_tardos_scoring():
    biases = generate_bias_vector(20)
    suspects = [generate_codeword(biases) for _ in range(4)]
    leaked_word = suspects[0]
    scores = compute_scores(suspects, leaked_word, biases)
    
    assert len(scores) == 4
    assert scores[0] == max(scores)