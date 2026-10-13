"""Tardos collusion-resistant fingerprinting codes and accusation scoring (Plan 5.3)."""
from __future__ import annotations

import math
import random


def generate_bias_vector(slot_count: int, c: float = 2.0) -> list[float]:
    """Generate secret bias vector p_i for each slot."""
    t = 1.0 / (300.0 * c)
    biases = []
    for _ in range(slot_count):
        r = random.uniform(t, math.pi / 2.0 - t)
        p = math.sin(r) ** 2
        p = max(0.01, min(0.99, p))
        biases.append(p)
    return biases


def generate_codeword(biases: list[float]) -> list[int]:
    """Generate an invigilator binary codeword bit."""
    return [1 if random.random() < p else 0 for p in biases]


def compute_scores(suspect_codes: list[list[int]], leaked_word: list[int], biases: list[float]) -> list[float]:
    """Compute accusation scores for each suspect given leaked word y."""
    num_suspects = len(suspect_codes)
    scores = [0.0] * num_suspects
    num_slots = len(leaked_word)

    for i in range(num_slots):
        p = biases[i]
        y = leaked_word[i]
        w1 = math.sqrt((1.0 - p) / p)
        w2 = math.sqrt(p / (1.0 - p))

        for j in range(num_suspects):
            x = suspect_codes[j][i]
            if y == 1:
                if x == 1:
                    scores[j] += w1
                else:
                    scores[j] -= w2
            else:
                if x == 0:
                    scores[j] += w2
                else:
                    scores[j] -= w1
    return scores