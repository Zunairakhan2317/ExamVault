"""Leak Analyzer: Processes leaked paper text, fuzzy matches variants, and computes Tardos scores (Plan 5.7)."""
from __future__ import annotations

import difflib
import re
from typing import Any
from tracing.tardos import compute_scores


def normalize_text(text: str) -> str:
    """Normalise text: lowercase, collapse spaces, strip punctuation."""
    text = text.lower()
    text = re.sub(r"[^\w\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def extract_leaked_word(leaked_text: str, slots: list[dict], threshold: float = 0.8) -> list[int | None]:
    """
    For each slot, fuzzy match leaked text against each variant using sequence ratio and word overlap.
    Accept best match above threshold, otherwise return None (erasure).
    """
    normalized_leaked = normalize_text(leaked_text)
    leaked_word: list[int | None] = []

    for slot in slots:
        variants = slot["variants"]
        best_score = 0.0
        best_variant_idx = None

        for v_idx, v_text in enumerate(variants):
            norm_v = normalize_text(v_text)
            
            # Compute full sequence similarity
            seq_ratio = difflib.SequenceMatcher(None, norm_v, normalized_leaked).ratio()
            
            # Compute word token overlap ratio
            words_v = set(norm_v.split())
            words_l = set(normalized_leaked.split())
            overlap = len(words_v.intersection(words_l)) / max(1, len(words_v)) if words_v else 0.0
            
            score = max(seq_ratio, overlap)

            if score > best_score:
                best_score = score
                best_variant_idx = v_idx

        if best_score >= threshold and best_variant_idx is not None:
            leaked_word.append(best_variant_idx)
        else:
            leaked_word.append(None)  # Erasure

    return leaked_word


def analyze_leak(
    leaked_text: str,
    slots: list[dict],
    suspect_usernames: list[str],
    suspect_codes: list[list[int]],
    biases: list[float],
    threshold: float = 0.8
) -> list[dict[str, Any]]:
    """
    Analyzes leaked text, extracts variant selections, runs Tardos scoring,
    and returns a ranked table of suspects with confidence labels.
    """
    raw_word = extract_leaked_word(leaked_text, slots, threshold)
    
    # Fill erasures with default 0 for scoring
    processed_word = [0 if bit is None else bit for bit in raw_word]
    
    scores = compute_scores(suspect_codes, processed_word, biases)

    results = []
    for username, score in zip(suspect_usernames, scores):
        if score > 10.0:
            confidence = "High"
        elif score > 3.0:
            confidence = "Medium"
        else:
            confidence = "Low"

        results.append({
            "username": username,
            "score": round(float(score), 4),
            "confidence": confidence
        })

    results.sort(key=lambda x: x["score"], reverse=True)
    return results