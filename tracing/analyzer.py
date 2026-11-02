"""Leak Analyzer: reads a leaked text slot by slot, then scores every suspect (Plan 5.7).

How it reads the leaked word y (one bit per slot):
- Slots made by the current upload code carry ANCHORS (hashes of the 3 fixed words before and after the slot).
  The analyzer finds where each slot sits in the leaked text, in reading order, and compares only the words in
  that spot with the slot's two variants. So a verb such as "Explain" that appears in thirty questions is read
  in the right question each time.
- Older slots without anchors fall back to matching the variants against the whole text.
- A slot that cannot be read (words missing, too much OCR noise, or both variants match equally well) is an
  ERASURE. Erasures are left out of the score completely (they are not counted as 0 or 1).

How it labels the result: the confidence thresholds come from a simulation on the spot. Random innocent
codewords (drawn with the exam's own secret biases) are scored against the same leaked word, and a suspect is
labelled High / Medium / Low by comparing their score with the 99.9th / 99th percentile of those innocent scores.
The score is evidence, not proof.
"""
from __future__ import annotations

import difflib
import hashlib
import math
import random
import re
from typing import Any

from tracing.tardos import compute_scores

ANCHOR_MATCH_RATIO = 0.6  # at least 2 of 3 anchor words must match (tolerates one OCR error)
AMBIGUITY_MARGIN = 0.05  # two variants this close in score: the slot is unreadable
INNOCENT_SAMPLES = 1500  # random innocent codewords used to set the thresholds
HIGH_PERCENTILE, MEDIUM_PERCENTILE = 0.999, 0.99
CAVEAT = "The score is evidence, not proof."


def normalize_text(text: str) -> str:
    """Normalise text: lowercase, collapse spaces, strip punctuation."""
    text = text.lower()
    text = re.sub(r"[^\w\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def token_hash(token: str) -> str:
    """Short hash of one normalised word (stored as an anchor instead of the word itself)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:8]


def _legacy_choice(normalized_leaked: str, variants: list[str], threshold: float) -> int | None:
    """Old method (no anchors): best variant against the WHOLE text. Used only for slots without anchors."""
    best_score, best_index = 0.0, None
    words_leaked = set(normalized_leaked.split())
    for index, text in enumerate(variants):
        norm = normalize_text(text)
        ratio = difflib.SequenceMatcher(None, norm, normalized_leaked).ratio()
        words = set(norm.split())
        overlap = len(words & words_leaked) / max(1, len(words)) if words else 0.0
        score = max(ratio, overlap)
        if score > best_score:
            best_score, best_index = score, index
    return best_index if best_score >= threshold else None


def _anchor_hits(hashes: list[str], anchor: list[str], start: int) -> int:
    """How many anchor words match the leaked words that begin at `start` (out of range counts as no match)."""
    return sum(1 for offset, wanted in enumerate(anchor) if 0 <= start + offset < len(hashes) and hashes[start + offset] == wanted)


def _locate(hashes: list[str], slot: dict, pointer: int, max_words: int) -> tuple[int, int | None] | None:
    """Find (start, end) of the slot's words in the leaked text, at or after `pointer`. end None = open-ended."""
    before, after = slot.get("before") or [], slot.get("after") or []
    need_before = math.ceil(len(before) * ANCHOR_MATCH_RATIO)
    need_after = math.ceil(len(after) * ANCHOR_MATCH_RATIO)
    best: tuple[int, int, int | None] | None = None  # (score, start, end)
    for start in range(pointer, len(hashes) + 1):
        hits_before = _anchor_hits(hashes, before, start - len(before)) if before else 0
        if before and hits_before < need_before:
            continue
        if not after:
            candidate = (hits_before, start, None)
            if best is None or candidate[0] > best[0]:
                best = candidate
            continue
        for end in range(start, min(len(hashes), start + max_words + 3) + 1):
            hits_after = _anchor_hits(hashes, after, end)
            if hits_after < need_after:
                continue
            candidate = (hits_before + hits_after, start, end)
            if best is None or candidate[0] > best[0]:
                best = candidate  # ties keep the earliest place (reading order)
    return None if best is None else (best[1], best[2])


def _read_slot(tokens: list[str], located: tuple[int, int | None], variants: list[str], threshold: float) -> int | None:
    """Which variant is written in the located spot, or None when it is unreadable or ambiguous."""
    start, end = located
    scores: list[float] = []
    for text in variants:
        words = normalize_text(text).split()
        window = tokens[start:end] if end is not None else tokens[start:start + len(words)]
        scores.append(difflib.SequenceMatcher(None, " ".join(words), " ".join(window)).ratio() if window else 0.0)
    order = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
    if scores[order[0]] < threshold:
        return None
    if len(order) > 1 and scores[order[0]] - scores[order[1]] < AMBIGUITY_MARGIN:
        return None
    return order[0]


def extract_leaked_word(leaked_text: str, slots: list[dict], threshold: float = 0.8) -> list[int | None]:
    """The leaked word: for every slot the index of the variant found in the text, or None (erasure)."""
    normalized = normalize_text(leaked_text)
    tokens = normalized.split()
    hashes = [token_hash(t) for t in tokens]
    word: list[int | None] = []
    pointer = 0
    for slot in slots:
        variants = slot["variants"]
        if not (slot.get("before") or slot.get("after")):
            word.append(_legacy_choice(normalized, variants, threshold))  # no anchors: old whole-text method
            continue
        max_words = max(len(normalize_text(v).split()) for v in variants)
        located = _locate(hashes, slot, pointer, max_words)
        if located is None:
            word.append(None)
            continue
        choice = _read_slot(tokens, located, variants, threshold)
        word.append(choice)
        if choice is not None and located[1] is not None:
            pointer = located[1]  # the next slot is searched after this one
    return word


def _percentile(sorted_values: list[float], fraction: float) -> float:
    return sorted_values[min(len(sorted_values) - 1, int(fraction * (len(sorted_values) - 1)))]


def innocent_thresholds(biases: list[float], leaked_word: list[int], samples: int = INNOCENT_SAMPLES) -> tuple[float, float]:
    """(medium, high) score thresholds measured by simulation, not taken from theory.

    Random innocent codewords drawn with the exam's secret biases are scored against the leaked word; the
    thresholds are the 99th and 99.9th percentile of those innocent scores (about 1 % and 0.1 % false accusation).
    """
    innocents = [[1 if random.random() < p else 0 for p in biases] for _ in range(samples)]
    scores = sorted(compute_scores(innocents, leaked_word, biases))
    return _percentile(scores, MEDIUM_PERCENTILE), _percentile(scores, HIGH_PERCENTILE)


def analyze_leak_report(
    leaked_text: str,
    slots: list[dict],
    suspect_usernames: list[str],
    suspect_codes: list[list[int]],
    biases: list[float],
    threshold: float = 0.8,
) -> dict[str, Any]:
    """Full analysis: ranked suspects plus how much of the leak could be read and what it means."""
    raw_word = extract_leaked_word(leaked_text, slots, threshold)
    readable = [i for i, bit in enumerate(raw_word) if bit is not None]
    word = [int(raw_word[i]) for i in readable]  # erasures are dropped here, never turned into 0
    sub_biases = [biases[i] for i in readable]
    sub_codes = [[code[i] for i in readable] for code in suspect_codes]
    if readable:
        scores = compute_scores(sub_codes, word, sub_biases)
        medium, high = innocent_thresholds(sub_biases, word)
    else:
        scores, medium, high = [0.0] * len(suspect_usernames), math.inf, math.inf
    results = []
    for username, score in zip(suspect_usernames, scores):
        label = "High" if score > high else "Medium" if score > medium else "Low"
        results.append({"username": username, "score": round(float(score), 4), "confidence": label, "matched_slots": len(readable)})
    results.sort(key=lambda r: r["score"], reverse=True)
    accused = [r for r in results if r["confidence"] != "Low"]
    verdict = "none" if not accused else "single" if len(accused) == 1 else "multiple"
    return {
        "results": results,
        "slots_total": len(slots),
        "slots_matched": len(readable),
        "slots_unreadable": len(slots) - len(readable),
        "verdict": verdict,
        "medium_threshold": None if not readable else round(medium, 3),
        "high_threshold": None if not readable else round(high, 3),
        "caveat": CAVEAT,
    }


def analyze_leak(
    leaked_text: str,
    slots: list[dict],
    suspect_usernames: list[str],
    suspect_codes: list[list[int]],
    biases: list[float],
    threshold: float = 0.8,
) -> list[dict[str, Any]]:
    """Ranked table of suspects (name, score, confidence, matched slots), best first."""
    return analyze_leak_report(leaked_text, slots, suspect_usernames, suspect_codes, biases, threshold)["results"]
