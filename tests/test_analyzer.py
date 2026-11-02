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


# --- position-aware reading, erasures and thresholds (plan 5.7) ----------------------------------------------

import random  # noqa: E402

from tracing.analyzer import analyze_leak_report, token_hash  # noqa: E402
from tracing.tardos import compute_scores  # noqa: E402
from web import copy_service  # noqa: E402

VERB_PAIRS = [("Explain", "Describe"), ("Define", "State"), ("List", "Name"), ("Compare", "Contrast"),
              ("Write", "Give"), ("Discuss", "Outline"), ("Identify", "Specify"), ("Summarise", "Review")]
TOPICS = ["encryption", "hashing", "firewalls", "VPNs", "phishing", "malware", "backups", "patching", "logging", "MFA",
          "PKI", "TLS", "ransomware", "sandboxing", "IDS", "SIEM", "zero trust", "VLANs", "DNS security", "key rotation",
          "salting", "padding", "nonce reuse", "side channels", "XSS", "CSRF", "SQL injection", "buffer overflow", "DoS",
          "social engineering", "least privilege", "audit trails", "incident response", "risk analysis", "threat models",
          "access control", "biometrics", "smart cards", "digital signatures", "secret sharing", "onion routing",
          "steganography", "forensics", "honeypots", "patch cycles"]
# A realistic paper: the SAME verbs repeat in many questions, so slots can only be told apart by position.
TEMPLATE = "\n".join(
    f"Q{i}. {{{VERB_PAIRS[i % 8][0]}|{VERB_PAIRS[i % 8][1]}}} the role of {topic} in a secure system. [5 marks]"
    for i, topic in enumerate(TOPICS, start=1)
) + "\n"
NAMES = [f"inv{i}" for i in range(10)]


def _setup():
    slots = copy_service.parse_template(TEMPLATE)
    biases = copy_service.new_bias_vector(len(slots))
    words = copy_service.assign_codewords(10, biases)
    return slots, biases, words, [[int(bit) for bit in word] for word in words]


def test_slots_store_hashes_of_nearby_words_not_the_words():
    slots = copy_service.parse_template(TEMPLATE)
    assert len(slots) == 45 and all(slots[i]["before"] and slots[i]["after"] for i in range(45))
    assert slots[0]["after"] == [token_hash("the"), token_hash("role"), token_hash("of")]
    assert "role" not in str(slots)  # only hashes of the fixed words are kept


def test_single_leaker_is_found_even_when_the_same_verbs_repeat():
    slots, biases, words, codes = _setup()
    for leaker in range(10):
        text = copy_service.assemble_copy_text(TEMPLATE, words[leaker])
        top = analyze_leak(text, slots, NAMES, codes, biases)[0]
        assert top["username"] == f"inv{leaker}" and top["confidence"] == "High"


def test_lost_questions_become_erasures_and_the_leaker_is_still_found():
    slots, biases, words, codes = _setup()
    hits = 0
    for trial in range(30):
        leaker = trial % 10
        lines = copy_service.assemble_copy_text(TEMPLATE, words[leaker]).split("\n")
        kept = [line for line in lines if random.random() > 0.15]  # about 15% of the questions are missing
        report = analyze_leak_report("\n".join(kept), slots, NAMES, codes, biases)
        hits += report["results"][0]["username"] == f"inv{leaker}"
        assert report["slots_matched"] + report["slots_unreadable"] == 45
    assert hits >= 28


def test_erasures_are_left_out_of_the_score_not_counted_as_zero():
    slots, biases, words, codes = _setup()
    lines = copy_service.assemble_copy_text(TEMPLATE, words[3]).split("\n")
    report = analyze_leak_report("\n".join(lines[:30]), slots, NAMES, codes, biases)  # last 15 questions cut off
    assert report["slots_unreadable"] == 15 and report["slots_matched"] == 30
    expected = compute_scores([c[:30] for c in codes], [int(b) for b in words[3][:30]], biases[:30])
    by_name = {r["username"]: r["score"] for r in report["results"]}
    assert all(abs(by_name[n] - round(s, 4)) < 1e-6 for n, s in zip(NAMES, expected))


def test_two_colluders_are_accused_at_a_measured_rate_of_at_least_75_percent():
    """Plan success criterion 4: at least one colluder accused (measured about 87 percent at 45 slots)."""
    slots, biases, words, codes = _setup()
    rng, accused, trials = random.Random(7), 0, 200
    for _ in range(trials):
        biases = copy_service.new_bias_vector(45)
        words = copy_service.assign_codewords(10, biases)
        codes = [[int(bit) for bit in word] for word in words]
        pair = rng.sample(range(10), 2)
        leaked = "".join(
            words[pair[0]][k] if words[pair[0]][k] == words[pair[1]][k] else rng.choice([words[pair[0]][k], words[pair[1]][k]])
            for k in range(45)
        )
        report = analyze_leak_report(copy_service.assemble_copy_text(TEMPLATE, leaked), slots, NAMES, codes, biases)
        accused += any(r["username"] in {f"inv{i}" for i in pair} and r["confidence"] != "Low" for r in report["results"])
    assert accused / trials >= 0.75


def test_unrelated_text_gives_no_match_and_only_low_confidence():
    slots, biases, words, codes = _setup()
    report = analyze_leak_report("Completely different text about cooking pasta.", slots, NAMES, codes, biases)
    assert report["slots_matched"] == 0 and report["verdict"] == "none"
    assert all(r["confidence"] == "Low" and r["score"] == 0 for r in report["results"])


def test_report_always_carries_the_evidence_caveat():
    slots, biases, words, codes = _setup()
    report = analyze_leak_report(copy_service.assemble_copy_text(TEMPLATE, words[0]), slots, NAMES, codes, biases)
    assert "evidence, not proof" in report["caveat"] and report["verdict"] == "single"
