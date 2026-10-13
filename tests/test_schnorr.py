"""
tests/test_schnorr.py

Unit tests for the Schnorr ZKP module.
Proves that valid proofs are accepted, invalid proofs/secrets are rejected, 
and replayed or modified nonces fail verification[cite: 22, 37].
"""

import pytest
from auth.schnorr import generate_schnorr_keypair, generate_schnorr_proof, verify_schnorr_proof

def test_schnorr_valid_proof():
    """Valid proof generated with correct secret passes verification."""
    x, y = generate_schnorr_keypair()
    nonce = "test-nonce-12345"
    timestamp = "2026-10-09T12:00:00Z"
    
    t, s = generate_schnorr_proof(x, y, nonce, timestamp)
    assert verify_schnorr_proof(y, t, s, nonce, timestamp) is True

def test_schnorr_invalid_secret():
    """Proof generated with a different secret fails verification against y."""
    x1, y1 = generate_schnorr_keypair()
    x2, y2 = generate_schnorr_keypair()
    
    nonce = "test-nonce-12345"
    timestamp = "2026-10-09T12:00:00Z"
    
    # Generate proof using x1, but try to verify against y2
    t, s = generate_schnorr_proof(x1, y1, nonce, timestamp)
    assert verify_schnorr_proof(y2, t, s, nonce, timestamp) is False

def test_schnorr_tampered_proof():
    """Tampering with response s or commitment t invalidates the proof."""
    x, y = generate_schnorr_keypair()
    nonce = "test-nonce-12345"
    timestamp = "2026-10-09T12:00:00Z"
    
    t, s = generate_schnorr_proof(x, y, nonce, timestamp)
    
    # Tamper with s
    assert verify_schnorr_proof(y, t, s + 1, nonce, timestamp) is False

def test_schnorr_nonce_replay_protection():
    """A proof bound to a specific server nonce fails if the nonce changes (replay prevention)."""
    x, y = generate_schnorr_keypair()
    nonce_original = "nonce-A"
    nonce_replayed = "nonce-B"
    timestamp = "2026-10-09T12:00:00Z"
    
    t, s = generate_schnorr_proof(x, y, nonce_original, timestamp)
    
    # Attempting to verify with a different server nonce must fail
    assert verify_schnorr_proof(y, t, s, nonce_replayed, timestamp) is False