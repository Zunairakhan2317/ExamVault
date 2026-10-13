"""
auth/schnorr.py

Provides non-interactive Zero-Knowledge Proofs of key possession using the 
Schnorr signature/identification scheme via the Fiat-Shamir heuristic[cite: 22, 37].
Security Property: Proves knowledge of the discrete logarithm (secret key) 
without revealing the secret itself, bound to a server nonce and timestamp to prevent replays.
"""

import hashlib
import secrets
from crypto.feldman import P, Q, G

def generate_schnorr_keypair():
    """
    Generates a Schnorr keypair (secret x, public y) in the Feldman/RFC 3526 group[cite: 22].
    x is a random scalar in [1, Q-1], y = G^x mod P.
    """
    x = secrets.randbelow(Q - 1) + 1
    y = pow(G, x, P)
    return x, y

def generate_schnorr_proof(x, y, server_nonce, timestamp):
    """
    Generates a non-interactive Fiat-Shamir Schnorr proof (t, s) for secret x[cite: 22, 37].
    """
    # 1. Pick random ephemeral scalar r in [1, Q-1]
    r = secrets.randbelow(Q - 1) + 1
    
    # 2. Compute commitment t = G^r mod P
    t = pow(G, r, P)
    
    # 3. Compute challenge c = H(G, y, t, server_nonce, timestamp) mod Q
    h_input = f"{G}:{y}:{t}:{server_nonce}:{timestamp}".encode('utf-8')
    c = int(hashlib.sha256(h_input).hexdigest(), 16) % Q
    
    # 4. Compute response s = (r + c * x) mod Q
    s = (r + c * x) % Q
    
    return t, s

def verify_schnorr_proof(y, t, s, server_nonce, timestamp):
    """
    Verifies a non-interactive Schnorr proof (t, s) against public key y[cite: 22, 37].
    Checks whether G^s == t * y^c mod P.
    """
    if not (0 < s < Q) or not (0 < t < P):
        return False
        
    try:
        # 1. Recompute challenge c
        h_input = f"{G}:{y}:{t}:{server_nonce}:{timestamp}".encode('utf-8')
        c = int(hashlib.sha256(h_input).hexdigest(), 16) % Q
        
        # 2. Check left-hand side: G^s mod P
        lhs = pow(G, s, P)
        
        # 3. Check right-hand side: (t * y^c) mod P
        rhs = (t * pow(y, c, P)) % P
        
        return lhs == rhs
    except Exception:
        return False