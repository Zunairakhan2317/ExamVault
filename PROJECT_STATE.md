# ExamVault: PROJECT_STATE.md

> Read this file FIRST in every new session or new AI tool.
> Update it at the end of every work session (ask the AI: "Update PROJECT_STATE.md").

## 1. What this project is

ExamVault is a Flask web app for an Information Security course project.
Goal: stop exam paper leaks, trace leakers, and keep tamper-evident records.
Claim wording (use this in code comments and report): ExamVault deters leaks, limits insider damage,
traces leakers, and makes tampering detectable. It does NOT eliminate leaks.

Stack: Python 3.11, Flask, SQLite, Jinja2 + Bootstrap 5, cryptography, pycryptodome (optional),
argon2-cffi, pyotp, qrcode, Flask-Login, Flask-Limiter, Flask-WTF, numpy, matplotlib, Pillow, pytest.

Folders: crypto/, auth/, tracing/, audit/, demo/, web/, tests/, keys/ (git-ignored), data/ (git-ignored), docs/.

## 2. Rules for the AI (always follow)

1. Work on ONE module at a time. Do not build extra modules unless asked.
2. Do not rename or move existing files, functions, or database columns.
3. Use the `cryptography` library for AES-GCM, RSA, Ed25519, HKDF, X.509. Never write your own cipher or hash.
4. Write Shamir, Feldman VSS, Schnorr, Merkle tree, Tardos yourself in plain Python with clear comments.
5. Use `secrets` / `os.urandom` for anything secret. `random` is allowed only in simulations.
6. Every module gets a pytest file in tests/. A module is done only when its tests pass.
7. Every function has type hints and a docstring stating its security purpose.
8. Never log or print passwords, shares, or keys. Never commit keys, .env, or \*.db.
9. Ask before adding any new dependency. No paid services.
10. When fixing a bug: fix only that bug. Do not refactor or rename anything else.

## 3. Current status (EDIT THIS EVERY SESSION)

- Date of last update: 2026-10-02
- Tool used last: GitHub Copilot
- Current phase: Layer 1 (cryptographic core)
- Last completed module: crypto/keywrap.py (Layer 1.5)
- Currently working on: none
- NEXT STEP: crypto/signing.py (3.6)
- Tests passing: 25 / 25
- Last git commit message: phase0: project setup

## 4. Master checklist

### Phase 0: Setup

- [ ] Virtual environment created, requirements.txt saved
- [ ] Folder structure and empty files created
- [ ] .gitignore in place BEFORE first commit
- [ ] web/db.py creates all tables
- [ ] `python run.py` shows hello page at localhost:5000
- [ ] `pytest` runs

### Layer 1: Cryptographic core (crypto/)

- [x] 3.1 aes_gcm.py (+ tests: round trip, tamper, wrong key, wrong aad)
- [x] 3.2 kdf.py (master secret + HKDF)
- [x] 3.3 shamir.py (all k-subsets recover; k-1 fails)
- [x] 3.4 feldman.py (RFC 3526 2048-bit prime, q=(p-1)/2, g=4; verify tests)
- [x] 3.5 keywrap.py (hybrid AES-GCM + RSA-OAEP; DB holds only blobs)
- [ ] 3.6 signing.py (Ed25519 over paper hash + exam id + window)
- [ ] 3.7 rotation.py (new polynomial, old shares fail; optional re-key)
- [ ] 3.8 paper_service.py (create_exam, release_exam) + CLI demo

### Layer 4: Audit and PKI (audit/, crypto/pki.py)

- [ ] 6.1 hashchain.py (append-only, SQLite triggers block UPDATE/DELETE)
- [ ] 6.2 merkle.py (root, proofs)
- [ ] 6.3 daily_root.py (signed daily root)
- [ ] 6.4 verifier.py (names the exact altered entry)
- [ ] 6.5 pki.py (root CA, certificates, CRL)
- [ ] 6.6 Revocation wired into login, share submission, downloads

### Layer 2: Access control (auth/)

- [ ] 4.1 passwords.py (Argon2id + policy)
- [ ] 4.2 totp.py (QR enrolment, replay protection)
- [ ] 4.3 rbac.py (role_required, default deny)
- [ ] 4.4 lockout.py + Flask-Limiter
- [ ] 4.5 timewindow.py (server UTC only)
- [ ] 4.6 Share submission flow (one-time nonce, Feldman check, release at k shares)
- [ ] 4.7 schnorr.py (Fiat-Shamir proof of key possession)
- [ ] 4.8 timelock.py (STRETCH, do last)

### Layer 3: Leak tracing (tracing/)

- [ ] 5.1 variants.json (40+ reviewed binary slots)
- [ ] 5.2 codes.py (unique patterns, minimum Hamming distance)
- [ ] 5.3 tardos.py (bias vector, codewords, accusation score)
- [ ] 5.4 copygen.py (per-invigilator copies)
- [ ] 5.5 zerowidth.py (OPTIONAL)
- [ ] 5.6 lsb.py (OPTIONAL)
- [ ] 5.7 analyzer.py (fuzzy match, erasures, ranked suspects, confidence)
- [ ] 5.8 simulate.py (graphs saved to docs/)

### Layer 5: Detection and demos (demo/)

- [ ] 7.1 ecb_vs_gcm.py + /demo/ecb page + one-byte tamper test
- [ ] 7.2 honeytoken.py (decoy file, CRITICAL audit entry, alert, account suspension)
- [ ] 7.3 redteam.py (14 attacks, PASS/FAIL table, exit code, docs/redteam_report.md)

### Web app (web/)

- [ ] base.html with Bootstrap, role-based menu, flash messages
- [ ] login + 2FA pages, enroll_2fa
- [ ] Admin pages (users, revoke, rotate, alerts)
- [ ] Examiner pages (upload, exams, variants)
- [ ] Invigilator pages (countdown, submit share, copy download)
- [ ] Auditor pages (log, verify, roots)
- [ ] Leak Analyzer page
- [ ] Files page (with honeytoken) and ECB demo page
- [ ] Security: CSRF, security headers, session settings, upload limits, error pages

### Final

- [ ] Full pytest suite green
- [ ] Red-team script all PASS
- [ ] End-to-end demo script rehearsed twice
- [ ] Report, slides, backup demo video

## 5. Design decisions already made (do not change without asking)

- AES-256-GCM, 32-byte key, fresh random 12-byte nonce per encryption, AAD = exam id.
- Master secret = random 256-bit integer; AES key = HKDF-SHA256(master, info=b"examvault-paper-key").
- Shamir and Feldman share the same group: RFC 3526 group 14 prime p, q=(p-1)/2, g=4. Shares are mod q.
- Shares are stored only as hybrid-wrapped blobs (AES-GCM key wrapped by holder's RSA-3072 OAEP SHA-256).
- Signatures: Ed25519 over SHA-256(paper) + exam id + window times.
- Passwords: Argon2id. 2FA: TOTP with valid_window=1 and last-used-step replay protection.
- Lockout: 5 failures, 15 minutes. Rate limit: 5 login attempts per minute per IP.
- Time window uses the server UTC clock only.
- Fingerprinting: wording variants; start with unique patterns (min Hamming distance), then Tardos on 40+ binary slots.
- Analyzer: difflib fuzzy match threshold 0.8; unmatched slots are erasures (skipped in scoring).
- Audit: SHA-256 hash chain, genesis prev_hash = 64 zeros, daily Merkle root signed with Ed25519.
- Revocation: internal root CA, CRL checked on login, share submission, and copy download.
- Schnorr is proof of key possession used with HTTPS and TOTP, not a replacement for them.

## 6. Known bugs and TODO (EDIT THIS EVERY SESSION)

- None yet.

## 7. Files changed in the last session

- crypto/keywrap.py (new) — share encryption using AES-GCM with the AES key wrapped by RSA-3072 OAEP-SHA256
- tests/test_keywrap.py (new) — SQLite BLOB round trip and rejection with the wrong private key
- crypto/kdf.py (new) — 256-bit master-secret generation and HKDF-SHA256 AES key derivation
- tests/test_kdf.py (new) — secret generation, stable 32-byte derivation, and input validation tests
- crypto/feldman.py (new) — Feldman commitments and share verification using RFC 3526 group 14
- tests/test_feldman.py (new) — honest, modified-value, and mismatched-index share verification tests
- crypto/aes_gcm.py (new) — AES-256-GCM encrypt/decrypt with 32-byte key validation, 12-byte nonce, AAD binding
- tests/test_aes_gcm.py (new) — 7 tests: round trip, tamper, wrong key, wrong aad, short/long key
- crypto/shamir.py (new) — Shamir secret sharing split/combine over a prime field
- tests/test_shamir.py (new) — 7 tests: k-subsets recover, k-1 fails, 3-of-5 all 10 subsets, input validation

## 8. Cut list (apply in this order if time runs short)

1. Time-lock puzzle 2. LSB image marks 3. Schnorr ZKP 4. Full X.509 CA (use signed revocation list) 5. Zero-width marks and OCR

NEVER cut: AES-GCM, Shamir, signatures, hash chain + verifier, wording fingerprint + analyzer, red-team script, tests.

## 9. Starter prompt for a NEW tool or NEW chat (copy and paste)

```text
I am continuing a project from another AI tool. Read PROJECT_STATE.md and every file it mentions
before doing anything. Then tell me in 5 lines: what is done, what is half-done, and what you plan
to do next. Do not change or rename existing files. Wait for my approval before editing.
```

## 10. End-of-session prompt (paste to the CURRENT tool before its limit runs out)

```text
Update PROJECT_STATE.md: current status, last completed module, what is half-done, exact next step,
tests passing count, known bugs, decisions made, and the list of files changed in this session.
Do not change anything else.
```

## 11. Session log (add one line per session)

| Date       | Tool           | What was done                                                                       | Next step                          |
| ---------- | -------------- | ----------------------------------------------------------------------------------- | ---------------------------------- |
| \_\_\_\_   | \_\_\_\_       | Project started                                                                     | Run P1 (skeleton)                  |
| 2026-10-02 | Claude Code    | Wrote crypto/aes_gcm.py (7 tests) and crypto/shamir.py (7 tests); 14/14 tests pass. | Next step: crypto/feldman.py (3.4) |
| 2026-10-02 | GitHub Copilot | Implemented crypto/feldman.py and tests/test_feldman.py; full suite passes 17/17.   | Next step: crypto/kdf.py (3.2)     |
| 2026-10-02 | GitHub Copilot | Implemented crypto/kdf.py and tests/test_kdf.py; full suite passes 23/23.           | Next step: crypto/keywrap.py (3.5) |
| 2026-10-02 | GitHub Copilot | Implemented crypto/keywrap.py and tests/test_keywrap.py; full suite passes 25/25.   | Next step: crypto/signing.py (3.6) |
