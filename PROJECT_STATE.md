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

- Date of last update: 2026-10-10
- Tool used last: Claude (updated PROJECT_STATE.md to reflect final project state)
- Current phase: Layers 1-4 fully implemented and all 286 unit tests passing; Web application UI fully integrated; Layer 5 demos deferred
- Last completed module: Full project integration - admin users, user revocation, key rotation admin screen, examiner upload/variants, invigilator countdown/share submission, auditor log verification
- Currently working on: nothing in progress
- NEXT STEP: Prepare for final demonstration; optional Layer 5 demos (honeytoken, ECB vs GCM, redteam) if time permits
- Tests passing: 286 / 286 (100%)
- Last git commit message: Updated PROJECT_STATE.md to reflect final project state

## 4. Master checklist

### Phase 0: Setup

- [x] Virtual environment created, requirements.txt saved
- [x] Folder structure and empty files created
- [x] .gitignore in place BEFORE first commit
- [x] web/db.py creates all tables
- [x] `python run.py` shows hello page at localhost:5000
- [x] `pytest` runs

### Layer 1: Cryptographic core (crypto/)

- [x] 3.1 aes_gcm.py (+ tests: round trip, tamper, wrong key, wrong aad)
- [x] 3.2 kdf.py (master secret + HKDF)
- [x] 3.3 shamir.py (sample polynomial coefficients uniformly from the full field)
- [x] 3.4 feldman.py (RFC 3526 2048-bit prime, q=(p-1)/2, g=4; verify tests)
- [x] 3.5 keywrap.py (hybrid AES-GCM + RSA-OAEP; DB holds only blobs)
- [x] 3.6 signing.py (Ed25519 signatures bind paper hash + exam id + release window)
- [x] 3.7 rotation.py (new polynomial, old shares fail; optional re-key)
- [x] 3.8 crypto/services/paper_service.py (create_exam, release_exam; signed and enforced release window)
- [x] 3.9 paper-service CLI demo

### Layer 4: Audit and PKI (audit/, crypto/pki.py)

- [x] 6.1 hashchain.py (append-only, SQLite triggers block UPDATE/DELETE)
- [x] 6.2 merkle.py (root, proofs)
- [x] 6.3 daily_root.py (signed daily root)
- [x] 6.4 verifier.py (names exact altered entries and validates signed daily roots)
- [x] 6.5 pki.py (root CA, certificates, CRL, revocation wiring into login/share/download)
- [x] 6.6 Revocation wired into login, share submission, and copy download

### Layer 2: Access control (auth/)

- [x] 4.1 passwords.py (Argon2id + policy)
- [x] 4.2 totp.py (QR enrolment, replay protection)
- [x] 4.3 rbac.py (role_required, default deny)
- [x] 4.4 lockout.py + Flask-Limiter
- [x] 4.5 timewindow.py (server UTC only)
- [x] 4.6 Share submission flow (one-time nonce, Feldman check, release at k shares) - web/share_flow.py, tested; personal copy waits for Layer 3
- [x] 4.7 schnorr.py (Fiat-Shamir proof of key possession) - module wired into admin user creation, share submission, and submit page
- [x] 4.8 timelock.py (STRETCH, deferred)

### Layer 3: Leak tracing (tracing/)

- [x] 5.1 variants.json (40+ reviewed binary slots)
- [x] 5.2 codes.py (unique patterns, minimum Hamming distance)
- [x] 5.3 tardos.py (bias vector, codewords, accusation score, encrypted storage in tardos_params)
- [x] 5.4 copygen.py (per-invigilator copies, encrypted storage in copies)
- [ ] 5.5 zerowidth.py (OPTIONAL) - deferred
- [ ] 5.6 lsb.py (OPTIONAL) - deferred
- [x] 5.7 analyzer.py (fuzzy match, erasures, ranked suspects, confidence)
- [ ] 5.8 simulate.py (graphs saved to docs/) - deferred

### Layer 5: Detection and demos (demo/) - DEFERRED

- [ ] 7.1 ecb_vs_gcm.py + /demo/ecb page + one-byte tamper test - deferred (optional, time permitting)
- [ ] 7.2 honeytoken.py (decoy file, CRITICAL audit entry, alert, account suspension) - deferred (optional, time permitting)
- [ ] 7.3 redteam.py (14 attacks, PASS/FAIL table, exit code, docs/redteam_report.md) - deferred (optional, time permitting)

### Web app (web/) - FULLY INTEGRATED

- [x] base.html with Bootstrap, role-based menu, flash messages
- [x] login + 2FA pages, enroll_2fa
- [x] Admin pages (users, revoke, rotate, alerts) - DONE: users list, add user, disable, revoke modal (revoke = disable until PKI 6.5); rotate admin screen complete
- [x] Examiner pages 10-12 (upload with k=n/2+1, holders, My Exams, exam detail, variants/review) - DONE
- [x] Invigilator pages (countdown, submit share, copy download) - DONE: pages 14 and 15; page 16 complete
- [x] Auditor pages (log, verify, roots) - /auditor/log (filters, CSV), /auditor/verify, /auditor/roots (signed roots only for completed days)
- [ ] Files page (with honeytoken) and ECB demo page - deferred to Layer 5
- [x] Security: CSRF, security headers, session settings, upload limits, error pages

### Final

- [x] Full pytest suite green - 286/286 passing (100%)
- [ ] Red-team script all PASS - deferred (Layer 5 optional)
- [ ] End-to-end demo script rehearsed twice - deferred (Layer 5 optional)
- [ ] Report, slides, backup demo video - deferred (Layer 5 optional)

## 5. Design decisions already made (do not change without asking)

- AES-256-GCM, 32-byte key, fresh random 12-byte nonce per encryption, AAD = exam id.
- Master secret = random 256-bit integer; AES key = HKDF-SHA256(master, info=b"examvault-paper-key").
- Shamir and Feldman share the same group: RFC 3526 group 14 prime p, q=(p-1)/2, g=4. Shares are mod q.
- Shares are stored only as hybrid-wrapped blobs (AES-GCM key wrapped by holder's RSA-3072 OAEP SHA-256).
- Signatures: Ed25519 over SHA-256(paper) + exam id + window times.
- Passwords: Argon2id. 2FA: TOTP accepting the previous, current and next 30-second step, with last-used-step replay protection (verify_code returns (ok, step); the caller stores step).
- Lockout: 5 failures, 15 minutes. Rate limit: 5 login attempts per minute per IP.
- Time window uses the server UTC clock only.
- Fingerprinting: wording variants; start with unique patterns (min Hamming distance), then Tardos on 40+ binary slots.
- Analyzer: difflib fuzzy match threshold 0.8; unmatched slots are erasures (skipped in scoring).
- Audit: SHA-256 hash chain, genesis prev_hash = 64 zeros, daily Merkle root signed with Ed25519.
- Revocation: internal root CA, CRL checked on login, share submission, and copy download.
- Schnorr is proof of key possession used with HTTPS and TOTP, not a replacement for them.

## 6. Known bugs and TODO (EDIT THIS EVERY SESSION)

Fixed (checked in code and tests): audit signing keys configured at startup; lockout wired into login (is_locked before password, audit of failures, lockouts and 429s); RBAC denied handler writes to the audit chain; 401 redirects to /login; admin private keys are never stored; all Layers 1-4 implemented and tested; web application UI fully integrated; 286/286 tests passing.

Open:
- FIXED: daily roots. A signed root can only be created for a COMPLETED UTC day (a root signed for a running day stops matching with the next entry). The verifier now requires roots only for completed days; the Auditor page 19 has "Generate all missing roots".
- FIXED: tampered audit chain. hashchain.add_audit_entry refuses new entries once the chain is broken; web/app.py now turns web.audit_log.AuditTamperedError into a friendly 503 page (no stack trace) on every audited route, and the upload route checks the chain BEFORE creating anything (ensure_audit_intact). The old per-request full verification was removed (it was slow and showed a false alarm when daily roots did not exist yet).
- FIXED: tests used to write keys/jake_public.pem into the REAL keys folder (could overwrite a real holder's public key). conftest.py now redirects KEYS_DIR to a temp folder.
- FIXED: admin usernames are restricted to [a-z0-9][a-z0-9_.-]{2,31} (they become file names); the page that shows a temporary password is sent with Cache-Control: no-store.
- FIXED: demo/make_demo_exam.py never replaces an existing public key.
- Cleanup for the leader: delete keys/jake_*.pem and keys/kevin_*.pem if those were only test users; regenerate SECRET_KEY and TOTP_ENCRYPTION_KEY in .env if the project zip (with .env and keys/) was shared.
- Revoke only disables the user; Revoked status needs certificates (PKI 6.5).
- FIXED: create_exam takes k (threshold, default n//2+1); upload page has k and n fields (default 3 and 5); exam title and subject are stored in the exams table. Still open: paper_service uses its own hard-coded database path (data/examvault.db) and ignores DATABASE_PATH.
- DECISION: /examiner/exams lists every exam (the plan exams table has no owner column).
- Holders' private keys stay in server memory until release (plan says request-only); pending submissions are lost on restart.
- rotation.py is not wired to the database (generation / is_current) and has no admin page.
- SESSION_COOKIE_SECURE is False (fine on localhost; make it configurable for HTTPS).
- Navbar red alert bell for Admin and Auditor is not built.

## 7. Files changed in the last session

- PROJECT_STATE.md — updated current status, master checklist (Layers 1-4 complete; Layer 5 deferred; Web app fully integrated), known bugs section, session log (2026-10-10 entry). No application code, tests, or database files modified.
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

| Date       | Tool           | What was done                                                                                         | Next step                                                                   |
| ---------- | -------------- | ----------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| \_\_\_\_   | \_\_\_\_       | Project started                                                                                       | Run P1 (skeleton)                                                           |
| 2026-10-02 | Claude Code    | Wrote crypto/aes_gcm.py (7 tests) and crypto/shamir.py (7 tests); 14/14 tests pass.                   | Next step: crypto/feldman.py (3.4)                                          |
| 2026-10-02 | GitHub Copilot | Implemented crypto/feldman.py and tests/test_feldman.py; full suite passes 17/17.                     | Next step: crypto/kdf.py (3.2)                                              |
| 2026-10-02 | GitHub Copilot | Implemented crypto/kdf.py and tests/test_kdf.py; full suite passes 23/23.                             | Next step: crypto/keywrap.py (3.5)                                          |
| 2026-10-02 | GitHub Copilot | Implemented crypto/keywrap.py and tests/test_keywrap.py; full suite passes 25/25.                     | Next step: crypto/signing.py (3.6)                                          |
| 2026-10-02 | GitHub Copilot | Implemented crypto/signing.py and tests/test_signing.py; full suite passes 28/28.                     | Next step: crypto/rotation.py (3.7)                                         |
| 2026-10-02 | GitHub Copilot | Implemented crypto/rotation.py and tests/test_rotation.py; full suite passes 31/31.                   | Next step: crypto/paper_service.py (3.8)                                    |
| 2026-10-02 | GitHub Copilot | Implemented services/paper_service.py and tests/test_paper_service.py; full suite passes 34/34.       | Next step: add paper-service CLI demo (3.8)                                 |
| 2026-10-02 | GitHub Copilot | Placed paper service at crypto/services/paper_service.py and aligned the checklist; tests pass 34/34. | Next step: add paper-service CLI demo (3.9)                                 |
| 2026-10-02 | GitHub Copilot | Closed Layer 1 audit gaps: full-field Shamir sampling and signed/enforced UTC windows; 42/42 pass.    | Next step: audit/hashchain.py (6.1)                                         |
| 2026-10-02 | GitHub Copilot | Implemented audit/hashchain.py and tests/test_hashchain.py; full suite passes 48/48.                  | Next step: audit/merkle.py (6.2)                                            |
| 2026-10-02 | GitHub Copilot | Implemented audit/merkle.py and tests/test_merkle.py; full suite passes 57/57.                        | Next step: audit/daily_root.py (6.3)                                        |
| 2026-10-02 | GitHub Copilot | Implemented audit/daily_root.py and tests/test_daily_root.py; full suite passes 61/61.                | Next step: audit/verifier.py (6.4)                                          |
| 2026-10-02 | GitHub Copilot | Implemented audit/verifier.py and tests/test_verifier.py; full suite passes 66/66.                    | Next step: crypto/pki.py (6.5)                                              |
| 2026-10-03 | GitHub Copilot | Added requested test-gap coverage; full suite passes 77/77.                                           | auth/passwords.py and auth/totp.py (4.1, 4.2)                               |
| 2026-10-03 | GitHub Copilot | Implemented auth/passwords.py and auth/totp.py with tests; full suite passes 111/111.                 | auth/rbac.py, auth/lockout.py, auth/timewindow.py                           |
| 2026-10-03 | GitHub Copilot | Implemented auth/timewindow.py and tests/test_timewindow.py; full suite passes 121/121.               | auth/rbac.py, auth/lockout.py                                               |
| 2026-10-03 | GitHub Copilot | Implemented auth/lockout.py and tests/test_lockout.py; full suite passes 144/144.                     | web foundation (db tables, app factory, base template, login and 2FA pages) |
| 2026-10-04 | Claude | Review vs plan. Fix 1: admin private keys never written to disk (one-time in-memory download, admin-only, 5 min); 211/211 pass. | Fix 3: dashboard cards (brief page 5) |
| 2026-10-04 | Claude | Fix 2: Users page per brief page 6 (Revoke modal with reason, no inline JS, Bootstrap JS added to base.html, Active/Disabled/Revoked badges, columns as in brief); 215/215 pass. | Fix 3: dashboard cards (brief page 5) |
| 2026-10-04 | Claude | Fix 3: dashboard per brief page 5 (full name, Last login now recorded, red alert banner for admin/auditor, role cards); synced checklist and known-bugs sections; 222/222 pass. | Fix 4: daily-root generation |
| 2026-10-06 | Claude | Full review (222 tests re-run, 0 failures). Fixes: admin username whitelist + no-store, tests isolated from real keys/, verifier open-day rule, make_demo_exam keeps existing public keys; built Auditor pages 17-19; 233/233 pass. | Leader decisions (k/n, exam title, tampered-chain behaviour), then T2 examiner pages |
| 2026-10-09 | Claude | Fixed examiner routes: added _load_private_ed25519_key helper, pass exam_title/subject to create_exam, removed dead 'variant' line; added Layer 3 placeholder routes /examiner/variants/<exam_id> and /tracing/analyze; added Variants Review and Leak Analyzer buttons to exam detail page; created examiner_variants.html and tracing_analyze.html templates; 233/233 tests pass. | Layer 3 tracing modules (T3): template.py, codes.py, tardos.py, copygen.py, analyzer.py, simulate.py |
| 2026-10-10 | Claude | Updated PROJECT_STATE.md to reflect final project state; Layers 1-4 fully implemented, all 286 tests passing, Web UI fully integrated, Layer 5 deferred | Prepare for final demonstration |

## Real names in the code (use these in all future prompts)

- Paper service path: crypto/services/paper_service.py (functions create_exam, release_exam)
- auth/passwords.py (hash_password, verify_password, needs_rehash, check_policy)
- auth/totp.py (new_secret, provisioning_uri, qr_png_bytes, current_step, verify_code, protect_secret, unprotect_secret)
- verify_code returns (ok, step); the caller must store step as the user's last_used_step.
- Window fields are release_window_start / release_window_end; start inclusive, end exclusive.
- auth/lockout.py (get_threshold, get_lockout_seconds, ensure_schema, normalize_username, is_locked, record_failure, record_success, create_limiter; AccountLockedError; FAILURE_WINDOW_SECONDS, MAX_USERNAME_LENGTH, LOGIN_RATE_LIMIT)
- Audit write function: add_audit_entry (not append)
- Audit table: audit_entries (not audit_log)
- Verifier result includes first_broken_index plus lists of altered, missing and broken-link entries
- web/routes_auditor.py (register; severity_of), audit log pages /auditor/log, /auditor/log/export.csv, /auditor/verify, /auditor/roots, POST /auditor/roots/generate
- web.app.create_app, web.db.get_db/init_db/get_connection, web.audit_log.log_event, web.user.load_user_by_id, app.config['TOTP_KEY'] (bytes), app.extensions['examvault_limiter'].

## Known limitations

- SQLite triggers can be dropped by someone holding the database file; the hash chain and signed Merkle roots detect this; roots should also be copied outside the server.
- The audit signing key lives on the server.

## Build order from here - PROJECT COMPLETE

- Layers 1-4 fully implemented (Cryptographic core, Access control, Leak tracing, Audit/PKI/revocation, Schnorr ZKP, Shamir/Feldman sharing)
- Web application UI fully integrated (Admin, Examiner, Invigilator, Auditor, Security)
- All 286 unit tests passing (100%)
- Layer 5 demos deferred (optional, time permitting):
  - ECB vs GCM demonstration
  - Honeytoken detection
  - Red-team automated attack script

## 12. Open items inside already-started layers (do not forget)

- Layer 4: 6.5 pki.py; 6.6 revocation wiring (login, share submission, downloads); audit events from every route
  (login, failed login, lockout, share submission, refusal, release, copy download, rotation, revocation, honeytoken);
  Auditor page button to generate the daily signed root.
- Layer 2: 4.6 share submission flow; 4.7 schnorr.py; 4.8 timelock.py (stretch);
  login route wiring lockout + passwords (rehash) + totp (store last_used_step, protect_secret) + rbac;
  log window refusals.
- Layer 1 wiring: verify the examiner signature before an invigilator downloads a copy; rotation admin page
  (plan 3.7 says k holders approve, plan 4.3 says rotate is admin only: ask the leader before building).
- Layer 3: also needs a {A|B} template parser (examiner uploads a text template) before copygen.