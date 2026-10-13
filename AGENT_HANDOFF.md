# ExamVault: AGENT_HANDOFF.md

Read this file and PROJECT_STATE.md first. The leader (a student) works with you in Roman Urdu; answer her in simple
Roman Urdu (technical words in English), short and practical. She is the only coder and reviews everything.

THE PLAN IS THE SOURCE OF TRUTH. If anything in the existing code, in this file, or in a request differs from the plan,
STOP and ask before changing anything. Never add features, tables, permissions or files that are not listed here.
If `docs/` contains the exported "Full Implementation Plan" and "Frontend Design Brief", read them for details.

## 0. First actions (do these before writing code)

1. `python -m pytest -q` (all tests must pass; about 190 expected) and `git status` (should be clean).
2. Read PROJECT_STATE.md, then list the files under crypto/, audit/, auth/, web/, demo/, tracing/, tests/.
3. Tell the leader in 5 lines: what is done, what is half-done, and the task you will do next. Wait for "ok".

## 1. What the project is

ExamVault is a Flask web app (Information Security course project). It deters exam-paper leaks, limits insider damage,
traces leakers and makes tampering detectable. Never write "eliminates leaks" or "enterprise-grade".
Stack: Python 3.11, Flask, SQLite, Jinja2 + Bootstrap 5 (CDN), cryptography, argon2-cffi, pyotp, qrcode, Flask-Login,
Flask-Limiter, Flask-WTF, numpy, matplotlib, Pillow, reportlab, pdfplumber, pytest. Ask before adding any dependency.
Folders: crypto/, auth/, audit/, tracing/, demo/, web/, tests/, keys/ and data/ (both git-ignored), docs/.

## 2. Rules (always)

1. ONE task at a time. Finish it, run the tests, then stop and report.
2. Never rename or move existing files, functions, tables or columns. Bug fix = fix only that bug.
3. Crypto primitives only from the `cryptography` library (AES-GCM, RSA, Ed25519, HKDF, X.509) or hashlib. Never your own cipher.
   Shamir, Feldman, Schnorr, Merkle, Tardos are plain Python with comments.
4. Randomness for anything secret: `secrets` / `os.urandom`. `random` only inside tracing/simulate.py.
5. Every module gets a pytest file. A task is done only when the whole suite passes. Show the new test count.
6. Type hints and a docstring on every function (state the security purpose).
7. Never log, print or store passwords, key shares, private keys, TOTP secrets or the paper text.
   Use `web.audit_log.log_event(conn, actor, action, details)`; it drops detail keys containing: password, secret, share,
   token, otp, code, key, private. So use keys like `exam_id`, `reason`, `count`, `used`, `index`.
8. SQL always parameterised. Jinja autoescape stays on. All POST forms carry the CSRF token.
9. The CSP forbids inline scripts and inline styles. Put JavaScript in web/static/*.js; use `<progress>` instead of
   inline-width progress bars; no `style="..."` attributes.
10. Web routes: protect with `@role_required(...)` from auth.rbac; every denial is already audited by the app.
11. After each task: update PROJECT_STATE.md (Section 3 status, Section 4 ticks, Section 7 files, "Real names in the code",
    Section 11 row) and give the leader a commit message. Do not commit yourself unless she asks.
12. If a request conflicts with the plan or is unclear: stop and ask one short question.

## 3. Real names in the code (use exactly these)

crypto/aes_gcm.py: encrypt(plaintext, key, aad) -> (nonce, ciphertext); decrypt(nonce, ciphertext, key, aad).
crypto/kdf.py: generate_master_secret(), derive_aes_key(master_secret) (HKDF-SHA256, info=b"examvault-paper-key").
crypto/shamir.py: split(secret, k, n, prime), combine(shares, prime). crypto/feldman.py: commit(coeffs), verify_share(x, y, commitments)
(RFC 3526 group 14, q=(p-1)//2, g=4, shares mod q). crypto/keywrap.py: wrap_share(share_bytes, holder_public_key), unwrap_share(blob, holder_private_key).
crypto/signing.py: generate_keypair, sign_message, verify_signature. crypto/rotation.py: rotate_shares, verify_share_validity.
crypto/services/paper_service.py: create_exam(paper_content, holders, admin_private_key, release_window_start, release_window_end) ->
{exam_id, threshold, num_shares, release_window_start, release_window_end, commitments, wrapped_shares, signature};
release_exam(exam_id, submitted_shares, holder_private_keys, admin_public_key) -> paper bytes. It has a module global DATABASE_PATH
(its own database with tables exams and exam_shares) and NO k/n parameters (the threshold is decided inside). Do not edit it.
audit/hashchain.py: add_audit_entry (table audit_entries), verify_hashchain. audit/merkle.py. audit/daily_root.py:
configure_audit_signing_keys, configure_audit_verification_key, compute_daily_root(conn, date), verify_daily_root.
audit/verifier.py: verify_full_chain(conn) -> dict(status "green"/"red", valid, altered_entry_indices, missing_entry_indices,
broken_link_indices, first_broken_index, missing_daily_root_dates, invalid_daily_root_dates).
auth/passwords.py (hash_password, verify_password, needs_rehash, check_policy), auth/totp.py (new_secret, provisioning_uri, qr_png_bytes,
verify_code -> (ok, step), protect_secret, unprotect_secret), auth/timewindow.py (window fields release_window_start/end; start inclusive,
end exclusive; window_summary, require_open, WindowError), auth/rbac.py (ROLES, PERMISSIONS, has_permission, set_denied_handler, role_required),
auth/lockout.py (ensure_schema, is_locked, record_failure, record_success, create_limiter, LOGIN_RATE_LIMIT).
web/app.py create_app (sets app.config["TOTP_KEY"], app.extensions["examvault_limiter"], loads the audit signing key keys/audit_ed25519.pem);
web/db.py (get_connection, init_db, get_db, SCHEMA; web tables: users, share_submissions, copies, tardos_params, used_nonces,
honeytoken_events, certificates, shares, exam_release; login_attempts via lockout), web/user.py, web/audit_log.py (log_event),
web/routes_auth.py (login, 2FA, enrol, logout, dashboard, NAV dict), web/exam_store.py, web/share_flow.py (PendingShares, ShareRefused,
submit_share), web/routes_invigilator.py (pages 14-16; app.extensions["examvault_pending"] and app.extensions["examvault_release_handlers"]:
a list of functions(exam_id, plaintext) called after a paper is released).
demo/seed_users.py (8 demo users), demo/make_demo_exam.py (creates keys/<user>_private.pem and _public.pem, keys/examiner_signing*.pem,
and a demo exam), demo/paper_cli.py. Examiner public key path: EXAMINER_PUBLIC_KEY_PATH (default keys/examiner_signing_public.pem).

## 4. Status (updated 2026-10-06)

Also done since: T1 Admin Users pages (list, add user, one-time private key download, disable, revoke modal) and T4 Auditor pages (17-19). 233 tests pass. Tests must never write to the real keys/ folder (conftest.py redirects KEYS_DIR). Signed daily roots are created only for completed UTC days.

Done: Layer 1 (crypto) and the paper service; Layer 4 audit (hash chain, Merkle, daily root, verifier); Layer 2 modules (passwords, TOTP,
rbac, lockout, timewindow); web foundation; login, 2FA, enrol, logout, dashboard; 4.6 share submission and paper release (pages 14-16;
the personal copy download waits for Layer 3).

## 5. Tasks in order (one at a time; the leader says which one to start)

### T1. Admin: Users pages (Frontend Brief pages 6 and 7) - DONE (revoke = disable until T5)
- GET /admin/users: table (username, full name, role badge, status Active/Disabled/Revoked, certificate serial short, 2FA enrolled yes/no,
  last login if available, actions Disable and Revoke), search box, role filter, "Add user" button, empty state "No users yet".
- GET/POST /admin/users/new: full name, username, email, role dropdown (4 roles), temporary password (+ Generate button; check_policy),
  Create. On success show one-time notice and (for invigilators) generate an RSA-3072 keypair: keep only the PUBLIC key
  (save as keys/<username>_public.pem for now), offer the private key ONCE as a download, never store it. Hash the password with Argon2.
- POST /admin/users/<id>/disable (is_active=0). Revoke is T8 (needs PKI); until then Revoke only disables and logs.
- Role: admin only (`@role_required("admin")`). Every action audited. Confirm modal for Revoke (Bootstrap modal, no inline JS).

### T2. Examiner: Upload, My exams, Exam detail (pages 10, 11, 12)
- POST /examiner/upload: exam title, subject, window start/end (UTC, validate end > start), paper file (.txt template, max 10 MB),
  holders = invigilator checkboxes (at least 2). Uses paper_service.create_exam and exam_store.register_shares, signs with the examiner's
  Ed25519 key (keys/examiner_signing.pem for the demo). Show a success card: exam id, paper hash prefix, "Signature: valid", threshold,
  shares issued, window. ASK THE LEADER before adding k/n fields: create_exam has no k/n parameters, the threshold is decided inside it.
  Show the threshold it returns instead.
- GET /examiner/exams (table: exam id/title, window, status badge Encrypted/Window open/Released/Closed, shares submitted x of threshold)
  and GET /examiner/exams/<id> (info card, holders table with submitted yes/no, copies table, recent audit events, link to Leak Analyzer).
- The exam title and subject need a place to live: ask the leader (the plan's `exams` table is not used because paper_service owns `exams`).

### T3. Layer 3 leak tracing (Plan Section 5), as pure modules first, in this order
1. tracing/template.py: parse the examiner's text template. Slots are written `{Option A|Option B}`; every other character is fixed text.
   Functions: parse_template(text) -> (segments, slot_count) and render(segments, bits) -> str. Reject empty options and nested braces.
   Every option of a slot must read correctly in any combination with other slots (same meaning, numbers and marks). Minimum 40 binary slots
   recommended for the demo paper (15 questions x 2 to 3 slots).
2. tracing/codes.py: unique bit patterns per invigilator with a minimum pairwise Hamming distance (single leaker, Phase A).
3. tracing/tardos.py (Phase B): per exam a secret bias vector p_i = sin^2(r), r uniform in [t, pi/2 - t], t = 1/(300*c) (c = expected colluders);
   codeword bit x_i = 1 with probability p_i. Accusation score for suspect j with leaked word y: for each slot, if y_i = 1 add
   sqrt((1-p_i)/p_i) when x_ji = 1 and subtract sqrt(p_i/(1-p_i)) when x_ji = 0; if y_i = 0 add sqrt(p_i/(1-p_i)) when x_ji = 0 and subtract
   sqrt((1-p_i)/p_i) when x_ji = 1. Store the bias vector encrypted (crypto.aes_gcm, key from .env, aad = exam id) in table tardos_params.
   Choose the accusation threshold by simulation (measured false-accusation rate), not by theory.
4. tracing/copygen.py: for each holder of the exam build the personal copy from the template and that holder's codeword; save the bit
   pattern in table `copies` (slot_pattern, file_path); render a PDF (reportlab) or text; store the file ENCRYPTED with crypto.aes_gcm
   (aad = exam id + user id). Register it as a release handler in app.extensions["examvault_release_handlers"] so copies are made at release.
   The decrypted paper is never written to disk.
5. Page 16 download: /invigilator/copy/<exam_id>/download streams the invigilator's OWN copy (decrypt in memory), logs "copy_downloaded".
6. tracing/analyzer.py: input leaked text (paste, PDF via pdfplumber, optional photo OCR with pytesseract). Normalise (lowercase, collapse
   spaces, strip punctuation), fuzzy-match each slot with difflib.SequenceMatcher (ratio >= 0.8, otherwise the slot is an erasure and is
   skipped), build the leaked word, score every holder, return a ranked list with score, matched slots and a confidence label
   (High/Medium/Low from the simulated thresholds). Always show: "Score is evidence, not proof."
7. tracing/simulate.py: 1000 trials each; n = 10 holders; 1 to 4 colluders; attacks: majority, minority, random, interleaving;
   matplotlib graphs to docs/ (detection rate vs colluders, vs slot count (20, 40, 60, 80), false accusation vs threshold).
8. Page 13 Variants review (/examiner/variants) and page 20 Leak Analyzer (/tracing/analyze, roles examiner and auditor).
Honest claim to keep in comments and report: with about 10 invigilators, 40 to 60 slots and 2 colluders, at least one colluder is accused
with a measured rate. Optional later: tracing/zerowidth.py, tracing/lsb.py (document that they do not survive printing).

### T4. Auditor pages (17, 18, 19) - DONE
- /auditor/log: filters (date range, actor, action, severity), search, table (entry number, UTC time, actor, action, details short, hash
  prefix), pagination, "Verify log now", Export CSV; critical rows highlighted.
- /auditor/verify: run audit.verifier.verify_full_chain; big green "Log intact. N entries checked" or red "TAMPERED: entry #<first_broken_index>
  was altered" with the reason lists and a checks table; show who ran it and when.
- /auditor/roots: table of daily signed Merkle roots with Verify and "Generate today's root" (compute_daily_root).

### T5. Certificates and revocation (Plan 6.5, 6.6) and rotation page (page 8)
- crypto/pki.py: self-signed root CA (keys/ca_private.pem), issue_certificate(username, role, public_key) (CN=username, OU=role, 1 year),
  verify_certificate (chain, dates, CRL), revoke(serial, reason) with a signed CRL (cryptography x509 CertificateRevocationListBuilder, next_update).
- Wire the CRL check into login, share submission and copy download. Revoking a user disables the account, writes an audit entry and adds
  a rotation to-do. Rotation page uses crypto/rotation.py. ASK THE LEADER: plan 3.7 says k holders approve a rotation, plan 4.3 says rotation
  is admin only.

### T6. Layer 5 demos
- demo/ecb_vs_gcm.py and /demo/ecb (page 22): Pillow image, AES-ECB (demonstration only, label it insecure) vs AES-GCM side by side, plus the one-byte tamper test
  (GCM rejects, ECB silently accepts).
- demo/honeytoken.py and /files (page 21): a decoy file (for example FINAL_Exam_Paper_ANSWERS.pdf) that looks exactly like other rows.
  Any access: CRITICAL audit entry, honeytoken_events row, red alert on Admin and Auditor dashboards, optional SMTP email (.env), suspend
  the account pending admin review. Admin alerts page (page 9).
- demo/redteam.py: 14 automated attacks against a fresh test database, PASS/FAIL table, exit code 1 if any attack succeeds, writes
  docs/redteam_report.md: A1 lone insider with 1 or k-1 shares cannot decrypt; A2 edited audit entry is named by the verifier; A3 deleted or
  reordered entry detected; A4 replayed share nonce refused; A5 replayed Schnorr proof refused; A6 flipped ciphertext byte raises InvalidTag;
  A7 share before the window refused and logged; A8 revoked ex-employee refused after revocation and rotation; A9 forged paper signature
  fails; A10 brute-force login triggers rate limit and lockout; A11 reused TOTP code refused; A12 decoy file access alerts; A13 two colluding
  invigilators mixing copies get accused by the analyzer; A14 a modified share is rejected by Feldman.

### T7. Schnorr proof of key possession (Plan 4.7)
Same group as Feldman. Registration y = g^x mod p (users.schnorr_public_y). Non-interactive proof: r random, t = g^r, c = SHA-256(g, y, t, server_nonce,
timestamp) mod q, s = (r + c*x) mod q; server checks g^s == t * y^c mod p. Use the existing one-time nonce of the submit page.
Honest wording: a demonstration of proof of key possession alongside HTTPS and TOTP, not a replacement. ASK THE LEADER where the proof is
produced (a small local command the invigilator runs with the nonce) before building.

### T8. Remaining pages and hardening (Plan Section 8)
Profile page (optional), error pages, upload limits, security headers check, the end-to-end demo script (Plan Section 9), README with setup steps,
final `pytest` run. Last: time-lock puzzle (Plan 4.8) only if time remains.

## 6. Known gaps and decisions to raise with the leader (do not decide silently)

1. share_flow keeps verified submissions (wrapped blob + the holder's RSA private key) in server MEMORY until release or window end. The plan says
   keys are not stored. Improvement to propose: keep only the unwrapped, Feldman-verified share in memory and add a new release function that
   takes shares instead of keys (new file, do not edit paper_service). Ask first.
2. Extra table `exam_release` (not in the plan) remembers that a paper was released (only the SHA-256).
3. create_exam has no k/n parameters (see T2). Plan 3.7 vs 4.3 rotation approval (see T5).
4. First-login 2FA enrolment: whoever knows the initial password could enrol first. Document in the report.
5. Demo keys for all users live in keys/ for convenience. A real deployment keeps each private key on the holder's own device.

## 7. Team context (non-coding work, for your explanations only)

Two non-coder members work in Google Drive: Member 1 writes the question templates (`{A|B}` slots, 15 questions, 40+ slots);
Member 2 keeps the bug list, test checklist, report and slides. Nobody except the leader touches the repository.

## 8. Report limitations to keep honest (not features)

Screen photography and full paraphrasing defeat the fingerprints; a compromised server at release time sees the paper in memory; SQLite triggers
can be dropped by someone with the database file (the hash chain and signed Merkle roots detect it, copy roots outside the server); the audit
signing key lives on the server; zero-width and LSB marks do not survive printing; the server clock is trusted for the time window.
