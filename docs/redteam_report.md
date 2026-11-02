# ExamVault red-team report

Generated 2026-11-01 08:16 UTC by `python demo/redteam.py` on a fresh test database (temporary keys, temporary CA).

**Result: 14 of 14 attacks caught.**

| # | Attack | What was tried | What the system did | Result |
|---|---|---|---|---|
| A1 | Lone insider holds 1 (then k-1) shares and tries to decrypt | An insider holds 1 share, then k-1 = 2 shares, and tries to rebuild the key and decrypt. | Control: 3 shares open the paper. With 1 share and with 2 shares the guessed key is wrong (GCM refuses: InvalidTag) and the server refuses to release. | PASS (caught) |
| A2 | Attacker edits an old audit entry | An attacker with database access removes the no-update trigger and rewrites old audit entry #3. | Control: untouched log = green. After the edit the verifier says red: TAMPERED, entry #3 hash mismatch. | PASS (caught) |
| A3 | Attacker deletes or reorders an audit entry | An attacker deletes entry #3, and in a second copy swaps entries #3 and #4. | Deleted entry: red (first broken #3, missing [3]). Reordered entries: red (first broken #3). | PASS (caught) |
| A4 | Replay an old share-submission nonce | The attacker replays a captured share-submission request (same one-time nonce). | Control: the first submission is accepted (1 of 3). The replay is refused as nonce_reuse and no extra share was counted (1). | PASS (caught) |
| A5 | Replay an old Schnorr proof | The attacker replays an old Schnorr proof against a new server nonce, and tries a proof made without the secret. | Control: a fresh valid proof is accepted (True). The replayed proof is accepted: False. A proof without the secret is accepted: False. (Schnorr is a documented extension, tested at module level.) | PASS (caught) |
| A6 | Flip one byte of the encrypted paper | The attacker flips one bit of the stored encrypted paper. | AES-GCM raises InvalidTag when the correct key is used on the altered ciphertext, and the server refuses to release the damaged paper. | PASS (caught) |
| A7 | Submit a share before the exam window opens | A real holder submits their share 10 minutes before the exam window opens. | Refused as window_before; the refusal is in the audit log: True. | PASS (caught) |
| A8 | Revoked ex-employee tries to log in or submit an old share | A revoked ex-employee tries to log in and to submit their old share, before and after share rotation. | Control: certificate valid before revocation (True). After revocation: login blocked (True), submission refused as revoked_certificate. After rotation (generation 2): the old share plus two old shares cannot release the paper (True) and the leaver holds no current share (True). | PASS (caught) |
| A9 | Forge or edit the paper with a wrong signature | The attacker presents the exam under a signature from the wrong key, and edits the paper's recorded hash. | Control: the genuine examiner key releases the paper (True). Wrong signing key: refused (True). Edited record: refused (True). | PASS (caught) |
| A10 | Brute-force the login | The attacker guesses passwords for one account, then (still locked out) tries the correct password. | Account locked after 5 failures (True) for 15 minutes; even the correct password is refused during lockout (True). Per-IP limit on the login page: 5 per minute. | PASS (caught) |
| A11 | Reuse a TOTP code | The attacker captures a valid TOTP code and uses it again. | Control: first use accepted (True). The same code a second time is accepted: False. | PASS (caught) |
| A12 | Open the honeytoken file | A snooping invigilator opens the decoy file FINAL_Exam_Paper_ANSWERS.pdf. | Alert row created (1 event), CRITICAL audit entry written (True), account suspended (True). | PASS (caught) |
| A13 | Two invigilators mix their copies and leak the result | Two of 10 invigilators mix their copies of a 45-slot paper (random pick where they differ) and leak the result; repeated 1000 times. | The analyzer accused at least one colluder (confidence Medium or High) in 84.6% of the trials (target 80%); the top-ranked suspect was a colluder in 95.8%. The score is evidence, not proof. | PASS (caught) |
| A14 | Submit a share with a modified value | The attacker submits a share whose value was changed by one, and a share paired with another holder's index. | Control: the honest share verifies (True). Modified value verifies: False. Wrong index verifies: False. | PASS (caught) |

## Honest notes

- Each attack first runs a control step (for example that k real shares do open the paper), so a PASS cannot come from a wrongly built attack.
- A13 is statistical: the accusation score is evidence, not proof, and detection of at least one colluder is measured, not guaranteed.
- A10 checks the account lockout; the per-IP limit of the login page is covered by the Flask-Limiter tests.
- The demo keeps private keys on disk and trusts the server clock; see the report's limitations section.
