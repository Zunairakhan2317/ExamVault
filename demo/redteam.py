"""Red-team script (plan 7.3): ExamVault attacks itself, 14 ways, on a brand-new test database.

Run from the project folder:   python demo/redteam.py      (or: python -m demo.redteam)

Every attack prints what it tried, what the system did and PASS (the attack was caught) or FAIL (it was not).
The script exits with a non-zero code if any attack succeeded and writes docs/redteam_report.md.

Nothing touches your real data: a temporary folder holds the test database, the test keys and the test CA.
Each attack also runs a CONTROL step first (for example "k real shares DO open the paper"), so a PASS can never
come from the attack simply being set up wrongly.
"""
from __future__ import annotations

import argparse
import json
import random
import secrets
import sqlite3
import sys
import tempfile
from contextlib import closing
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:  # allow "python demo/redteam.py" as well as "python -m demo.redteam"
    sys.path.insert(0, str(ROOT))

from cryptography.exceptions import InvalidTag  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa  # noqa: E402

from audit.daily_root import compute_daily_root, configure_audit_signing_keys  # noqa: E402
from audit.hashchain import add_audit_entry  # noqa: E402
from audit.verifier import verify_full_chain  # noqa: E402
from auth import lockout, schnorr, totp  # noqa: E402
from crypto import feldman, keywrap, pki  # noqa: E402
from crypto.aes_gcm import decrypt  # noqa: E402
from crypto.kdf import derive_aes_key  # noqa: E402
from crypto.services import paper_service  # noqa: E402
from crypto.shamir import combine  # noqa: E402
from demo import honeytoken  # noqa: E402
from tracing.analyzer import analyze_leak_report  # noqa: E402
from web import copy_service, exam_store, rotation_flow, share_flow  # noqa: E402
from web.db import get_connection, init_db  # noqa: E402

PAPER = b"Q1. Explain the CIA triad. [5 marks]\nQ2. Define a nonce. [5 marks]\n"
HOLDERS = ["inv1", "inv2", "inv3", "inv4", "inv5"]
THRESHOLD = 3
DEFAULT_TRIALS = 1000  # A13 is statistical: many trials keep a PASS/FAIL verdict stable
A13_TARGET = 0.80  # plan success criterion 4: at least one colluder accused in 80 % or more of the trials

# A realistic 45-question paper: the SAME verbs repeat, so slots can only be told apart by their position.
_VERBS = [("Explain", "Describe"), ("Define", "State"), ("List", "Name"), ("Compare", "Contrast"),
          ("Write", "Give"), ("Discuss", "Outline"), ("Identify", "Specify"), ("Summarise", "Review")]
_TOPICS = ["encryption", "hashing", "firewalls", "VPNs", "phishing", "malware", "backups", "patching", "logging", "MFA",
           "PKI", "TLS", "ransomware", "sandboxing", "IDS", "SIEM", "zero trust", "VLANs", "DNS security", "key rotation",
           "salting", "padding", "nonce reuse", "side channels", "XSS", "CSRF", "SQL injection", "buffer overflow", "DoS",
           "social engineering", "least privilege", "audit trails", "incident response", "risk analysis", "threat models",
           "access control", "biometrics", "smart cards", "digital signatures", "secret sharing", "onion routing",
           "steganography", "forensics", "honeypots", "patch cycles"]
LEAK_TEMPLATE = "\n".join(
    f"Q{i}. {{{_VERBS[i % 8][0]}|{_VERBS[i % 8][1]}}} the role of {topic} in a secure system. [5 marks]"
    for i, topic in enumerate(_TOPICS, start=1)
) + "\n"


@dataclass
class Result:
    code: str
    title: str
    tried: str
    system: str
    passed: bool


class Lab:
    """A throw-away ExamVault: temporary database, keys, CA, five holders and an examiner signing key."""

    def __init__(self, folder: Path, trials: int) -> None:
        self.folder, self.trials = folder, trials
        self.keys_dir = folder / "keys"
        self.keys_dir.mkdir()
        paper_service.DATABASE_PATH = folder / "paper.db"  # the exam records live here, not in data/
        pki.KEYS_DIR = self.keys_dir
        pki.CA_PRIVATE_KEY_PATH = self.keys_dir / "ca_private.pem"
        pki.CA_CERT_PATH = self.keys_dir / "ca_cert.pem"
        pki.CRL_PATH = self.keys_dir / "crl.pem"
        self.conn = get_connection(folder / "web.db")
        init_db(self.conn)
        audit_key = ed25519.Ed25519PrivateKey.generate()
        configure_audit_signing_keys(audit_key, audit_key.public_key())
        self.signer = ed25519.Ed25519PrivateKey.generate()
        self.rsa = {name: rsa.generate_private_key(public_exponent=65537, key_size=3072) for name in HOLDERS}
        self.ids: dict[str, int] = {}
        for name in ["admin1", *HOLDERS]:
            role = "admin" if name == "admin1" else "invigilator"
            self.ids[name] = self.conn.execute(
                "INSERT INTO users (username, role, password_hash) VALUES (?, ?, 'x')", (name, role)
            ).lastrowid
        self.conn.commit()
        for name, key in self.rsa.items():
            (self.keys_dir / f"{name}_public.pem").write_bytes(
                key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            )
        self.results: dict[str, dict[str, Any]] = {}

    def new_exam(self, opens_in_minutes: int = -1) -> str:
        """A 3-of-5 exam. opens_in_minutes < 0: the window is open now; > 0: it opens later."""
        now = datetime.now(timezone.utc)
        start = now + timedelta(minutes=opens_in_minutes)
        result = paper_service.create_exam(
            PAPER, [self.rsa[n].public_key() for n in HOLDERS], self.signer, start, start + timedelta(hours=1),
            threshold=THRESHOLD,
        )
        exam_store.register_shares(
            self.conn, result["exam_id"], result["commitments"], [self.ids[n] for n in HOLDERS], result["wrapped_shares"]
        )
        self.results[result["exam_id"]] = result
        return result["exam_id"]

    def key_pem(self, name: str) -> bytes:
        return self.rsa[name].private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
        )

    def points(self, exam_id: str, names: list[str]) -> list[tuple[int, int]]:
        """The share points of these holders (what an insider who holds them would have)."""
        wrapped = self.results[exam_id]["wrapped_shares"]
        return [
            paper_service._decode_share(keywrap.unwrap_share(wrapped[HOLDERS.index(n)], self.rsa[n])) for n in names
        ]

    def stored(self, exam_id: str) -> tuple[bytes, bytes]:
        """(nonce, ciphertext) exactly as stored in the database."""
        with closing(paper_service._connect_database()) as db:
            nonce, ciphertext = db.execute("SELECT nonce, ciphertext FROM exams WHERE exam_id = ?", (exam_id,)).fetchone()
        return bytes(nonce), bytes(ciphertext)

    def release(self, exam_id: str, names: list[str], public_key: Any = None) -> bytes:
        wrapped = self.results[exam_id]["wrapped_shares"]
        return paper_service.release_exam(
            exam_id, [wrapped[HOLDERS.index(n)] for n in names], [self.rsa[n] for n in names],
            public_key or self.signer.public_key(),
        )

    def submit(self, exam_id: str, name: str, nonce: str, pending: share_flow.PendingShares, now: Any = None) -> dict[str, Any]:
        return share_flow.submit_share(
            self.conn, pending, exam_id=exam_id, user_id=self.ids[name], username=name, key_pem=self.key_pem(name),
            nonce=nonce, load_admin_public_key=lambda: self.signer.public_key(), now=now,
        )

    def audit_count(self, event_type: str, needle: str = "") -> int:
        return self.conn.execute(
            "SELECT COUNT(*) FROM audit_entries WHERE event_type = ? AND details LIKE ?", (event_type, f"%{needle}%")
        ).fetchone()[0]


def _expect(exc_types: tuple[type[BaseException], ...], call: Callable[[], Any]) -> BaseException | None:
    """Run `call`; return the exception it raised if it is one of exc_types, else None (the attack worked)."""
    try:
        call()
    except exc_types as error:
        return error
    return None


# ------------------------------------------------------------------------------------------ the 14 attacks

def a1_lone_insider(lab: Lab) -> tuple[str, str, bool]:
    exam = lab.new_exam()
    nonce, ciphertext = lab.stored(exam)
    aad = exam.encode()
    opened = decrypt(nonce, ciphertext, derive_aes_key(combine(lab.points(exam, HOLDERS[:THRESHOLD]), feldman.Q)), aad)
    control_ok = opened == PAPER  # control: k real shares DO open the paper
    one, two = lab.points(exam, HOLDERS[:1]), lab.points(exam, HOLDERS[:THRESHOLD - 1])
    to_256_bits = lambda value: value % (1 << 256)  # the attacker must feed HKDF a 256-bit secret  # noqa: E731
    guesses = [derive_aes_key(to_256_bits(one[0][1])), derive_aes_key(to_256_bits(combine(two, feldman.Q)))]
    failed = [_expect((InvalidTag,), lambda g=g: decrypt(nonce, ciphertext, g, aad)) is not None for g in guesses]
    refused = _expect((ValueError,), lambda: lab.release(exam, HOLDERS[:THRESHOLD - 1])) is not None
    return (f"An insider holds 1 share, then k-1 = {THRESHOLD - 1} shares, and tries to rebuild the key and decrypt.",
            f"Control: {THRESHOLD} shares open the paper. With 1 share and with {THRESHOLD - 1} shares the guessed key "
            f"is wrong (GCM refuses: InvalidTag) and the server refuses to release.", control_ok and all(failed) and refused)


def _signed_chain(entries: int = 6) -> sqlite3.Connection:
    db = sqlite3.connect(":memory:")
    for number in range(entries):
        add_audit_entry(db, "login", f"entry {number}", f"user{number}")
    compute_daily_root(db, date.today().isoformat())
    return db


def a2_edit_audit_entry(lab: Lab) -> tuple[str, str, bool]:
    db = _signed_chain()
    green = verify_full_chain(db)["status"] == "green"  # control: the untouched log is green
    db.execute("DROP TRIGGER audit_entries_no_update")  # the attacker has database access and removes the guard
    db.execute("UPDATE audit_entries SET details = 'nothing happened' WHERE id = 3")
    report = verify_full_chain(db)
    named = report["altered_entry_indices"] == [3] and report["status"] == "red"
    return ("An attacker with database access removes the no-update trigger and rewrites old audit entry #3.",
            f"Control: untouched log = green. After the edit the verifier says red: TAMPERED, entry #{report['first_broken_index']} "
            "hash mismatch.", green and named)


def a3_delete_or_reorder_audit_entry(lab: Lab) -> tuple[str, str, bool]:
    deleted = _signed_chain()
    deleted.execute("DROP TRIGGER audit_entries_no_delete")
    deleted.execute("DELETE FROM audit_entries WHERE id = 3")
    report_del = verify_full_chain(deleted)
    reordered = _signed_chain()
    reordered.execute("DROP TRIGGER audit_entries_no_update")
    reordered.execute("UPDATE audit_entries SET id = 99 WHERE id = 3")
    reordered.execute("UPDATE audit_entries SET id = 3 WHERE id = 4")
    reordered.execute("UPDATE audit_entries SET id = 4 WHERE id = 99")
    report_re = verify_full_chain(reordered)
    caught = report_del["status"] == "red" and report_re["status"] == "red"
    return ("An attacker deletes entry #3, and in a second copy swaps entries #3 and #4.",
            f"Deleted entry: red (first broken #{report_del['first_broken_index']}, missing "
            f"{report_del['missing_entry_indices']}). Reordered entries: red (first broken #{report_re['first_broken_index']}).",
            caught)


def a4_replay_share_nonce(lab: Lab) -> tuple[str, str, bool]:
    exam = lab.new_exam()
    pending = share_flow.PendingShares()
    first = lab.submit(exam, "inv1", "nonce-captured-by-attacker", pending)  # control: the real submission works
    refusal = _expect((share_flow.ShareRefused,), lambda: lab.submit(exam, "inv2", "nonce-captured-by-attacker", pending))
    reused = refusal is not None and refusal.reason == "nonce_reuse"  # type: ignore[union-attr]
    return ("The attacker replays a captured share-submission request (same one-time nonce).",
            f"Control: the first submission is accepted ({first['received']} of {first['needed']}). The replay is refused "
            f"as {getattr(refusal, 'reason', 'NOT refused')} and no extra share was counted ({pending.count(exam)}).",
            first["outcome"] == "accepted" and reused and pending.count(exam) == 1)


def a5_replay_schnorr_proof(lab: Lab) -> tuple[str, str, bool]:
    x, y = schnorr.generate_schnorr_keypair()
    t, s = schnorr.generate_schnorr_proof(x, y, "server-nonce-1", "1700000000")
    valid = schnorr.verify_schnorr_proof(y, t, s, "server-nonce-1", "1700000000")  # control
    replayed = schnorr.verify_schnorr_proof(y, t, s, "server-nonce-2", "1700000000")  # old proof, new nonce
    other_x, _ = schnorr.generate_schnorr_keypair()
    t2, s2 = schnorr.generate_schnorr_proof(other_x, y, "server-nonce-3", "1700000000")  # proof made without the secret
    forged = schnorr.verify_schnorr_proof(y, t2, s2, "server-nonce-3", "1700000000")
    return ("The attacker replays an old Schnorr proof against a new server nonce, and tries a proof made without the secret.",
            f"Control: a fresh valid proof is accepted ({valid}). The replayed proof is accepted: {replayed}. "
            f"A proof without the secret is accepted: {forged}. (Schnorr is a documented extension, tested at module level.)",
            valid and not replayed and not forged)


def a6_flip_ciphertext_byte(lab: Lab) -> tuple[str, str, bool]:
    exam = lab.new_exam()
    nonce, ciphertext = lab.stored(exam)
    key = derive_aes_key(combine(lab.points(exam, HOLDERS[:THRESHOLD]), feldman.Q))
    tampered = bytearray(ciphertext)
    tampered[len(tampered) // 2] ^= 0x01
    gcm_refuses = _expect((InvalidTag,), lambda: decrypt(nonce, bytes(tampered), key, exam.encode())) is not None
    with closing(paper_service._connect_database()) as db, db:
        db.execute("UPDATE exams SET ciphertext = ? WHERE exam_id = ?", (bytes(tampered), exam))
    release_refused = _expect((ValueError,), lambda: lab.release(exam, HOLDERS[:THRESHOLD])) is not None
    return ("The attacker flips one bit of the stored encrypted paper.",
            "AES-GCM raises InvalidTag when the correct key is used on the altered ciphertext, and the server refuses to "
            "release the damaged paper.", gcm_refuses and release_refused)


def a7_submit_before_window(lab: Lab) -> tuple[str, str, bool]:
    exam = lab.new_exam(opens_in_minutes=10)
    refusal = _expect((share_flow.ShareRefused,), lambda: lab.submit(exam, "inv1", "early-nonce", share_flow.PendingShares()))
    logged = lab.audit_count("share_refused", "window_before") >= 1
    return ("A real holder submits their share 10 minutes before the exam window opens.",
            f"Refused as {getattr(refusal, 'reason', 'NOT refused')}; the refusal is in the audit log: {logged}.",
            refusal is not None and refusal.reason == "window_before" and logged)  # type: ignore[union-attr]


def a8_revoked_employee(lab: Lab) -> tuple[str, str, bool]:
    exam = lab.new_exam()
    leaver = "inv5"
    old_blobs = list(lab.results[exam]["wrapped_shares"])
    serial, pem = pki.issue_certificate(leaver, "invigilator", lab.rsa[leaver].public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    lab.conn.execute("INSERT INTO certificates (serial, user_id, pem, issued_at) VALUES (?, ?, ?, ?)",
                     (serial, lab.ids[leaver], pem, datetime.now(timezone.utc).isoformat()))
    lab.conn.commit()
    control = pki.user_certificate_ok(lab.conn, lab.ids[leaver])  # control: valid before revocation
    pki.revoke(lab.conn, serial, "Left job", actor="admin1")
    lab.conn.execute("UPDATE users SET is_active = 0 WHERE id = ?", (lab.ids[leaver],))
    lab.conn.commit()
    login_blocked = not pki.user_certificate_ok(lab.conn, lab.ids[leaver])  # the check the login page makes
    submit_refusal = _expect((share_flow.ShareRefused,), lambda: lab.submit(exam, leaver, "leaver-nonce", share_flow.PendingShares()))
    # the remaining holders rotate the shares (ceremony), re-keying the paper
    ceremonies, pending = rotation_flow.RotationCeremonies(), share_flow.PendingShares()
    rotation_flow.start_ceremony(lab.conn, ceremonies, exam_id=exam, admin_username="admin1", keys_dir=lab.keys_dir,
                                 extra_holder_ids=[], new_threshold=None)
    outcome: dict[str, Any] = {}
    for name in HOLDERS[:THRESHOLD]:
        outcome = rotation_flow.approve(lab.conn, ceremonies, pending, exam_id=exam, user_id=lab.ids[name], username=name,
                                        key_pem=lab.key_pem(name), keys_dir=lab.keys_dir, load_signing_key=lambda: lab.signer)
    old_share_dead = _expect((ValueError,), lambda: paper_service.release_exam(
        exam, [old_blobs[4], old_blobs[0], old_blobs[1]], [lab.rsa[leaver], lab.rsa["inv1"], lab.rsa["inv2"]],
        lab.signer.public_key())) is not None
    holds_nothing = exam_store.get_share_row(lab.conn, exam, lab.ids[leaver]) is None
    return ("A revoked ex-employee tries to log in and to submit their old share, before and after share rotation.",
            f"Control: certificate valid before revocation ({control}). After revocation: login blocked ({login_blocked}), "
            f"submission refused as {getattr(submit_refusal, 'reason', 'NOT refused')}. After rotation "
            f"(generation {outcome.get('generation')}): the old share plus two old shares cannot release the paper "
            f"({old_share_dead}) and the leaver holds no current share ({holds_nothing}).",
            control and login_blocked and submit_refusal is not None and submit_refusal.reason == "revoked_certificate"  # type: ignore[union-attr]
            and outcome.get("outcome") == "rotated" and old_share_dead and holds_nothing)


def a9_forged_signature(lab: Lab) -> tuple[str, str, bool]:
    exam = lab.new_exam()
    control = lab.release(exam, HOLDERS[:THRESHOLD]) == PAPER  # control: the real signature releases the paper
    attacker = ed25519.Ed25519PrivateKey.generate()
    wrong_key = _expect((ValueError,), lambda: lab.release(exam, HOLDERS[:THRESHOLD], attacker.public_key())) is not None
    with closing(paper_service._connect_database()) as db, db:
        db.execute("UPDATE exams SET paper_hash = ? WHERE exam_id = ?", (secrets.token_bytes(32), exam))
    edited = _expect((ValueError,), lambda: lab.release(exam, HOLDERS[:THRESHOLD])) is not None
    return ("The attacker presents the exam under a signature from the wrong key, and edits the paper's recorded hash.",
            f"Control: the genuine examiner key releases the paper ({control}). Wrong signing key: refused ({wrong_key}). "
            f"Edited record: refused ({edited}).", control and wrong_key and edited)


def a10_brute_force_login(lab: Lab) -> tuple[str, str, bool]:
    db = sqlite3.connect(":memory:")
    now = 1_800_000_000.0
    states = [lockout.record_failure(db, "victim", "203.0.113.9", now=now + i) for i in range(lockout.get_threshold())]
    locked = states[-1]["locked"] and lockout.is_locked(db, "victim", now=now + 10)[0]
    correct_password_refused = _expect((lockout.AccountLockedError,), lambda: lockout.record_success(db, "victim", "203.0.113.9", now=now + 11)) is not None
    return ("The attacker guesses passwords for one account, then (still locked out) tries the correct password.",
            f"Account locked after {lockout.get_threshold()} failures ({locked}) for {lockout.get_lockout_seconds() // 60} "
            f"minutes; even the correct password is refused during lockout ({correct_password_refused}). "
            f"Per-IP limit on the login page: {lockout.LOGIN_RATE_LIMIT}.", bool(locked) and correct_password_refused)


def a11_reuse_totp_code(lab: Lab) -> tuple[str, str, bool]:
    import pyotp

    secret = totp.new_secret()
    code = pyotp.TOTP(secret).now()
    accepted, step = totp.verify_code(secret, code, None)  # control: the first use works
    replay, _ = totp.verify_code(secret, code, step)
    return ("The attacker captures a valid TOTP code and uses it again.",
            f"Control: first use accepted ({accepted}). The same code a second time is accepted: {replay}.", accepted and not replay)


def a12_open_honeytoken(lab: Lab) -> tuple[str, str, bool]:
    before = lab.audit_count(honeytoken.HONEYTOKEN_ACTION)
    result = honeytoken.record_hit(lab.conn, lab.ids["inv2"], "inv2", "invigilator", "198.51.100.7")
    events = lab.conn.execute("SELECT COUNT(*) FROM honeytoken_events").fetchone()[0]
    suspended = lab.conn.execute("SELECT is_active FROM users WHERE username = 'inv2'").fetchone()[0] == 0
    audited = lab.audit_count(honeytoken.HONEYTOKEN_ACTION, "CRITICAL") == before + 1
    return (f"A snooping invigilator opens the decoy file {honeytoken.DECOY_FILENAME}.",
            f"Alert row created ({events} event), CRITICAL audit entry written ({audited}), account suspended "
            f"({suspended and result['suspended']}).", events >= 1 and audited and suspended)


def a13_mixed_copies(lab: Lab) -> tuple[str, str, bool]:
    slots = copy_service.parse_template(LEAK_TEMPLATE)
    rng, accused, top_hits, trials = random.Random(), 0, 0, lab.trials
    names = [f"inv{i}" for i in range(10)]
    for _ in range(trials):
        biases = copy_service.new_bias_vector(len(slots))
        words = copy_service.assign_codewords(10, biases)
        codes = [[int(bit) for bit in word] for word in words]
        pair = rng.sample(range(10), 2)
        leaked = "".join(
            words[pair[0]][k] if words[pair[0]][k] == words[pair[1]][k] else rng.choice([words[pair[0]][k], words[pair[1]][k]])
            for k in range(len(slots))
        )
        report = analyze_leak_report(copy_service.assemble_copy_text(LEAK_TEMPLATE, leaked), slots, names, codes, biases)
        colluders = {names[i] for i in pair}
        accused += any(r["username"] in colluders and r["confidence"] != "Low" for r in report["results"])
        top_hits += report["results"][0]["username"] in colluders
    rate = accused / trials
    lab.a13_rate = rate  # type: ignore[attr-defined]
    return (f"Two of 10 invigilators mix their copies of a {len(slots)}-slot paper (random pick where they differ) and leak "
            f"the result; repeated {trials} times.",
            f"The analyzer accused at least one colluder (confidence Medium or High) in {rate:.1%} of the trials "
            f"(target {A13_TARGET:.0%}); the top-ranked suspect was a colluder in {top_hits / trials:.1%}. "
            "The score is evidence, not proof.", rate >= A13_TARGET)


def a14_modified_share(lab: Lab) -> tuple[str, str, bool]:
    exam = lab.new_exam()
    commitments = lab.results[exam]["commitments"]
    (x1, y1), (x2, _) = lab.points(exam, ["inv1"])[0], lab.points(exam, ["inv2"])[0]
    honest = feldman.verify_share(x1, y1, commitments)  # control
    modified = feldman.verify_share(x1, (y1 + 1) % feldman.Q, commitments)
    wrong_index = feldman.verify_share(x2, y1, commitments)
    return ("The attacker submits a share whose value was changed by one, and a share paired with another holder's index.",
            f"Control: the honest share verifies ({honest}). Modified value verifies: {modified}. Wrong index verifies: {wrong_index}.",
            honest and not modified and not wrong_index)


ATTACKS: list[tuple[str, str, Callable[[Lab], tuple[str, str, bool]]]] = [
    ("A1", "Lone insider holds 1 (then k-1) shares and tries to decrypt", a1_lone_insider),
    ("A2", "Attacker edits an old audit entry", a2_edit_audit_entry),
    ("A3", "Attacker deletes or reorders an audit entry", a3_delete_or_reorder_audit_entry),
    ("A4", "Replay an old share-submission nonce", a4_replay_share_nonce),
    ("A5", "Replay an old Schnorr proof", a5_replay_schnorr_proof),
    ("A6", "Flip one byte of the encrypted paper", a6_flip_ciphertext_byte),
    ("A7", "Submit a share before the exam window opens", a7_submit_before_window),
    ("A8", "Revoked ex-employee tries to log in or submit an old share", a8_revoked_employee),
    ("A9", "Forge or edit the paper with a wrong signature", a9_forged_signature),
    ("A10", "Brute-force the login", a10_brute_force_login),
    ("A11", "Reuse a TOTP code", a11_reuse_totp_code),
    ("A12", "Open the honeytoken file", a12_open_honeytoken),
    ("A13", "Two invigilators mix their copies and leak the result", a13_mixed_copies),
    ("A14", "Submit a share with a modified value", a14_modified_share),
]


def run_all(trials: int = DEFAULT_TRIALS) -> list[Result]:
    """Build the lab, run the 14 attacks in order and return their results (an error counts as FAIL)."""
    results: list[Result] = []
    # The lab points these module settings at a temporary folder. Put them back afterwards, otherwise
    # a later test (or any code in the same process) would write into a folder that no longer exists.
    saved = {
        (pki, "KEYS_DIR"): pki.KEYS_DIR,
        (pki, "CA_PRIVATE_KEY_PATH"): pki.CA_PRIVATE_KEY_PATH,
        (pki, "CA_CERT_PATH"): pki.CA_CERT_PATH,
        (pki, "CRL_PATH"): pki.CRL_PATH,
        (paper_service, "DATABASE_PATH"): paper_service.DATABASE_PATH,
    }
    try:
        with tempfile.TemporaryDirectory(prefix="examvault_redteam_") as folder:
            lab = Lab(Path(folder), trials)
            try:
                for code, title, attack in ATTACKS:
                    try:
                        tried, system, caught = attack(lab)
                    except Exception as error:  # an unexpected crash is never reported as "caught"
                        tried, system, caught = "(the attack could not be carried out)", f"{type(error).__name__}: {error}", False
                    results.append(Result(code, title, tried, system, bool(caught)))
            finally:
                lab.conn.close()
    finally:
        for (module, name), value in saved.items():
            setattr(module, name, value)
    return results


def format_table(results: list[Result]) -> str:
    lines = []
    for r in results:
        lines += [f"[{'PASS' if r.passed else 'FAIL'}] {r.code}  {r.title}", f"        tried : {r.tried}", f"        system: {r.system}"]
    caught = sum(r.passed for r in results)
    lines.append(f"\n{caught} of {len(results)} attacks caught." + ("" if caught == len(results) else "  SOME ATTACKS SUCCEEDED."))
    return "\n".join(lines)


def write_report(results: list[Result], path: Path) -> None:
    caught = sum(r.passed for r in results)
    rows = "\n".join(
        f"| {r.code} | {r.title} | {r.tried} | {r.system} | {'PASS (caught)' if r.passed else '**FAIL (not caught)**'} |"
        for r in results
    ).replace("\n|", "\n|")
    text = (
        "# ExamVault red-team report\n\n"
        f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} by `python demo/redteam.py` on a fresh test "
        "database (temporary keys, temporary CA).\n\n"
        f"**Result: {caught} of {len(results)} attacks caught.**\n\n"
        "| # | Attack | What was tried | What the system did | Result |\n|---|---|---|---|---|\n"
        f"{rows}\n\n"
        "## Honest notes\n\n"
        "- Each attack first runs a control step (for example that k real shares do open the paper), so a PASS cannot come "
        "from a wrongly built attack.\n"
        "- A13 is statistical: the accusation score is evidence, not proof, and detection of at least one colluder is "
        "measured, not guaranteed.\n"
        "- A10 checks the account lockout; the per-IP limit of the login page is covered by the Flask-Limiter tests.\n"
        "- The demo keeps private keys on disk and trusts the server clock; see the report's limitations section.\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ExamVault red-team: 14 attacks against a fresh test database.")
    parser.add_argument("--report", default=str(ROOT / "docs" / "redteam_report.md"), help="where to write the report")
    parser.add_argument("--trials", type=int, default=DEFAULT_TRIALS, help="trials for the statistical attack A13")
    args = parser.parse_args(argv)
    results = run_all(args.trials)
    print(format_table(results))
    write_report(results, Path(args.report))
    print(f"\nReport written to {args.report}")
    return 0 if all(r.passed for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
