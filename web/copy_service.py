"""Per-invigilator copies built from the examiner's uploaded paper (plan 5.2 to 5.4).

How it works (Frontend Brief pages 10, 13 and 16):
- The examiner writes the paper (PDF or text) with variant slots: ``{first wording | second wording}``.
  The slots are read from the uploaded paper itself, so nobody edits a hard-coded file.
- At upload each holder gets a secret codeword (one bit per slot, Tardos style: a secret bias vector
  decides how likely each bit is 1). The bits are stored in ``copies.slot_pattern``; the bias vector is
  stored encrypted in ``tardos_params``.
- When the paper is released (k shares), the decrypted paper exists only in memory. For every holder the
  chosen wording is put into the paper, a PDF is rendered, and the PDF is stored ENCRYPTED (AES-256-GCM).
  The PDF contains no visible name or ID: the marking is the wording itself.

Security properties:
- The variant wordings are question text, so they are stored only encrypted (AES-256-GCM, key file
  keys/copy_storage.key, AAD binds each blob to its exam and holder). A database or file thief learns
  neither the wordings, the codewords' meaning nor the bias vector.
- Randomness for codewords and the bias vector comes from ``secrets`` (SystemRandom), never ``random``.
- A copy is decrypted only for its own holder, after the release, at download time.

Known limits (state them in the report): only the first two options of a slot are used (binary code); the
PDF uses the standard Latin-1 font, so other scripts are replaced by "?"; the storage key lives on the server.
"""
from __future__ import annotations

import io
import json
import math
import os
import re
import secrets
import sqlite3
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from crypto.aes_gcm import decrypt, encrypt
from tracing.codes import hamming_distance

MIN_SLOTS = 40
MAX_SLOTS = 400
MAX_PDF_PAGES = 200
SLOT_PATTERN = re.compile(r"\{([^{}]*\|[^{}]*)\}")
# A question label at the start of a line: "Q1.", "1.", "2)" or a table row such as "3 {What is | Define} ...".
_QUESTION_LABEL = re.compile(
    r"(?im)^[ \t]*(?:q(?:uestion)?[ \t]*\.?[ \t]*)?(\d+[a-z]?)"
    r"(?:[ \t]*[.):]|[ \t]+(?![ \t]*marks?\b)(?=\{|(?-i:[A-Z])))"
)
_MARKS = re.compile(r"(\d+)\s*marks?", re.IGNORECASE)
_EXAM_ID = re.compile(r"^[0-9a-fA-F-]{8,64}$")
_rng = secrets.SystemRandom()


# ---------- reading the paper ----------

def extract_paper_text(content: bytes) -> str:
    """Text of an uploaded paper: a PDF (recognised by its first bytes) or a UTF-8 text file.

    Raises ValueError when the PDF cannot be read, so the upload page can refuse it politely.
    """
    if not isinstance(content, bytes):
        raise TypeError("content must be bytes")
    if content.startswith(b"%PDF-"):
        try:
            import pdfplumber

            with pdfplumber.open(io.BytesIO(content)) as pdf:
                pages = pdf.pages[:MAX_PDF_PAGES]
                return "\n".join((page.extract_text() or "") for page in pages)
        except Exception as exc:  # corrupt or encrypted PDF
            raise ValueError("The PDF could not be read") from exc
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
        return content.decode("latin-1")


def _slot_matches(text: str) -> list[tuple[re.Match, list[str]]]:
    """Every ``{a | b}`` group with at least two different, non-empty options, in reading order."""
    found = []
    for match in SLOT_PATTERN.finditer(text):
        options = [" ".join(option.split()) for option in match.group(1).split("|")]
        if all(options) and len({option.lower() for option in options}) >= 2:
            found.append((match, options))
    return found


def parse_template(text: str) -> list[dict[str, Any]]:
    """Variant slots found in the paper text (same slot format as tracing/parser.py).

    Each slot: slot_id, question_no, group_index, variants (the first two options), marks (or None).
    """
    slots: list[dict[str, Any]] = []
    last_label_start, in_question = -1, 0
    for match, options in _slot_matches(text):
        labels = list(_QUESTION_LABEL.finditer(text, 0, match.start() + 1))  # +1 so a label right before '{' is seen
        label = labels[-1] if labels else None
        label_start = label.start() if label else -1
        if label_start != last_label_start:
            last_label_start, in_question = label_start, 0
        tail = text[match.end(): match.end() + 1500]
        cut = next((m.start() for m in _QUESTION_LABEL.finditer(tail) if m.start() > 0), len(tail))
        marks = _MARKS.search(tail[:cut])
        slots.append({
            "slot_id": len(slots) + 1,
            "question_no": label.group(1) if label else "-",
            "group_index": in_question,
            "variants": options[:2],
            "marks": int(marks.group(1)) if marks else None,
        })
        in_question += 1
    return slots


def assemble_copy_text(template: str, pattern: str) -> str:
    """The paper with each slot replaced by the option the holder's bit selects ('0' = A, '1' = B)."""
    matches = _slot_matches(template)
    if len(pattern) != len(matches) or set(pattern) - {"0", "1"}:
        raise ValueError("The codeword does not fit this paper")
    parts, last = [], 0
    for (match, options), bit in zip(matches, pattern):
        parts.append(template[last:match.start()])
        parts.append(options[int(bit)])
        last = match.end()
    parts.append(template[last:])
    return "".join(parts)


# ---------- codewords ----------

def new_bias_vector(slot_count: int, colluders: float = 2.0) -> list[float]:
    """Secret bias vector (plan 5.3): p_i = sin^2(r), r uniform in [t, pi/2 - t], t = 1/(300 c)."""
    cutoff = 1.0 / (300.0 * colluders)
    return [
        min(0.99, max(0.01, math.sin(_rng.uniform(cutoff, math.pi / 2.0 - cutoff)) ** 2))
        for _ in range(slot_count)
    ]


def assign_codewords(count: int, biases: list[float]) -> list[str]:
    """One codeword per holder: bit i is 1 with probability p_i, all pairwise different enough.

    The minimum Hamming distance is 1 for short papers and slots//8 for long ones (plan 5.2). If a
    very short paper cannot give every holder a different word, the last candidate is accepted.
    """
    if not biases:
        return ["" for _ in range(count)]
    distance = 1 if len(biases) < 8 else max(1, len(biases) // 8)
    words: list[list[int]] = []
    for _ in range(count):
        candidate: list[int] = []
        for attempt in range(400):
            odds = biases if attempt < 200 else [0.5] * len(biases)  # fall back to fair bits
            candidate = [1 if _rng.random() < p else 0 for p in odds]
            if all(hamming_distance(candidate, other) >= distance for other in words):
                break
        words.append(candidate)
    return ["".join(str(bit) for bit in word) for word in words]


# ---------- encrypted storage ----------

def keys_dir_for(app) -> Path:
    """Folder with the key files (config KEYS_DIR, otherwise the same folder the admin pages use)."""
    configured = app.config.get("KEYS_DIR")
    if configured:
        return Path(configured)
    from web import routes_admin  # imported late: routes import this module

    return Path(routes_admin.KEYS_DIR)


def data_dir_for(app) -> Path:
    """Folder that holds the database; encrypted variants and copies live beside it."""
    return Path(app.config["DATABASE_PATH"]).resolve().parent


def storage_key(keys_dir: Path) -> bytes:
    """The 32-byte storage key; created on first use and never written anywhere else."""
    path = Path(keys_dir) / "copy_storage.key"
    if path.exists():
        key = path.read_bytes()
        if len(key) != 32:
            raise RuntimeError("keys/copy_storage.key must be exactly 32 bytes")
        return key
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(key)
    return key


def _seal(key: bytes, aad: str, data: bytes) -> bytes:
    nonce, ciphertext = encrypt(data, key, aad.encode("utf-8"))
    return nonce + ciphertext


def _open(key: bytes, aad: str, blob: bytes) -> bytes:
    return decrypt(blob[:12], blob[12:], key, aad.encode("utf-8"))


def _safe_exam_id(exam_id: str) -> str:
    if not isinstance(exam_id, str) or not _EXAM_ID.match(exam_id):
        raise ValueError("invalid exam id")
    return exam_id


def _write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_bytes(data)
    os.replace(temp, path)


def _variants_path(data_dir: Path, exam_id: str) -> Path:
    return Path(data_dir) / "variants" / f"{_safe_exam_id(exam_id)}.bin"


def _copy_relative_path(exam_id: str, user_id: int) -> str:
    return f"copies/{_safe_exam_id(exam_id)}/{int(user_id)}.pdf.enc"


def _save_slots(data_dir: Path, key: bytes, exam_id: str, slots: list[dict[str, Any]]) -> None:
    blob = _seal(key, f"variants:{exam_id}", json.dumps(slots).encode("utf-8"))
    _write_atomic(_variants_path(data_dir, exam_id), blob)


def load_variant_slots(data_dir: Path, key: bytes, exam_id: str) -> list[dict[str, Any]] | None:
    """The slots of an exam with their review state; None when the exam has no variant data."""
    try:
        path = _variants_path(data_dir, exam_id)
    except ValueError:
        return None
    if not path.exists():
        return None
    return json.loads(_open(key, f"variants:{exam_id}", path.read_bytes()))


def prepare_exam_variants(
    conn: sqlite3.Connection, data_dir: Path, key: bytes, exam_id: str,
    slots: list[dict[str, Any]], holder_ids: list[int],
) -> int:
    """Store the slots (encrypted), the secret bias vector and one codeword per holder. Returns the slot count."""
    biases = new_bias_vector(len(slots))
    words = assign_codewords(len(holder_ids), biases)
    stored = [dict(slot, reviewed_by="", status="") for slot in slots]
    _save_slots(data_dir, key, exam_id, stored)
    with conn:
        conn.execute(
            "INSERT OR REPLACE INTO tardos_params (exam_id, bias_vector_encrypted, slot_count) VALUES (?, ?, ?)",
            (exam_id, _seal(key, f"tardos:{exam_id}", json.dumps(biases).encode("utf-8")), len(slots)),
        )
        conn.execute("DELETE FROM copies WHERE exam_id = ?", (exam_id,))
        for user_id, word in zip(holder_ids, words):
            conn.execute(
                "INSERT INTO copies (exam_id, user_id, slot_pattern, file_path) VALUES (?, ?, ?, NULL)",
                (exam_id, int(user_id), word),
            )
    return len(slots)


def set_slot_review(
    data_dir: Path, key: bytes, exam_id: str, slot_id: int, status: str, reviewer: str
) -> bool:
    """Mark one slot 'ok' (reviewed) or 'doubtful'. False if the exam or slot does not exist."""
    if status not in ("ok", "doubtful"):
        raise ValueError("status must be 'ok' or 'doubtful'")
    slots = load_variant_slots(data_dir, key, exam_id)
    if slots is None:
        return False
    for slot in slots:
        if slot["slot_id"] == slot_id:
            slot["status"], slot["reviewed_by"] = status, reviewer
            _save_slots(data_dir, key, exam_id, slots)
            return True
    return False


# ---------- release: build one PDF per holder ----------

def render_pdf(title: str, body: str) -> bytes:
    """A plain A4 PDF of the paper text (title, then the paper line by line)."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    def clean(text: str) -> str:  # the standard PDF font is Latin-1 only
        return escape(text.encode("cp1252", "replace").decode("cp1252"))

    styles = getSampleStyleSheet()
    story = [Paragraph(clean(title or "Exam paper"), styles["Heading1"]), Spacer(1, 12)]
    for line in body.splitlines():
        story.append(Paragraph(clean(line), styles["BodyText"]) if line.strip() else Spacer(1, 8))
    out = io.BytesIO()
    SimpleDocTemplate(out, pagesize=A4, title=clean(title or "Exam paper")).build(story)
    return out.getvalue()


def build_copies(
    conn: sqlite3.Connection, data_dir: Path, key: bytes, exam_id: str, plaintext: bytes, title: str
) -> int:
    """Create every holder's encrypted PDF from the released paper (it exists only in memory here).

    An exam that was created without variant data (for example by the CLI demo) is prepared now, from
    the released paper, for its current holders. Returns how many copies were written.
    """
    text = extract_paper_text(plaintext)
    if not text.strip():
        raise ValueError("The released paper has no readable text")
    slots = parse_template(text)
    params = conn.execute("SELECT slot_count FROM tardos_params WHERE exam_id = ?", (exam_id,)).fetchone()
    if params is None:
        holder_ids = [
            row[0] for row in conn.execute(
                "SELECT holder_user_id FROM shares WHERE exam_id = ? AND is_current = 1 ORDER BY holder_user_id",
                (exam_id,),
            )
        ]
        prepare_exam_variants(conn, data_dir, key, exam_id, slots, holder_ids)
    elif int(params[0]) != len(slots):
        raise ValueError("The released paper does not match the stored variant slots")
    written = 0
    for row in conn.execute(
        "SELECT id, user_id, slot_pattern FROM copies WHERE exam_id = ? AND file_path IS NULL", (exam_id,)
    ).fetchall():
        pdf = render_pdf(title, assemble_copy_text(text, row["slot_pattern"]))
        relative = _copy_relative_path(exam_id, row["user_id"])
        _write_atomic(Path(data_dir) / relative, _seal(key, f"copy:{exam_id}:{row['user_id']}", pdf))
        with conn:
            conn.execute("UPDATE copies SET file_path = ? WHERE id = ?", (relative, row["id"]))
        written += 1
    return written


def copy_info(conn: sqlite3.Connection, exam_id: str, user_id: int) -> sqlite3.Row | None:
    """The holder's copies row (id and file path only; never the codeword) or None."""
    return conn.execute(
        "SELECT id, file_path FROM copies WHERE exam_id = ? AND user_id = ?", (exam_id, int(user_id))
    ).fetchone()


def load_copy_pdf(conn: sqlite3.Connection, data_dir: Path, key: bytes, exam_id: str, user_id: int) -> bytes | None:
    """Decrypt the holder's own PDF; None when it has not been built yet."""
    row = copy_info(conn, exam_id, user_id)
    if row is None or not row["file_path"]:
        return None
    path = Path(data_dir) / row["file_path"]
    if path.resolve().parent.parent.parent != Path(data_dir).resolve() or not path.exists():
        return None
    return _open(key, f"copy:{exam_id}:{int(user_id)}", path.read_bytes())
