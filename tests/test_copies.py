"""Variants read from the uploaded paper, per-holder codewords, release-time PDFs and the download page.

Frontend Brief pages 10, 13, 16 and plan 5.2-5.4. Uses the real paper service, share flow and encryption.
"""
import io
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization

from crypto.services import paper_service
from tests.test_examiner_pages import (  # noqa: F401  (fixtures and helpers are reused)
    HOLDERS, PAPER, Env, env, exam_rows, form, make_exam, rsa_keys, rsa_pub, signing_key, upload, window,
)
from web import copy_service, exam_store

TEMPLATE = (
    "Q1. {Explain|Describe} a stack and its uses. [5 marks]\n"
    "Q2. {Define|State} a queue. [5 marks]\n"
    "Q3. {List|Name} two sorting algorithms {quickly|briefly}. [4 marks]\n"
    "Q4. {Compare|Contrast} arrays and linked lists. [6 marks]\n"
    "Q5. {Write|Give} the steps of binary search. [5 marks]\n"
    "Plain braces {stay as they are} and {same|same} too.\n"
)
SLOT_COUNT = 6


def pdf_bytes(text: str) -> bytes:
    return copy_service.render_pdf("Source", text)


def pdf_text(data: bytes) -> str:
    import pdfplumber

    with pdfplumber.open(io.BytesIO(data)) as pdf:
        return "\n".join(page.extract_text() or "" for page in pdf.pages)


def open_window():
    base = datetime.now(timezone.utc)
    fmt = "%Y-%m-%dT%H:%M"
    return (base - timedelta(minutes=5)).strftime(fmt), (base + timedelta(hours=1)).strftime(fmt)


def upload_template(env, content=TEMPLATE.encode(), name="paper.txt", **kwargs):
    start, end = open_window()
    return upload(env, window_start=start, window_end=end, paper=(io.BytesIO(content), name), **kwargs)


def data_dir(env):
    return Path(env.app.config["DATABASE_PATH"]).parent


def private_pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def submit_share(env, rsa_keys, name, exam_id):
    client = env.client(name)
    page = client.get(f"/invigilator/submit-share/{exam_id}")
    nonce = re.search(r'name="nonce" value="([^"]+)"', page.get_data(as_text=True)).group(1)
    return client.post(
        f"/invigilator/submit-share/{exam_id}",
        data={"nonce": nonce, "keyfile": (io.BytesIO(private_pem(rsa_keys[name])), "key.pem")},
        content_type="multipart/form-data", follow_redirects=True,
    )


def release(env, rsa_keys, exam_id, who=("inv1", "inv2", "inv3")):
    env.app.config["EXAMINER_PUBLIC_KEY_PATH"] = str(env.keys_dir / "examiner_signing_public.pem")
    for name in who:
        submit_share(env, rsa_keys, name, exam_id)


def only_exam_id():
    (row,) = exam_rows()
    return row["exam_id"]


def pattern_of(env, exam_id, name):
    return env.conn.execute(
        "SELECT slot_pattern FROM copies WHERE exam_id = ? AND user_id = ?", (exam_id, env.ids[name])
    ).fetchone()["slot_pattern"]


# ---------- reading the paper ----------

def test_parse_template_finds_slots_questions_and_marks():
    slots = copy_service.parse_template(TEMPLATE)
    assert len(slots) == SLOT_COUNT
    assert [s["slot_id"] for s in slots] == list(range(1, 7))
    assert slots[0]["variants"] == ["Explain", "Describe"] and slots[0]["question_no"] == "1"
    assert [s["question_no"] for s in slots] == ["1", "2", "3", "3", "4", "5"]
    assert [s["group_index"] for s in slots] == [0, 0, 0, 1, 0, 0]
    assert [s["marks"] for s in slots] == [5, 5, 4, 4, 6, 5]


def test_parse_template_ignores_plain_braces_and_identical_options_and_keeps_two_options():
    text = "Q1. {just braces} {A|a} {one|two|three}\n"
    slots = copy_service.parse_template(text)
    assert len(slots) == 1 and slots[0]["variants"] == ["one", "two"]
    assert copy_service.parse_template("no slots here") == []
    assert copy_service.parse_template("") == []


def test_parse_template_handles_a_group_split_over_two_lines():
    slots = copy_service.parse_template("Q7. {Explain\n   the|Describe the} role of a key.")
    assert slots[0]["variants"] == ["Explain the", "Describe the"] and slots[0]["question_no"] == "7"


def test_extract_text_from_text_and_pdf():
    assert copy_service.extract_paper_text("Q1. {a|b} caf\u00e9".encode()) == "Q1. {a|b} caf\u00e9"
    assert copy_service.extract_paper_text(b"caf\xe9") == "caf\u00e9"  # not UTF-8: Latin-1 fallback
    text = copy_service.extract_paper_text(pdf_bytes(TEMPLATE))
    assert len(copy_service.parse_template(text)) == SLOT_COUNT
    with pytest.raises(ValueError):
        copy_service.extract_paper_text(b"%PDF-1.4 this is not a real pdf")
    with pytest.raises(TypeError):
        copy_service.extract_paper_text("text")  # type: ignore[arg-type]


def test_assemble_copy_text_uses_the_bits():
    first = copy_service.assemble_copy_text(TEMPLATE, "000000")
    second = copy_service.assemble_copy_text(TEMPLATE, "111111")
    assert "Explain a stack" in first and "Describe a stack" in second
    assert "{stay as they are}" in first and "{same|same}" in first and "{" not in first.replace("{stay as they are}", "").replace("{same|same}", "")
    for bad in ("00000", "0000000", "00000x"):
        with pytest.raises(ValueError):
            copy_service.assemble_copy_text(TEMPLATE, bad)


# ---------- codewords ----------

def test_bias_vector_and_codewords():
    biases = copy_service.new_bias_vector(40)
    assert len(biases) == 40 and all(0.01 <= p <= 0.99 for p in biases)
    for _ in range(20):  # a short paper still gives every holder a different word
        words = copy_service.assign_codewords(5, copy_service.new_bias_vector(SLOT_COUNT))
        assert len(set(words)) == 5 and all(len(w) == SLOT_COUNT and set(w) <= {"0", "1"} for w in words)
    long_words = copy_service.assign_codewords(5, biases)
    distance = max(1, 40 // 8)
    assert all(sum(a != b for a, b in zip(x, y)) >= distance for i, x in enumerate(long_words) for y in long_words[:i])
    assert copy_service.assign_codewords(3, []) == ["", "", ""]


# ---------- encrypted storage ----------

def test_storage_key_is_created_once_and_blobs_are_authenticated(tmp_path):
    key = copy_service.storage_key(tmp_path)
    assert len(key) == 32 and copy_service.storage_key(tmp_path) == key
    (tmp_path / "copy_storage.key").write_bytes(b"short")
    with pytest.raises(RuntimeError):
        copy_service.storage_key(tmp_path)
    blob = copy_service._seal(key, "aad", b"secret wording")
    assert b"secret wording" not in blob and copy_service._open(key, "aad", blob) == b"secret wording"
    with pytest.raises(InvalidTag):
        copy_service._open(key, "other-aad", blob)
    with pytest.raises(InvalidTag):
        copy_service._open(key, "aad", blob[:-1] + bytes([blob[-1] ^ 1]))


def test_render_pdf_escapes_markup_and_replaces_unsupported_letters():
    text = pdf_text(copy_service.render_pdf("Mid <b>term</b> & Co", "Line one <i>x</i>\n\n\u0627\u0631\u062f\u0648 end"))
    assert "<b>term</b>" in text and "<i>x</i>" in text and "end" in text


# ---------- upload: variants come from the paper ----------

def test_upload_reads_variants_from_the_paper_and_assigns_codewords(env):
    response = upload_template(env)
    assert response.status_code == 200
    text = response.get_data(as_text=True)
    assert f"Variant slots: {SLOT_COUNT}" in text and "Need at least 40 slots" in text
    exam_id = only_exam_id()
    rows = env.conn.execute("SELECT user_id, slot_pattern, file_path FROM copies WHERE exam_id = ?", (exam_id,)).fetchall()
    assert len(rows) == 5 and {r["user_id"] for r in rows} == {env.ids[n] for n in HOLDERS}
    assert all(len(r["slot_pattern"]) == SLOT_COUNT and r["file_path"] is None for r in rows)
    params = env.conn.execute("SELECT * FROM tardos_params WHERE exam_id = ?", (exam_id,)).fetchone()
    assert params["slot_count"] == SLOT_COUNT
    blob = bytes(params["bias_vector_encrypted"])
    key = copy_service.storage_key(env.keys_dir)
    biases = __import__("json").loads(copy_service._open(key, f"tardos:{exam_id}", blob))
    assert len(biases) == SLOT_COUNT and all(0.01 <= p <= 0.99 for p in biases)
    assert str(biases[0]).encode() not in blob  # the bias vector is not stored in the clear
    assert "variant_slots" in str([tuple(r) for r in env.conn.execute("SELECT * FROM audit_entries")])


def test_variant_wordings_are_only_stored_encrypted(env):
    upload_template(env)
    exam_id = only_exam_id()
    blob = (data_dir(env) / "variants" / f"{exam_id}.bin").read_bytes()
    assert b"Explain" not in blob and b"Describe" not in blob
    for table in ("copies", "tardos_params", "exams", "audit_entries"):
        dump = str([tuple(r) for r in env.conn.execute(f"SELECT * FROM {table}")]) if table != "exams" else ""
        assert "Explain" not in dump and "Describe" not in dump
    assert b"Explain" not in (env.keys_dir / "copy_storage.key").read_bytes()


def test_upload_accepts_a_pdf_template(env):
    assert f"Variant slots: {SLOT_COUNT}" in upload_template(env, pdf_bytes(TEMPLATE), "paper.pdf").get_data(as_text=True)


def test_upload_without_slots_warns_and_still_creates_the_exam(env):
    response = upload(env)  # PAPER has no {a|b} groups
    assert response.status_code == 200 and "No variant slots found" in response.get_data(as_text=True)
    exam_id = only_exam_id()
    patterns = [r["slot_pattern"] for r in env.conn.execute("SELECT slot_pattern FROM copies WHERE exam_id = ?", (exam_id,))]
    assert patterns == [""] * 5


def test_upload_refuses_an_unreadable_pdf_and_too_many_slots(env):
    response = upload_template(env, b"%PDF-1.4 broken", "paper.pdf")
    assert response.status_code == 400 and "The paper could not be read" in response.get_data(as_text=True)
    many = ("{a|b} " * (copy_service.MAX_SLOTS + 1)).encode()
    response = upload_template(env, many)
    assert response.status_code == 400 and "Too many variant slots" in response.get_data(as_text=True)
    assert exam_rows() == []


def test_upload_page_explains_the_variant_syntax(env):
    text = env.client("exm1").get("/examiner/upload").get_data(as_text=True)
    assert "{pehli wording | doosri wording}" in text


# ---------- page 13: variants review ----------

def test_variants_page_shows_slots_from_the_paper(env):
    upload_template(env)
    exam_id = only_exam_id()
    text = env.client("exm1").get(f"/examiner/variants?exam_id={exam_id}").get_data(as_text=True)
    for expected in (
        f"Total slots: {SLOT_COUNT} (minimum 40)", "Need at least 40 slots", "Variant 1", "Variant 2", "Explain",
        "Describe", "Slot number", "Question number", "Marks", "Reviewed by", "Mark reviewed", "Flag doubtful",
        "Variants means shuffled versions of the same question with same marks and numbers.", "<progress",
    ):
        assert expected in text
    assert "style=" not in text and "onclick=" not in text
    assert "Explain" in env.client("exm1").get("/examiner/variants").get_data(as_text=True)  # newest exam by default


def test_variants_page_empty_states(env):
    assert "No exams yet" in env.client("exm1").get("/examiner/variants").get_data(as_text=True)
    exam_id = make_exam(env)  # created without variant data
    assert "No variant slots for this exam." in env.client("exm1").get(f"/examiner/variants?exam_id={exam_id}").get_data(as_text=True)
    assert env.client("exm1").get("/examiner/variants?exam_id=nope").status_code == 404


def test_review_buttons_update_status_filter_and_audit(env):
    upload_template(env)
    exam_id = only_exam_id()
    client = env.client("exm1")
    url = f"/examiner/variants/{exam_id}/review"
    assert client.post(url, data={"slot_id": "1", "action": "reviewed"}).status_code == 303
    assert client.post(url, data={"slot_id": "2", "action": "doubtful"}).status_code == 303
    page = client.get(f"/examiner/variants?exam_id={exam_id}").get_data(as_text=True)
    assert "exm1" in page and 'text-bg-success">OK' in page and 'text-bg-danger">Doubtful' in page
    reviewed = client.get(f"/examiner/variants?exam_id={exam_id}&filter=reviewed").get_data(as_text=True)
    assert "Explain" in reviewed and "Define" not in reviewed
    doubtful = client.get(f"/examiner/variants?exam_id={exam_id}&filter=doubtful").get_data(as_text=True)
    assert "Define" in doubtful and "Explain" not in doubtful
    audit = str([tuple(r) for r in env.conn.execute("SELECT * FROM audit_entries")])
    assert "variant_reviewed" in audit and "doubtful" in audit


def test_review_input_is_validated_and_role_protected(env):
    upload_template(env)
    exam_id = only_exam_id()
    url = f"/examiner/variants/{exam_id}/review"
    client = env.client("exm1")
    assert client.post(url, data={"slot_id": "1", "action": "delete"}).status_code == 400
    assert client.post(url, data={"slot_id": "x", "action": "reviewed"}).status_code == 400
    assert client.post(url, data={"slot_id": "999", "action": "reviewed"}).status_code == 404
    assert client.post("/examiner/variants/unknown/review", data={"slot_id": "1", "action": "reviewed"}).status_code == 404
    for other in ("adm1", "inv1", "aud1"):
        assert env.client(other).post(url, data={"slot_id": "1", "action": "reviewed"}).status_code == 403


def test_variant_text_is_escaped(env):
    upload_template(env, b"Q1. {<b>bold</b>|<script>alert(1)</script>} x. [1 marks]\n")
    text = env.client("exm1").get("/examiner/variants").get_data(as_text=True)
    assert "<script>alert" not in text and "&lt;script&gt;" in text


# ---------- release: one encrypted PDF per holder ----------

def test_release_builds_encrypted_pdfs_and_each_holder_downloads_their_own(env, rsa_keys):
    upload_template(env)
    exam_id = only_exam_id()
    release(env, rsa_keys, exam_id)
    rows = env.conn.execute("SELECT user_id, file_path FROM copies WHERE exam_id = ?", (exam_id,)).fetchall()
    assert len(rows) == 5 and all(r["file_path"] for r in rows)
    for row in rows:
        stored = (data_dir(env) / row["file_path"]).read_bytes()
        assert not stored.startswith(b"%PDF") and b"Explain" not in stored and b"Describe" not in stored
    texts = {}
    for name in HOLDERS:
        response = env.client(name).get(f"/invigilator/copy/{exam_id}/download")
        assert response.status_code == 200 and response.mimetype == "application/pdf"
        assert "attachment" in response.headers["Content-Disposition"] and response.headers["Cache-Control"] == "no-store"
        texts[name] = pdf_text(response.data)
        expected = copy_service.assemble_copy_text(TEMPLATE, pattern_of(env, exam_id, name))
        assert " ".join(texts[name].split()) .count("Plain braces") == 1
        for line in expected.splitlines()[:5]:
            assert line.split(". ", 1)[1].split(" [")[0] in " ".join(texts[name].split())
    assert len(set(texts.values())) > 1, "holders must get differently worded copies"
    assert "copies_issued" in str([tuple(r) for r in env.conn.execute("SELECT * FROM audit_entries")])


def test_copy_page_and_download_history(env, rsa_keys):
    upload_template(env)
    exam_id = only_exam_id()
    client = env.client("inv1")
    assert "Not available yet. Wait for the paper to be released." in client.get(f"/invigilator/copy/{exam_id}").get_data(as_text=True)
    assert client.get(f"/invigilator/copy/{exam_id}/download").status_code == 404  # not released yet
    release(env, rsa_keys, exam_id)
    page = client.get(f"/invigilator/copy/{exam_id}").get_data(as_text=True)
    for expected in ("Paper released", "Examiner signature: valid", "Your copy", "Copy ID", f"exam_{exam_id[:8]}_copy.pdf",
                     "Download PDF", "Ye copy aap ke naam se mark hai", "Download history", "No downloads yet."):
        assert expected in page
    assert client.get(f"/invigilator/copy/{exam_id}/download").status_code == 200
    page = client.get(f"/invigilator/copy/{exam_id}").get_data(as_text=True)
    assert "No downloads yet." not in page and re.search(r"\d{4}-\d{2}-\d{2}T", page)
    audit = str([tuple(r) for r in env.conn.execute("SELECT * FROM audit_entries WHERE event_type = 'copy_downloaded'")])
    assert "inv1" in audit and "%PDF" not in audit
    detail = env.client("exm1").get(f"/examiner/exams/{exam_id}").get_data(as_text=True)
    assert "Copy issued" in detail and "Yes" in detail and re.search(r"inv1</td><td>Yes</td><td class=\"small\">\d{4}", detail)


def test_only_holders_and_invigilators_can_use_the_copy_routes(env, rsa_keys):
    upload_template(env, holders=HOLDERS[:4] + ["inv5"])
    exam_id = only_exam_id()
    release(env, rsa_keys, exam_id)
    env.conn.execute("INSERT INTO users (username, role, password_hash) VALUES ('stranger', 'invigilator', 'x')")
    env.conn.commit()
    env.ids["stranger"] = env.conn.execute("SELECT id FROM users WHERE username = 'stranger'").fetchone()["id"]
    assert env.client("stranger").get(f"/invigilator/copy/{exam_id}/download").status_code == 404
    for other in ("exm1", "adm1", "aud1"):
        assert env.client(other).get(f"/invigilator/copy/{exam_id}/download").status_code == 403


def test_revoked_holder_cannot_download(env, rsa_keys):
    upload_template(env)
    exam_id = only_exam_id()
    release(env, rsa_keys, exam_id)
    env.conn.execute(
        "INSERT INTO certificates (serial, user_id, pem, issued_at, revoked_at) VALUES ('S1', ?, 'pem', 'now', 'now')",
        (env.ids["inv4"],),
    )
    env.conn.commit()
    assert env.client("inv4").get(f"/invigilator/copy/{exam_id}/download").status_code == 403
    assert env.client("inv5").get(f"/invigilator/copy/{exam_id}/download").status_code == 200
    assert "copy_refused" in str([tuple(r) for r in env.conn.execute("SELECT * FROM audit_entries")])


def test_a_changed_copy_file_is_refused(env, rsa_keys):
    upload_template(env)
    exam_id = only_exam_id()
    release(env, rsa_keys, exam_id)
    row = env.conn.execute("SELECT file_path FROM copies WHERE exam_id = ? AND user_id = ?", (exam_id, env.ids["inv1"])).fetchone()
    path = data_dir(env) / row["file_path"]
    blob = bytearray(path.read_bytes())
    blob[-1] ^= 1
    path.write_bytes(bytes(blob))
    env.app.config["PROPAGATE_EXCEPTIONS"] = False
    assert env.client("inv1").get(f"/invigilator/copy/{exam_id}/download").status_code == 500
    assert "integrity_check_failed" in str([tuple(r) for r in env.conn.execute("SELECT * FROM audit_entries")])


def test_exam_without_prepared_variants_is_prepared_at_release(env, rsa_keys):
    now = datetime.now(timezone.utc)
    holders = [rsa_pub(env, n) for n in HOLDERS]
    result = paper_service.create_exam(
        TEMPLATE.encode(), holders, env.signing, now - timedelta(minutes=5), now + timedelta(hours=1),
        exam_title="CLI exam", subject="CS", threshold=3,
    )
    exam_store.register_shares(env.conn, result["exam_id"], result["commitments"], [env.ids[n] for n in HOLDERS], result["wrapped_shares"])
    release(env, rsa_keys, result["exam_id"])
    row = env.conn.execute("SELECT slot_count FROM tardos_params WHERE exam_id = ?", (result["exam_id"],)).fetchone()
    assert row["slot_count"] == SLOT_COUNT
    response = env.client("inv1").get(f"/invigilator/copy/{result['exam_id']}/download")
    assert response.status_code == 200 and "stack" in pdf_text(response.data)


def test_paper_without_slots_gives_every_holder_the_same_readable_copy(env, rsa_keys):
    upload(env, window_start=open_window()[0], window_end=open_window()[1])
    exam_id = only_exam_id()
    release(env, rsa_keys, exam_id)
    first = pdf_text(env.client("inv1").get(f"/invigilator/copy/{exam_id}/download").data)
    second = pdf_text(env.client("inv2").get(f"/invigilator/copy/{exam_id}/download").data)
    assert first == second and "Explain a stack" in first


def test_release_handler_is_registered_once(env):
    handlers = env.app.extensions["examvault_release_handlers"]
    assert [h.__name__ for h in handlers].count("_issue_copies") == 1


# ---------- image-only PDFs and table-style papers ----------

def image_only_pdf() -> bytes:
    """A PDF that is just a picture of text (a screenshot saved as PDF): it has no text layer."""
    from PIL import Image, ImageDraw
    from reportlab.lib.utils import ImageReader
    from reportlab.pdfgen import canvas

    picture = Image.new("RGB", (600, 120), "white")
    ImageDraw.Draw(picture).text((10, 40), "1 {What is | Define} security? 5 marks", fill="black")
    out = io.BytesIO()
    page = canvas.Canvas(out)
    page.drawImage(ImageReader(picture), 40, 600, width=400, height=80)
    page.save()
    return out.getvalue()


def test_image_only_pdf_is_refused_at_upload_with_a_clear_message(env):
    response = upload_template(env, image_only_pdf(), "demo_exam.pdf")
    assert response.status_code == 400
    assert "No readable text found in the paper" in response.get_data(as_text=True)
    assert exam_rows() == []


def test_whitespace_only_text_paper_is_refused(env):
    response = upload_template(env, b"   \n\n  \t ", "paper.txt")
    assert response.status_code == 400 and "No readable text found" in response.get_data(as_text=True)
    assert exam_rows() == []


def test_releasing_a_paper_without_text_never_produces_blank_copies(env):
    image_bytes = image_only_pdf()
    with pytest.raises(ValueError, match="no readable text"):
        copy_service.build_copies(env.conn, data_dir(env), copy_service.storage_key(env.keys_dir), "abcdef12", image_bytes, "T")


TABLE_ROWS = (
    "Number Question Marks\n"
    "1 {What is | Define | how would you define} Information Security ? {Define and explain| Explain why | Why} { its importance | it is important} 5 marks\n"
    "2 {What is | Define | how would you define} Confidentiality?{Define and explain | Explain how | Why} {its role in Information Security | it protects information | it is important}. 5 marks\n"
    "3 {What is | Define | how would you define} Integrity? {Define and explain | Explain how | Why} {it maintains accurate information | it ensures data accuracy | it is important}. 5 Marks\n"
)


def test_table_style_rows_give_three_slots_per_row_with_numbers_and_marks():
    slots = copy_service.parse_template(TABLE_ROWS)
    assert len(slots) == 9
    assert [s["question_no"] for s in slots] == ["1"] * 3 + ["2"] * 3 + ["3"] * 3
    assert [s["group_index"] for s in slots] == [0, 1, 2] * 3
    assert all(s["marks"] == 5 for s in slots)
    assert slots[0]["variants"] == ["What is", "Define"]  # only the first two options of a slot are used
    assert slots[1]["variants"] == ["Define and explain", "Explain why"]
    assert slots[2]["variants"] == ["its importance", "it is important"]


def test_a_table_pdf_with_text_gives_slots_and_a_readable_copy(env, rsa_keys):
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate

    out = io.BytesIO()
    styles = getSampleStyleSheet()
    SimpleDocTemplate(out).build([Paragraph(line.replace("&", "&amp;"), styles["BodyText"]) for line in TABLE_ROWS.splitlines()])
    response = upload_template(env, out.getvalue(), "demo_exam.pdf")
    assert response.status_code == 200 and "Variant slots: 9" in response.get_data(as_text=True)
    exam_id = only_exam_id()
    release(env, rsa_keys, exam_id)
    body = " ".join(pdf_text(env.client("inv1").get(f"/invigilator/copy/{exam_id}/download").data).split())
    assert "Information Security" in body and "Confidentiality" in body and "{" not in body and "|" not in body


def test_an_unbalanced_brace_row_does_not_break_parsing():
    text = "13 {What is | Define} a Firewall? {Define and explain | Describe} fits role in network security | how it protects 5 marks\n"
    slots = copy_service.parse_template(text)
    assert len(slots) == 2 and slots[0]["question_no"] == "13"
