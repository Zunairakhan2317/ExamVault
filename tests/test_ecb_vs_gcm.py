"""ECB vs GCM demo (plan 7.1): ECB leaks the picture's structure and accepts damage, GCM does neither."""
from __future__ import annotations

import secrets

import pytest

from demo import ecb_vs_gcm as demo
from tests.test_web_auth import login_fully, make_config, make_user
from web.app import create_app


# --- logic level -----------------------------------------------------------------------------------------

def test_ecb_keeps_the_pattern_and_gcm_hides_it():
    result = demo.run_demo()
    repeated = result["repeated"]
    assert repeated["plaintext"] > repeated["total"] // 2  # flat colour areas: most blocks repeat
    assert repeated["ecb"] == repeated["plaintext"]  # identical blocks stay identical under ECB
    assert repeated["gcm"] == 0  # GCM output has no repeated blocks


def test_all_three_pictures_have_the_same_size():
    result = demo.run_demo()
    assert result["original"].size == result["ecb"].size == result["gcm"].size == demo.IMAGE_SIZE


def test_ecb_is_deterministic_but_gcm_is_not():
    key = secrets.token_bytes(32)
    data = demo.to_raw_rgb(demo.make_sample_image())
    assert demo.encrypt_ecb(data, key) == demo.encrypt_ecb(data, key)
    first, second = demo.gcm_encrypt(data, key, demo.DEMO_AAD), demo.gcm_encrypt(data, key, demo.DEMO_AAD)
    assert first != second  # fresh random nonce every call


def test_one_flipped_byte_is_rejected_by_gcm_and_silently_accepted_by_ecb():
    tamper = demo.run_demo()["tamper"]
    assert tamper["gcm_rejected"] is True
    assert tamper["ecb_accepted"] is True
    assert tamper["ecb_damaged_blocks"] == 1  # exactly one 16-byte block is wrecked, nobody is told


def test_ecb_round_trip_and_block_size_check():
    key = secrets.token_bytes(32)
    data = secrets.token_bytes(64)
    assert demo.decrypt_ecb(demo.encrypt_ecb(data, key), key) == data
    with pytest.raises(ValueError):
        demo.encrypt_ecb(b"not a whole block", key)


def test_raw_bytes_are_padded_to_whole_blocks_and_shown_as_an_image():
    image = demo.make_sample_image((50, 50))  # 7500 bytes: not a multiple of 16
    raw = demo.to_raw_rgb(image)
    assert len(raw) % demo.BLOCK == 0
    assert demo.bytes_to_image(raw, (50, 50)).size == (50, 50)


def test_data_uri_is_a_png():
    assert demo.image_data_uri(demo.make_sample_image((8, 8))).startswith("data:image/png;base64,")


# --- web level -------------------------------------------------------------------------------------------

def test_demo_page_is_visible_to_every_role_and_shows_three_pictures(tmp_path):
    app = create_app(make_config(tmp_path))
    for role in ("admin", "examiner", "invigilator", "auditor"):
        secret = make_user(app, f"u_{role}", role)
        client = app.test_client()
        login_fully(client, secret, f"u_{role}")
        page = client.get("/demo/ecb")
        assert page.status_code == 200
        text = page.get_data(as_text=True)
        assert text.count("data:image/png;base64,") == 3
        assert "never used in ExamVault" in text and "Refused to decrypt" in text


def test_demo_page_needs_a_login(tmp_path):
    client = create_app(make_config(tmp_path)).test_client()
    assert client.get("/demo/ecb").status_code in (302, 401)
