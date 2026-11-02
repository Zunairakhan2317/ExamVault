"""ECB vs GCM comparator (plan 7.1): why ExamVault uses authenticated encryption.

An image with large flat colour areas is encrypted with the SAME AES key two ways:
- AES-ECB (demonstration only, NEVER used in ExamVault): identical 16-byte blocks give identical ciphertext
  blocks, so the picture's outline stays visible in the "encrypted" image.
- AES-GCM (what ExamVault uses): a fresh random nonce and authentication, so the output looks like noise.
Second demo: flip one byte in each ciphertext. GCM refuses to decrypt (InvalidTag); ECB silently decrypts to
damaged data. Only the AES primitives of the `cryptography` library are used.
"""
from __future__ import annotations

import base64
import io
import secrets
import sys
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PIL import Image, ImageDraw

from crypto.aes_gcm import decrypt as gcm_decrypt
from crypto.aes_gcm import encrypt as gcm_encrypt

BLOCK = 16
IMAGE_SIZE = (256, 256)
DEMO_AAD = b"examvault-ecb-demo"


def make_sample_image(size: tuple[int, int] = IMAGE_SIZE) -> Image.Image:
    """A simple logo-like picture: flat colours only, so repeated plaintext blocks are plentiful."""
    width, height = size
    image = Image.new("RGB", size, (245, 245, 245))
    draw = ImageDraw.Draw(image)
    draw.rectangle([width // 8, height // 8, width * 7 // 8, height * 7 // 8], fill=(30, 80, 200))
    draw.ellipse([width // 4, height // 4, width * 3 // 4, height * 3 // 4], fill=(220, 40, 40))
    draw.polygon([(width // 2, height * 3 // 10), (width * 7 // 20, height * 13 // 20), (width * 13 // 20, height * 13 // 20)], fill=(250, 220, 30))
    draw.rectangle([width // 8, height * 7 // 8 - 10, width * 7 // 8, height * 7 // 8], fill=(0, 0, 0))
    return image


def load_image(path: str | Path) -> Image.Image:
    """Load any picture (for example the classic Tux PNG) at the demo size."""
    return Image.open(path).convert("RGB").resize(IMAGE_SIZE)


def to_raw_rgb(image: Image.Image) -> bytes:
    """The picture as raw RGB bytes, padded with zeros to a whole number of 16-byte blocks."""
    data = image.convert("RGB").tobytes()
    return data + b"\x00" * (-len(data) % BLOCK)


def bytes_to_image(data: bytes, size: tuple[int, int]) -> Image.Image:
    """Show any byte string as an image of the given size (cut or padded to fit)."""
    needed = size[0] * size[1] * 3
    return Image.frombytes("RGB", size, (data[:needed] + b"\x00" * max(0, needed - len(data))))


def encrypt_ecb(data: bytes, key: bytes) -> bytes:
    """AES-ECB. INSECURE: for this demonstration only, never used by ExamVault itself."""
    if len(data) % BLOCK:
        raise ValueError("ECB needs whole 16-byte blocks")
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # noqa: S305 (deliberate demo)
    return encryptor.update(data) + encryptor.finalize()


def decrypt_ecb(data: bytes, key: bytes) -> bytes:
    """AES-ECB decryption (no integrity check at all: damaged input just decrypts to damaged output)."""
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()  # noqa: S305 (deliberate demo)
    return decryptor.update(data) + decryptor.finalize()


def repeated_blocks(data: bytes) -> int:
    """How many 16-byte blocks are copies of an earlier block (a measure of visible structure)."""
    blocks = [data[i:i + BLOCK] for i in range(0, len(data) - len(data) % BLOCK, BLOCK)]
    return len(blocks) - len(set(blocks))


def flip_one_byte(data: bytes, position: int | None = None) -> bytes:
    """Return a copy with a single bit changed in one byte (default: a byte in the middle)."""
    index = len(data) // 2 if position is None else position
    tampered = bytearray(data)
    tampered[index] ^= 0x01
    return bytes(tampered)


def tamper_test(plaintext: bytes, key: bytes) -> dict[str, Any]:
    """Flip one byte in each ciphertext and report what each mode does."""
    ecb_cipher = encrypt_ecb(plaintext, key)
    nonce, gcm_cipher = gcm_encrypt(plaintext, key, DEMO_AAD)
    try:
        gcm_decrypt(nonce, flip_one_byte(gcm_cipher), key, DEMO_AAD)
        gcm_rejected = False
    except InvalidTag:
        gcm_rejected = True
    ecb_plain = decrypt_ecb(flip_one_byte(ecb_cipher), key)  # no error: nothing notices
    blocks = lambda d: [d[i:i + BLOCK] for i in range(0, len(d), BLOCK)]  # noqa: E731
    damaged_blocks = sum(1 for a, b in zip(blocks(plaintext), blocks(ecb_plain)) if a != b)
    return {
        "gcm_rejected": gcm_rejected,
        "ecb_accepted": ecb_plain != plaintext and len(ecb_plain) == len(plaintext),
        "ecb_damaged_blocks": damaged_blocks,
        "ecb_total_blocks": len(plaintext) // BLOCK,
    }


def run_demo(image: Image.Image | None = None, key: bytes | None = None) -> dict[str, Any]:
    """Run both demos. Returns the three images (original, ECB, GCM) and the tamper results."""
    image = image or make_sample_image()
    key = key or secrets.token_bytes(32)
    plaintext = to_raw_rgb(image)
    ecb_cipher = encrypt_ecb(plaintext, key)
    _, gcm_cipher = gcm_encrypt(plaintext, key, DEMO_AAD)
    return {
        "original": image,
        "ecb": bytes_to_image(ecb_cipher, image.size),
        "gcm": bytes_to_image(gcm_cipher, image.size),
        "repeated": {
            "plaintext": repeated_blocks(plaintext),
            "ecb": repeated_blocks(ecb_cipher),
            "gcm": repeated_blocks(gcm_cipher),
            "total": len(plaintext) // BLOCK,
        },
        "tamper": tamper_test(plaintext, key),
    }


def image_data_uri(image: Image.Image) -> str:
    """PNG data URI so a page can show the image without any file or extra route (the CSP allows data:)."""
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")


def main(argv: list[str]) -> int:
    """CLI: python -m demo.ecb_vs_gcm [image.png]  -> saves the three images into docs/ and prints the tamper test."""
    result = run_demo(load_image(argv[1]) if len(argv) > 1 else None)
    out = Path("docs")
    out.mkdir(exist_ok=True)
    for name in ("original", "ecb", "gcm"):
        result[name].save(out / f"ecb_demo_{name}.png")
    tamper, rep = result["tamper"], result["repeated"]
    print(f"Repeated 16-byte blocks of {rep['total']}: plaintext={rep['plaintext']} ECB={rep['ecb']} GCM={rep['gcm']}")
    print(f"One flipped byte -> GCM rejected it: {tamper['gcm_rejected']}; ECB decrypted silently to damaged data: {tamper['ecb_accepted']}")
    print("Images saved in docs/ecb_demo_*.png. ECB is insecure and is NOT used in ExamVault.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
