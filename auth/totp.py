"""TOTP enrollment, replay-resistant verification, and encrypted secret storage."""

import binascii
import hmac
import io
import struct
import time

import pyotp
import qrcode
from cryptography.exceptions import InvalidTag

from crypto.aes_gcm import decrypt, encrypt

STEP_SECONDS = 30
DIGITS = 6
NONCE_SIZE = 12


def new_secret() -> str:
    """Generate a cryptographically random base32 TOTP secret for enrollment."""
    return pyotp.random_base32()


def provisioning_uri(
    secret: str,
    username: str,
    issuer: str = "ExamVault",
) -> str:
    """Create an authenticator provisioning URI for the user's TOTP secret."""
    return pyotp.TOTP(secret, digits=DIGITS, interval=STEP_SECONDS).provisioning_uri(
        name=username,
        issuer_name=issuer,
    )


def qr_png_bytes(uri: str) -> bytes:
    """Render the provisioning URI as PNG bytes for private authenticator enrollment."""
    image = qrcode.make(uri)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def current_step(now: float | None = None) -> int:
    """Return the 30-second TOTP counter used to enforce bounded code freshness."""
    timestamp = time.time() if now is None else now
    return int(timestamp // STEP_SECONDS)


def verify_code(
    secret: str,
    code: str,
    last_used_step: int | None,
    now: float | None = None,
) -> tuple[bool, int | None]:
    """Verify a nearby TOTP and reject any step already accepted for replay protection."""
    if not isinstance(code, str):
        return False, None
    normalized_code = code.replace(" ", "")
    if not (
        normalized_code.isascii()
        and normalized_code.isdigit()
        and len(normalized_code) == DIGITS
    ):
        return False, None

    step_now = current_step(now)
    totp = pyotp.TOTP(secret, digits=DIGITS, interval=STEP_SECONDS)
    matching_steps: list[int] = []
    try:
        for step in (step_now - 1, step_now, step_now + 1):
            expected = totp.at(step * STEP_SECONDS)
            if hmac.compare_digest(normalized_code, expected):
                matching_steps.append(step)
    except (binascii.Error, ValueError, TypeError, OverflowError, struct.error):
        return False, None

    if not matching_steps:
        return False, None
    matched_step = max(matching_steps)
    if last_used_step is None or matched_step > last_used_step:
        return True, matched_step
    return False, None


def protect_secret(secret: str, key: bytes, username: str) -> bytes:
    """Encrypt a TOTP secret with AES-GCM and bind it to its username as AAD."""
    nonce, ciphertext = encrypt(
        secret.encode("utf-8"),
        key,
        b"totp:" + username.encode("utf-8"),
    )
    return nonce + ciphertext


def unprotect_secret(blob: bytes, key: bytes, username: str) -> str:
    """Decrypt a username-bound TOTP secret; AES-GCM detects wrong keys or tampering."""
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if len(blob) < NONCE_SIZE + 1:
        raise ValueError("blob must contain a nonce and ciphertext")
    nonce = blob[:NONCE_SIZE]
    ciphertext = blob[NONCE_SIZE:]
    plaintext = decrypt(
        nonce,
        ciphertext,
        key,
        b"totp:" + username.encode("utf-8"),
    )
    return plaintext.decode("utf-8")
