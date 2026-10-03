"""Password hashing and policy checks for ExamVault authentication."""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

MIN_LENGTH = 12
COMMON_PASSWORDS = frozenset(
    {
        "password123456",
        "123456789012",
        "qwertyuiop12",
        "adminadmin12",
        "examvault1234",
        "letmein123456",
        "welcome12345",
        "iloveyou1234",
        "changeme1234",
        "passw0rd1234",
        "passwordpassword",
        "1234567890123456",
        "qwerty123456",
        "administrator1",
        "football12345",
        "monkeymonkey12",
        "dragon12345678",
        "sunshine12345",
        "masterkey1234",
        "trustno123456",
        "abc123456789",
        "welcomehome12",
        "letmeinletmein",
        "loginpassword1",
        "secretsecret12",
        "iloveyouiloveyou",
        "pass123456789",
        "examvault2025",
    }
)

_password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Hash a password with Argon2id, making offline password cracking costly."""
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if not password:
        raise ValueError("password must not be empty")
    return _password_hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """Verify a password without exposing hash-parse or mismatch errors to callers."""
    if not isinstance(stored_hash, str) or not stored_hash or not isinstance(password, str) or not password:
        return False
    try:
        return _password_hasher.verify(stored_hash, password)
    except (VerificationError, InvalidHashError, TypeError, ValueError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """Identify invalid or outdated hashes so stored credentials can be upgraded."""
    if not isinstance(stored_hash, str) or not stored_hash:
        return True
    try:
        return _password_hasher.check_needs_rehash(stored_hash)
    except (VerificationError, InvalidHashError, TypeError, ValueError):
        return True


def check_policy(password: str) -> None:
    """Enforce the minimum password length and reject known common passwords."""
    if len(password) < MIN_LENGTH:
        raise ValueError(f"password must be at least {MIN_LENGTH} characters")
    if password.lower() in COMMON_PASSWORDS:
        raise ValueError("password is too common")
