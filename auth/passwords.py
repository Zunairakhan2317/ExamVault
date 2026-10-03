"""Password hashing and policy checks for ExamVault authentication."""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

MIN_LENGTH = 12
MAX_LENGTH = 128
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
    if len(password) > MAX_LENGTH:
        raise ValueError(f"password must be at most {MAX_LENGTH} characters")
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


def check_policy(password: str, username: str | None = None) -> None:
    """Enforce password length, identity resistance, common-password and diversity rules."""
    if not isinstance(password, str):
        raise ValueError("password must be a string")
    if len(password) < MIN_LENGTH:
        raise ValueError(f"password must be at least {MIN_LENGTH} characters")
    if len(password) > MAX_LENGTH:
        raise ValueError(f"password must be at most {MAX_LENGTH} characters")

    normalized_password = password.lower()
    if username:
        normalized_username = username.lower()
        if normalized_password == normalized_username:
            raise ValueError("password must not equal the username")
        if normalized_username in normalized_password:
            raise ValueError("password must not contain the username")

    if normalized_password in COMMON_PASSWORDS:
        raise ValueError("password is too common")

    classes = (
        any(character.islower() for character in password),
        any(character.isupper() for character in password),
        any(character.isdigit() for character in password),
        any(not character.isalnum() for character in password),
    )
    if sum(classes) < 3:
        raise ValueError("password must use at least three character classes")
