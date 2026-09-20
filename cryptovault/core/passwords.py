from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw


@dataclass(frozen=True)
class PasswordAssessment:
    score: int
    label: str
    suggestions: tuple[str, ...]


def assess_password(password: str) -> PasswordAssessment:
    """A transparent local heuristic; this is guidance, not an entropy proof."""
    suggestions: list[str] = []
    score = 0
    if len(password) >= 12:
        score += 1
    else:
        suggestions.append("Use at least 12 characters")
    if len(password) >= 16:
        score += 1
    classes = sum(bool(re.search(pattern, password)) for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^\w\s]"))
    score += min(2, max(0, classes - 1))
    common = {"password", "123456", "qwerty", "letmein", "admin", "cryptovault"}
    if password.lower() in common or len(set(password)) < 5:
        score = min(score, 1)
        suggestions.append("Avoid common or repetitive passwords")
    if classes < 3:
        suggestions.append("Mix words, numbers, and symbols")
    labels = ("Very weak", "Weak", "Fair", "Strong", "Excellent")
    return PasswordAssessment(score=max(0, min(4, score)), label=labels[max(0, min(4, score))], suggestions=tuple(suggestions))


def derive_key(password: str, salt: bytes, method: str, params: dict | None = None) -> tuple[bytes, dict]:
    if not password:
        raise ValueError("Password cannot be empty")
    params = dict(params or {})
    password_bytes = password.encode("utf-8")
    if method == "Argon2id":
        effective = {"time_cost": 3, "memory_cost": 65536, "parallelism": 4, **params}
        if not 1 <= int(effective["time_cost"]) <= 10:
            raise ValueError("Argon2 time_cost is outside the safe range")
        if not 8192 <= int(effective["memory_cost"]) <= 1_048_576:
            raise ValueError("Argon2 memory_cost is outside the safe range")
        if not 1 <= int(effective["parallelism"]) <= 16:
            raise ValueError("Argon2 parallelism is outside the safe range")
        key = hash_secret_raw(password_bytes, salt, hash_len=32, type=Type.ID, **effective)
    elif method == "scrypt":
        effective = {"n": 2**15, "r": 8, "p": 1, **params}
        n, r, p = int(effective["n"]), int(effective["r"]), int(effective["p"])
        if n < 2**14 or n > 2**20 or n & (n - 1):
            raise ValueError("scrypt n must be a power of two in the safe range")
        if not 1 <= r <= 32 or not 1 <= p <= 16 or r * p > 128:
            raise ValueError("scrypt r/p parameters are outside the safe range")
        key = hashlib.scrypt(password_bytes, salt=salt, dklen=32, **effective)
    elif method == "PBKDF2-SHA256":
        effective = {"iterations": 600_000, **params}
        if not 100_000 <= int(effective["iterations"]) <= 10_000_000:
            raise ValueError("PBKDF2 iterations are outside the safe range")
        key = hashlib.pbkdf2_hmac("sha256", password_bytes, salt, effective["iterations"], dklen=32)
    else:
        raise ValueError(f"Unsupported KDF: {method}")
    return key, effective
