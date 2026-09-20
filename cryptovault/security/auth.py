from __future__ import annotations

import time

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


class SessionGuard:
    """Local app-lock helper. It stores only an Argon2id verifier."""

    def __init__(self, encoded_hash: str = "", timeout_minutes: int = 15):
        self.encoded_hash = encoded_hash
        self.timeout_seconds = max(1, timeout_minutes) * 60
        self.failed_attempts = 0
        self.locked_until = 0.0
        self.last_activity = time.monotonic()
        self._hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

    def configured(self) -> bool:
        return bool(self.encoded_hash)

    def set_password(self, password: str) -> str:
        if len(password) < 12:
            raise ValueError("Master password must contain at least 12 characters")
        self.encoded_hash = self._hasher.hash(password)
        self.touch()
        return self.encoded_hash

    def verify(self, password: str) -> bool:
        now = time.monotonic()
        if now < self.locked_until:
            raise ValueError(f"Too many failed attempts. Try again in {int(self.locked_until - now) + 1} seconds.")
        try:
            valid = self._hasher.verify(self.encoded_hash, password)
        except VerifyMismatchError:
            valid = False
        if valid:
            self.failed_attempts = 0
            self.touch()
            return True
        self.failed_attempts += 1
        if self.failed_attempts >= 5:
            self.locked_until = now + min(300, 2 ** self.failed_attempts)
        return False

    def touch(self) -> None:
        self.last_activity = time.monotonic()

    def expired(self) -> bool:
        return time.monotonic() - self.last_activity > self.timeout_seconds
