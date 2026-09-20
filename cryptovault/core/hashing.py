from __future__ import annotations

import hashlib
import hmac
from pathlib import Path

from blake3 import blake3

CHUNK_SIZE = 1024 * 1024


def new_hasher(algorithm: str):
    choices = {
        "SHA-256": hashlib.sha256,
        "SHA-512": hashlib.sha512,
        "SHA3-512": hashlib.sha3_512,
        "BLAKE3": blake3,
    }
    try:
        return choices[algorithm]()
    except KeyError as exc:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}") from exc


def hash_bytes(data: bytes, algorithm: str = "SHA-256") -> str:
    hasher = new_hasher(algorithm)
    hasher.update(data)
    return hasher.hexdigest()


def hash_file(path: str | Path, algorithm: str = "SHA-256", progress=None) -> str:
    source = Path(path)
    total = max(1, source.stat().st_size)
    processed = 0
    hasher = new_hasher(algorithm)
    with source.open("rb") as stream:
        while chunk := stream.read(CHUNK_SIZE):
            hasher.update(chunk)
            processed += len(chunk)
            if progress:
                progress(min(100, processed * 100 // total))
    return hasher.hexdigest()


def compare_digest(actual: str, expected: str) -> bool:
    return hmac.compare_digest(actual.strip().lower(), expected.strip().lower())

