from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from .hashing import hash_file
from .utils import atomic_write, b64d, b64e


def sign_bytes(data: bytes, private_key: ed25519.Ed25519PrivateKey) -> bytes:
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise ValueError("An Ed25519 private key is required")
    return private_key.sign(data)


def verify_bytes(data: bytes, signature: bytes, public_key: ed25519.Ed25519PublicKey) -> bool:
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise ValueError("An Ed25519 public key is required")
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False


def create_detached_signature(file_path: str | Path, private_key: ed25519.Ed25519PrivateKey, destination: str | Path, progress=None) -> None:
    digest = bytes.fromhex(hash_file(file_path, "SHA-512", progress))
    document = {
        "format": "CryptoVault Signature",
        "version": 1,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "filename": Path(file_path).name,
        "digest_algorithm": "SHA-512",
        "digest": digest.hex(),
        "signature": b64e(sign_bytes(digest, private_key)),
    }
    atomic_write(destination, json.dumps(document, indent=2).encode("utf-8"))


def verify_detached_signature(file_path: str | Path, signature_path: str | Path, public_key: ed25519.Ed25519PublicKey, progress=None) -> bool:
    document = json.loads(Path(signature_path).read_text(encoding="utf-8"))
    if document.get("format") != "CryptoVault Signature" or document.get("version") != 1:
        raise ValueError("Unsupported signature file")
    actual = bytes.fromhex(hash_file(file_path, document["digest_algorithm"], progress))
    recorded = bytes.fromhex(document["digest"])
    return __import__("hmac").compare_digest(actual, recorded) and verify_bytes(recorded, b64d(document["signature"]), public_key)
