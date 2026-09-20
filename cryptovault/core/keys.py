from __future__ import annotations

import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, x25519

from .utils import atomic_write


PRIVATE_ENCRYPTION = serialization.BestAvailableEncryption


def generate_private_key(kind: str):
    if kind == "RSA-4096":
        return rsa.generate_private_key(public_exponent=65537, key_size=4096)
    if kind == "X25519":
        return x25519.X25519PrivateKey.generate()
    if kind == "Ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    raise ValueError(f"Unsupported key type: {kind}")


def save_private_key(key, path: str | Path, password: str) -> None:
    if not password:
        raise ValueError("A password is required to export a private key")
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        PRIVATE_ENCRYPTION(password.encode("utf-8")),
    )
    atomic_write(path, pem)


def save_public_key(key, path: str | Path) -> None:
    public = key.public_key() if hasattr(key, "public_key") else key
    pem = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    atomic_write(path, pem)


def load_private_key(path: str | Path, password: str | None = None):
    data = Path(path).read_bytes()
    return serialization.load_pem_private_key(data, password=password.encode("utf-8") if password else None)


def load_public_key(path: str | Path):
    return serialization.load_pem_public_key(Path(path).read_bytes())


def public_fingerprint(key) -> str:
    public = key.public_key() if hasattr(key, "public_key") else key
    der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def key_description(key) -> dict[str, str]:
    public = key.public_key() if hasattr(key, "public_key") else key
    if isinstance(public, rsa.RSAPublicKey):
        kind = f"RSA-{public.key_size}"
    elif isinstance(public, x25519.X25519PublicKey):
        kind = "X25519 (Curve25519 ECDH)"
    elif isinstance(public, ed25519.Ed25519PublicKey):
        kind = "Ed25519 signature"
    else:
        kind = type(public).__name__
    return {"type": kind, "fingerprint": public_fingerprint(public)}

