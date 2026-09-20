from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptovault.errors import AuthenticationError, InvalidContainerError, KeyMismatchError
from .passwords import derive_key
from .utils import atomic_write, b64d, b64e, canonical_json

MAGIC = "CryptoVault"
VERSION = 1
MAX_CONTAINER_BYTES = 1024 * 1024 * 1024  # defensive 1 GiB JSON-container limit
MAX_PLAINTEXT_BYTES = 700 * 1024 * 1024  # base64 and JSON overhead must fit above


@dataclass(frozen=True)
class DecryptionResult:
    data: bytes
    metadata: dict[str, Any]


def _aead(name: str, key: bytes):
    if name == "AES-256-GCM":
        return AESGCM(key)
    if name == "ChaCha20-Poly1305":
        return ChaCha20Poly1305(key)
    raise ValueError(f"Unsupported content cipher: {name}")


def _aad(header: dict[str, Any]) -> bytes:
    return canonical_json(header)


def encrypt_bytes(
    data: bytes,
    *,
    algorithm: str = "AES-256-GCM",
    protection: str = "Password",
    password: str | None = None,
    kdf: str = "Argon2id",
    public_key=None,
    filename: str | None = None,
    content_type: str = "binary",
) -> dict[str, Any]:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if len(data) > MAX_PLAINTEXT_BYTES:
        raise ValueError("Payload exceeds the 700 MiB safety limit of the JSON v1 format")
    session_key = os.urandom(32)
    protection_info: dict[str, Any] = {"type": protection}

    if protection == "Password":
        salt = os.urandom(16)
        wrapping_key, params = derive_key(password or "", salt, kdf)
        wrap_nonce = os.urandom(12)
        wrapped = AESGCM(wrapping_key).encrypt(wrap_nonce, session_key, b"CryptoVault session key v1")
        protection_info.update(kdf=kdf, salt=b64e(salt), parameters=params, wrap_nonce=b64e(wrap_nonce), encrypted_key=b64e(wrapped))
    elif protection == "RSA-4096":
        if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 4096:
            raise ValueError("A 4096-bit RSA public key is required")
        wrapped = public_key.encrypt(
            session_key,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=b"CryptoVault v1"),
        )
        protection_info["encrypted_key"] = b64e(wrapped)
    elif protection == "X25519 ECDH":
        if not isinstance(public_key, x25519.X25519PublicKey):
            raise ValueError("An X25519 public key is required")
        ephemeral = x25519.X25519PrivateKey.generate()
        shared = ephemeral.exchange(public_key)
        salt = os.urandom(16)
        wrapping_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"CryptoVault X25519 key wrap v1").derive(shared)
        wrap_nonce = os.urandom(12)
        wrapped = AESGCM(wrapping_key).encrypt(wrap_nonce, session_key, b"CryptoVault session key v1")
        ephemeral_raw = ephemeral.public_key().public_bytes_raw()
        protection_info.update(
            salt=b64e(salt), wrap_nonce=b64e(wrap_nonce), encrypted_key=b64e(wrapped), ephemeral_public_key=b64e(ephemeral_raw)
        )
    else:
        raise ValueError(f"Unsupported key protection: {protection}")

    nonce = os.urandom(12)
    header = {
        "format": MAGIC,
        "version": VERSION,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "algorithm": algorithm,
        "key_protection": protection_info,
        "content": {"type": content_type, "filename": Path(filename).name if filename else None, "size": len(data)},
    }
    sealed = _aead(algorithm, session_key).encrypt(nonce, data, _aad(header))
    ciphertext, tag = sealed[:-16], sealed[-16:]
    return {
        **header,
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
        "authentication_tag": b64e(tag),
        "hash": {"algorithm": "SHA-256", "ciphertext": hashlib.sha256(ciphertext).hexdigest()},
        "signature": None,
    }


def decrypt_container(container: dict[str, Any], *, password: str | None = None, private_key=None) -> DecryptionResult:
    try:
        if container.get("format") != MAGIC or container.get("version") != VERSION:
            raise InvalidContainerError("Not a supported CryptoVault v1 container")
        protection = container["key_protection"]
        algorithm = container["algorithm"]
        ciphertext = b64d(container["ciphertext"], field="ciphertext")
        tag = b64d(container["authentication_tag"], field="authentication_tag")
        nonce = b64d(container["nonce"], field="nonce")
        if len(nonce) != 12 or len(tag) != 16:
            raise InvalidContainerError("Invalid nonce or authentication tag length")
        expected_hash = container["hash"]["ciphertext"]
        if not __import__("hmac").compare_digest(hashlib.sha256(ciphertext).hexdigest(), expected_hash):
            raise InvalidContainerError("Ciphertext checksum mismatch; the file is corrupted")

        kind = protection["type"]
        wrapped = b64d(protection["encrypted_key"], field="encrypted_key")
        if kind == "Password":
            wrapping_key, _ = derive_key(password or "", b64d(protection["salt"], field="salt"), protection["kdf"], protection["parameters"])
            session_key = AESGCM(wrapping_key).decrypt(
                b64d(protection["wrap_nonce"], field="wrap_nonce"), wrapped, b"CryptoVault session key v1"
            )
        elif kind == "RSA-4096":
            if not hasattr(private_key, "decrypt"):
                raise KeyMismatchError("An RSA private key is required")
            session_key = private_key.decrypt(
                wrapped,
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=b"CryptoVault v1"),
            )
        elif kind == "X25519 ECDH":
            if not isinstance(private_key, x25519.X25519PrivateKey):
                raise KeyMismatchError("An X25519 private key is required")
            ephemeral = x25519.X25519PublicKey.from_public_bytes(b64d(protection["ephemeral_public_key"], field="ephemeral_public_key"))
            shared = private_key.exchange(ephemeral)
            wrapping_key = HKDF(
                algorithm=hashes.SHA256(), length=32, salt=b64d(protection["salt"], field="salt"), info=b"CryptoVault X25519 key wrap v1"
            ).derive(shared)
            session_key = AESGCM(wrapping_key).decrypt(
                b64d(protection["wrap_nonce"], field="wrap_nonce"), wrapped, b"CryptoVault session key v1"
            )
        else:
            raise InvalidContainerError(f"Unsupported key protection: {kind}")

        header = {key: container[key] for key in ("format", "version", "created_utc", "algorithm", "key_protection", "content")}
        data = _aead(algorithm, session_key).decrypt(nonce, ciphertext + tag, _aad(header))
        if len(data) != int(container["content"]["size"]):
            raise InvalidContainerError("Decrypted size does not match protected metadata")
        return DecryptionResult(data=data, metadata=container["content"])
    except (InvalidContainerError, KeyMismatchError):
        raise
    except (InvalidTag, ValueError, TypeError, KeyError, OverflowError) as exc:
        raise AuthenticationError("Authentication failed. The password/key is incorrect or the container was modified.") from exc


def dumps_container(container: dict[str, Any]) -> bytes:
    return json.dumps(container, indent=2, ensure_ascii=False).encode("utf-8")


def validate_container_checksum(container: dict[str, Any]) -> None:
    """Perform structural and transport-corruption checks without a secret key."""
    try:
        if container.get("format") != MAGIC or container.get("version") != VERSION:
            raise InvalidContainerError("Not a supported CryptoVault v1 container")
        ciphertext = b64d(container["ciphertext"], field="ciphertext")
        expected = container["hash"]["ciphertext"]
        if not __import__("hmac").compare_digest(hashlib.sha256(ciphertext).hexdigest(), expected):
            raise InvalidContainerError("Ciphertext checksum mismatch after writing")
        if len(b64d(container["nonce"], field="nonce")) != 12 or len(b64d(container["authentication_tag"], field="authentication_tag")) != 16:
            raise InvalidContainerError("Invalid nonce or tag length")
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, InvalidContainerError):
            raise
        raise InvalidContainerError("Container structure is incomplete") from exc


def loads_container(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_CONTAINER_BYTES:
        raise InvalidContainerError("Container exceeds the 1 GiB safety limit")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidContainerError("This is not a valid CryptoVault JSON container") from exc
    if not isinstance(value, dict):
        raise InvalidContainerError("Container root must be an object")
    return value


def encrypt_file(source: str | Path, destination: str | Path, *, progress: Callable[[int], None] | None = None, **kwargs) -> None:
    source_path = Path(source)
    if progress:
        progress(10)
    data = source_path.read_bytes()
    if progress:
        progress(35)
    container = encrypt_bytes(data, filename=source_path.name, content_type="file", **kwargs)
    if progress:
        progress(80)
    atomic_write(destination, dumps_container(container))
    # Re-read and validate the serialized output to catch write/storage corruption.
    validate_container_checksum(loads_container(Path(destination).read_bytes()))
    if progress:
        progress(100)


def decrypt_file(source: str | Path, destination: str | Path, *, progress: Callable[[int], None] | None = None, **kwargs) -> dict[str, Any]:
    if progress:
        progress(15)
    container = loads_container(Path(source).read_bytes())
    if progress:
        progress(35)
    result = decrypt_container(container, **kwargs)
    if progress:
        progress(85)
    atomic_write(destination, result.data)
    if progress:
        progress(100)
    return result.metadata
