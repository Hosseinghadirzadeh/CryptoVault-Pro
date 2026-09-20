import copy

import pytest

from cryptovault.core.container import decrypt_container, encrypt_bytes
from cryptovault.core.keys import generate_private_key
from cryptovault.errors import AuthenticationError, InvalidContainerError


@pytest.mark.parametrize("algorithm", ["AES-256-GCM", "ChaCha20-Poly1305"])
@pytest.mark.parametrize("kdf", ["Argon2id", "scrypt", "PBKDF2-SHA256"])
def test_password_round_trip(algorithm, kdf):
    container = encrypt_bytes(b"secret payload", algorithm=algorithm, protection="Password", password="correct horse battery staple", kdf=kdf)
    assert decrypt_container(container, password="correct horse battery staple").data == b"secret payload"


def test_wrong_password_is_rejected():
    container = encrypt_bytes(b"secret", password="a sufficiently long password")
    with pytest.raises(AuthenticationError):
        decrypt_container(container, password="wrong password")


def test_ciphertext_tamper_is_rejected():
    container = encrypt_bytes(b"secret", password="a sufficiently long password")
    tampered = copy.deepcopy(container)
    tampered["ciphertext"] = ("A" if tampered["ciphertext"][0] != "A" else "B") + tampered["ciphertext"][1:]
    with pytest.raises((InvalidContainerError, AuthenticationError)):
        decrypt_container(tampered, password="a sufficiently long password")


def test_protected_metadata_tamper_is_rejected():
    container = encrypt_bytes(b"secret", password="a sufficiently long password", filename="one.txt")
    container["content"]["filename"] = "two.txt"
    with pytest.raises(AuthenticationError):
        decrypt_container(container, password="a sufficiently long password")


def test_rsa_round_trip():
    private = generate_private_key("RSA-4096")
    container = encrypt_bytes(b"rsa", protection="RSA-4096", public_key=private.public_key())
    assert decrypt_container(container, private_key=private).data == b"rsa"


def test_x25519_round_trip():
    private = generate_private_key("X25519")
    container = encrypt_bytes(b"x25519", protection="X25519 ECDH", public_key=private.public_key())
    assert decrypt_container(container, private_key=private).data == b"x25519"

