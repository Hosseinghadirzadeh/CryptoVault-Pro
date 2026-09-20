from __future__ import annotations

import secrets
import string


def caesar(text: str, shift: int) -> tuple[str, list[str]]:
    output, steps = [], []
    for char in text:
        if char.isascii() and char.isalpha():
            base = ord("A" if char.isupper() else "a")
            transformed = chr((ord(char) - base + shift) % 26 + base)
            steps.append(f"{char} → {transformed}  (+{shift % 26})")
            output.append(transformed)
        else:
            output.append(char)
    return "".join(output), steps


def vigenere(text: str, key: str, decrypt: bool = False) -> tuple[str, list[str]]:
    clean_key = "".join(c.upper() for c in key if c.isascii() and c.isalpha())
    if not clean_key:
        raise ValueError("Vigenère key must contain letters A-Z")
    output, steps, index = [], [], 0
    for char in text:
        if char.isascii() and char.isalpha():
            amount = ord(clean_key[index % len(clean_key)]) - ord("A")
            if decrypt:
                amount = -amount
            base = ord("A" if char.isupper() else "a")
            transformed = chr((ord(char) - base + amount) % 26 + base)
            steps.append(f"{char} + {clean_key[index % len(clean_key)]}({amount:+d}) → {transformed}")
            output.append(transformed)
            index += 1
        else:
            output.append(char)
    return "".join(output), steps


def xor_cipher(text: str, key: str) -> tuple[str, list[str]]:
    if not key:
        raise ValueError("XOR key cannot be empty")
    data, key_bytes = text.encode("utf-8"), key.encode("utf-8")
    transformed = bytes(byte ^ key_bytes[i % len(key_bytes)] for i, byte in enumerate(data))
    steps = [f"0x{byte:02x} XOR 0x{key_bytes[i % len(key_bytes)]:02x} = 0x{transformed[i]:02x}" for i, byte in enumerate(data[:100])]
    return transformed.hex(), steps


def substitution(text: str, alphabet: str) -> tuple[str, list[str]]:
    alphabet = alphabet.upper()
    if len(alphabet) != 26 or set(alphabet) != set(string.ascii_uppercase):
        raise ValueError("Substitution alphabet must contain each A-Z letter exactly once")
    mapping = dict(zip(string.ascii_uppercase, alphabet))
    output, steps = [], []
    for char in text:
        if char.upper() in mapping:
            mapped = mapping[char.upper()]
            mapped = mapped if char.isupper() else mapped.lower()
            steps.append(f"{char} → {mapped}")
            output.append(mapped)
        else:
            output.append(char)
    return "".join(output), steps


def random_substitution_alphabet() -> str:
    letters = list(string.ascii_uppercase)
    secrets.SystemRandom().shuffle(letters)
    return "".join(letters)

