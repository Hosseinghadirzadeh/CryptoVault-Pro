import pytest

from cryptovault.core.learning import caesar, substitution, vigenere, xor_cipher
from cryptovault.storage.archives import pack_folder, unpack_folder


def test_classical_examples():
    assert caesar("ABC xyz", 3)[0] == "DEF abc"
    assert vigenere("ATTACKATDAWN", "LEMON")[0] == "LXFOPVEFRNHR"
    assert xor_cipher("A", "K")[0] == "0a"
    assert substitution("abc", "QWERTYUIOPASDFGHJKLZXCVBNM")[0] == "qwe"


def test_folder_round_trip(tmp_path):
    source, destination = tmp_path / "source", tmp_path / "destination"
    source.mkdir(); (source / "nested").mkdir(); (source / "nested" / "file.bin").write_bytes(b"payload")
    unpack_folder(pack_folder(source), destination)
    assert (destination / "nested" / "file.bin").read_bytes() == b"payload"
