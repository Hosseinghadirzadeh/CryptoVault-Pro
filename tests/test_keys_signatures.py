from cryptovault.core.keys import generate_private_key, load_private_key, load_public_key, save_private_key, save_public_key
from cryptovault.core.signatures import create_detached_signature, verify_detached_signature


def test_encrypted_private_key_round_trip(tmp_path):
    key = generate_private_key("X25519")
    private_path, public_path = tmp_path / "private.pem", tmp_path / "public.pem"
    save_private_key(key, private_path, "private key password")
    save_public_key(key, public_path)
    assert load_private_key(private_path, "private key password").private_bytes_raw() == key.private_bytes_raw()
    assert load_public_key(public_path).public_bytes_raw() == key.public_key().public_bytes_raw()


def test_signature_detects_file_change(tmp_path):
    key = generate_private_key("Ed25519")
    source, signature = tmp_path / "message.txt", tmp_path / "message.cvsig"
    source.write_text("authentic", encoding="utf-8")
    create_detached_signature(source, key, signature)
    assert verify_detached_signature(source, signature, key.public_key())
    source.write_text("modified", encoding="utf-8")
    assert not verify_detached_signature(source, signature, key.public_key())

