from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from .core.container import decrypt_file, encrypt_file
from .core.hashing import hash_file
from .core.keys import generate_private_key, load_private_key, load_public_key, save_private_key, save_public_key
from .core.signatures import create_detached_signature, verify_detached_signature


def _password(prompt: str) -> str:
    value = getpass.getpass(prompt)
    if not value:
        raise ValueError("Password cannot be empty")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cryptovault-cli", description="CryptoVault Pro command-line interface")
    commands = parser.add_subparsers(dest="command", required=True)
    encrypt = commands.add_parser("encrypt", help="Encrypt a file")
    encrypt.add_argument("source"); encrypt.add_argument("destination"); encrypt.add_argument("--algorithm", choices=["AES-256-GCM", "ChaCha20-Poly1305"], default="AES-256-GCM"); encrypt.add_argument("--kdf", choices=["Argon2id", "scrypt", "PBKDF2-SHA256"], default="Argon2id"); encrypt.add_argument("--public-key"); encrypt.add_argument("--protection", choices=["Password", "RSA-4096", "X25519 ECDH"], default="Password")
    decrypt = commands.add_parser("decrypt", help="Decrypt a file")
    decrypt.add_argument("source"); decrypt.add_argument("destination"); decrypt.add_argument("--private-key")
    digest = commands.add_parser("hash", help="Hash a file"); digest.add_argument("source"); digest.add_argument("--algorithm", choices=["SHA-256", "SHA-512", "SHA3-512", "BLAKE3"], default="SHA-256")
    keygen = commands.add_parser("keygen", help="Generate a PEM key pair"); keygen.add_argument("kind", choices=["RSA-4096", "X25519", "Ed25519"]); keygen.add_argument("private"); keygen.add_argument("public")
    sign = commands.add_parser("sign", help="Create an Ed25519 detached signature"); sign.add_argument("source"); sign.add_argument("private_key"); sign.add_argument("signature")
    verify = commands.add_parser("verify", help="Verify an Ed25519 detached signature"); verify.add_argument("source"); verify.add_argument("public_key"); verify.add_argument("signature")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "encrypt":
            kwargs = {"algorithm": args.algorithm, "protection": args.protection}
            if args.protection == "Password": kwargs.update(password=_password("Encryption password: "), kdf=args.kdf)
            else:
                if not args.public_key: raise ValueError("--public-key is required for asymmetric protection")
                kwargs["public_key"] = load_public_key(args.public_key)
            encrypt_file(args.source, args.destination, **kwargs)
        elif args.command == "decrypt":
            key = load_private_key(args.private_key, _password("Private-key password: ")) if args.private_key else None
            password = None if key else _password("Container password: ")
            decrypt_file(args.source, args.destination, password=password, private_key=key)
        elif args.command == "hash": print(hash_file(args.source, args.algorithm))
        elif args.command == "keygen":
            key = generate_private_key(args.kind); save_private_key(key, args.private, _password("Private-key export password: ")); save_public_key(key, args.public)
        elif args.command == "sign":
            key = load_private_key(args.private_key, _password("Private-key password: ")); create_detached_signature(args.source, key, args.signature)
        elif args.command == "verify":
            valid = verify_detached_signature(args.source, args.signature, load_public_key(args.public_key)); print("VALID" if valid else "INVALID"); return 0 if valid else 2
        return 0
    except Exception as exc:
        print(f"CryptoVault error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
