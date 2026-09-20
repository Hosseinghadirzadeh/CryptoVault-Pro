# Security policy

## Reporting a vulnerability

Do not include real secrets, private keys, or sensitive encrypted material in a report. Provide a minimal reproduction with synthetic data, the CryptoVault version, operating system, Python version, and relevant dependency versions.

Until a vulnerability has been assessed, do not rely on the affected feature for sensitive data. This repository does not currently provide a private disclosure channel; for a production deployment, configure one before distributing the application.

## Safe use

- Keep multiple tested backups of encrypted data and private keys.
- Verify public-key fingerprints over an independent trusted channel.
- Use a password manager to generate unique high-entropy passphrases.
- Test decryption before removing any plaintext source.
- Keep Python, `cryptography`, PySide6, Argon2, and BLAKE3 dependencies updated.
- Use full-disk encryption and a patched operating system in addition to CryptoVault.

## Cryptographic dependencies

CryptoVault delegates primitives to `cryptography`, `argon2-cffi`, and `blake3`. Dependency advisories should be treated as application advisories. Lock and verify dependencies before packaging a release.

