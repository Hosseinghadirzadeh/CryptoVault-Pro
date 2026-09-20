# CryptoVault Pro

CryptoVault Pro is a cross-platform, local-first desktop application for authenticated file, folder, and text encryption. It demonstrates real cryptographic architecture while remaining useful as a portable encryption tool. Modern cryptography is provided exclusively by established libraries; AES, ChaCha20, RSA, X25519, Ed25519, hashing, and password KDFs are **not** reimplemented.

> **Security status:** this is a carefully designed educational application, not independently audited software. Do not treat it as a replacement for an audited enterprise key-management system, full-disk encryption, or a mounted encrypted filesystem.

## Highlights

- AES-256-GCM (default) and ChaCha20-Poly1305 authenticated encryption
- Password key wrapping with Argon2id, scrypt, or PBKDF2-HMAC-SHA256
- RSA-4096 OAEP-SHA256 and X25519 ECDH/HKDF session-key protection
- Encrypted text, arbitrary files, and ZIP64-packaged folders
- Encrypted PKCS#8 private-key export and public-key fingerprints
- Ed25519 detached file signatures
- SHA-256, SHA-512, SHA3-512, and BLAKE3 integrity tools
- Local operation history and CSV audit export (filenames only; no secrets)
- Optional Argon2id application lock with backoff after failed attempts
- Educational classical-cipher visualizer, clearly separated from secure tools
- GUI and command-line interfaces sharing one cryptographic engine

## Installation

Python 3.10 or newer is required.

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -e .
```

Run the desktop application:

```bash
cryptovault
# or
python -m cryptovault
```

Run the tests:

```bash
pip install pytest
pytest -q
```

## Quick user guide

### Password-encrypted file

1. Open **Encrypt → File**.
2. Select any source file and a destination ending in `.cvault`.
3. Keep AES-256-GCM and Password/Argon2id selected.
4. Use a long, unique passphrase and choose **Encrypt file**.
5. Verify recovery through **Decrypt → File / folder** before deleting or moving anything.

The original source is never removed. Decryption writes to a separate destination chosen by the user.

### Public-key encryption

1. In **Key Manager**, generate an RSA-4096 or X25519 pair. The private PEM must be protected by an export password.
2. Encrypt with the recipient's public PEM.
3. The recipient decrypts using the matching private PEM and its password.

For X25519, CryptoVault generates a new ephemeral X25519 key for each package, derives a wrapping key with HKDF-SHA256, and wraps a random content-encryption key with AES-GCM.

### Signatures

Generate an Ed25519 pair, then use **Signatures → Sign** to create a detached `.cvsig` file. A recipient verifies the original file, signature file, and public key together. A valid signature establishes possession of the matching private key and integrity of the signed digest; it does not independently establish the real-world identity of the signer.

### Folders and vaults

Folders are packaged as ZIP64 and encrypted as a single authenticated container. Extraction validates every archive path before writing. A vault is a portable encrypted archive—not a mounted filesystem. Plaintext exists at the restoration location while the vault is open.

## Cryptographic architecture

```text
plaintext
   │
   ├── random 256-bit session key ──► AES-256-GCM / ChaCha20-Poly1305
   │                                      │
   │                                      └── ciphertext + 128-bit tag
   │
   └── key protection
         ├── password ─► Argon2id/scrypt/PBKDF2 ─► AES-GCM key wrap
         ├── RSA-4096 public key ─► OAEP-SHA256
         └── ephemeral X25519 ECDH ─► HKDF-SHA256 ─► AES-GCM key wrap
```

Every encryption creates a fresh session key and nonce using the operating system's cryptographically secure random generator. Protected container metadata is supplied as AEAD associated data, so changes to the algorithm, key-protection fields, original name, content type, or size cause authentication failure. A SHA-256 ciphertext checksum provides an early corruption diagnostic; the AEAD tag is the actual cryptographic integrity control.

### `.cvault` v1 format

The current portable format is UTF-8 JSON:

```json
{
  "format": "CryptoVault",
  "version": 1,
  "created_utc": "...",
  "algorithm": "AES-256-GCM",
  "key_protection": {
    "type": "Password",
    "kdf": "Argon2id",
    "salt": "base64...",
    "parameters": {},
    "wrap_nonce": "base64...",
    "encrypted_key": "base64..."
  },
  "content": {"type": "file", "filename": "example.pdf", "size": 1234},
  "nonce": "base64...",
  "ciphertext": "base64...",
  "authentication_tag": "base64...",
  "hash": {"algorithm": "SHA-256", "ciphertext": "hex..."},
  "signature": null
}
```

The outer `signature` field is reserved for a future signed-container profile. Current signatures are deliberately detached `.cvsig` files.

## Project architecture

```text
cryptovault/
├── core/       container crypto, KDFs, keys, hashing, signatures, learning tools
├── gui/        PySide6 pages, theme, background workers
├── security/   local session lock and failed-attempt backoff
├── storage/    folder archives and non-secret operation history
├── app.py      desktop entry point
└── cli.py      command-line entry point
tests/          cryptographic round-trip, tamper, key, signature, and archive tests
```

The core has no GUI dependencies. This makes its security-sensitive behavior directly testable and allows the GUI and CLI to share exactly the same implementation.

## CLI examples

Passwords are read through a hidden terminal prompt and are never accepted as command-line arguments.

```bash
cryptovault-cli encrypt report.pdf report.cvault
cryptovault-cli decrypt report.cvault restored-report.pdf
cryptovault-cli keygen X25519 private.pem public.pem
cryptovault-cli encrypt secrets.zip secrets.cvault --protection "X25519 ECDH" --public-key public.pem
cryptovault-cli hash archive.zip --algorithm BLAKE3
cryptovault-cli keygen Ed25519 signing-private.pem signing-public.pem
cryptovault-cli sign release.zip signing-private.pem release.cvsig
cryptovault-cli verify release.zip signing-public.pem release.cvsig
```

## Threat model

CryptoVault is designed to protect data at rest and in transit when an attacker obtains an encrypted package but not the password/private key. It detects package tampering and accidental corruption, and detached signatures authenticate content relative to a trusted public key.

It does **not** protect against:

- malware, keyloggers, screen capture, or a compromised operating system;
- attackers who can read plaintext while it is open;
- weak/reused passwords or exposed private keys;
- traffic analysis, filenames present in protected metadata, or file-size leakage;
- rollback to an older valid container;
- deletion recovery, SSD wear-leveling, cloud version history, filesystem snapshots, swap, or hibernation;
- denial-of-service through deletion or replacement of encrypted files;
- untrusted public keys without an out-of-band fingerprint check.

## Security decisions and limitations

- **Authenticated encryption only.** No unauthenticated CBC/CTR mode is offered.
- **No password storage.** Encryption passwords exist only for the operation. The optional app-lock stores an Argon2id verifier through platform application settings.
- **Encrypted private keys.** Export requires a password and uses the library's best available PKCS#8 encryption.
- **Failure messages.** Decryption deliberately combines wrong-key and authentication failures to avoid exposing useful distinctions.
- **Constant-time comparisons.** Digest/checksum comparisons use `hmac.compare_digest`; signature and AEAD verification use library primitives.
- **Original preservation.** Encryption and decryption never erase the source automatically.
- **Memory behavior.** `.cvault` v1 is a base64 JSON format and currently processes an encrypted payload in memory. It is suitable for ordinary documents and archives, but **not multi-gigabyte files**. A future binary chunked format is required for bounded-memory pause/resume encryption. The UI makes no false claim of secure GB-scale streaming.
- **Pause/resume.** Not implemented because safe resumability requires a versioned chunk-authentication scheme and carefully defined nonce allocation. Stopping an operation leaves the source untouched.
- **Vault mounting.** Not implemented. Portable encrypted folder archives are supported instead.
- **Hardware keys and key rotation.** The modular key layer is prepared for additional providers, but no PKCS#11/FIDO integration or automatic rewrap workflow ships in v1.
- **Twofish.** Not included because the selected `cryptography` AEAD API does not provide a modern standardized Twofish AEAD construction.
- **Audit required.** The application has unit tests but has not undergone third-party cryptographic or implementation audit.

## Development rules

- Never add home-grown cryptographic primitives.
- Never reuse a nonce with the same key.
- Preserve associated-data compatibility when changing the format; bump the container version for breaking changes.
- Treat decrypted filenames and archives as untrusted input.
- Add a tamper test for every new protected field.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and safe-use guidance.

