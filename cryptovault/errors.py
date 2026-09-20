class CryptoVaultError(Exception):
    """Base class for user-facing CryptoVault errors."""


class InvalidContainerError(CryptoVaultError):
    """The encrypted container is malformed, unsupported, or corrupted."""


class AuthenticationError(CryptoVaultError):
    """Authentication failed: the password/key is wrong or data was modified."""


class KeyMismatchError(CryptoVaultError):
    """The supplied key cannot unlock this container."""

