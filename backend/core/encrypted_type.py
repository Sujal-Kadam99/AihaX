"""SQLAlchemy custom TypeDecorator for transparent AES-256-GCM column encryption."""

from sqlalchemy.types import TypeDecorator, String
from backend.core.encryption import encrypt_string, decrypt_string


class EncryptedText(TypeDecorator):
    """SQLAlchemy TypeDecorator that transparently encrypts strings on write

    and decrypts strings on read using AES-256-GCM authenticated encryption.
    """

    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        """Encrypt plaintext before binding to SQL statement."""
        if value is None:
            return None
        return encrypt_string(str(value))

    def process_result_value(self, value, dialect):
        """Decrypt ciphertext when fetching SQL result value."""
        if value is None:
            return None
        return decrypt_string(str(value))
