"""AES-256-GCM credential encryption with configurable master key via PBKDF2-HMAC-SHA256."""

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _derive_key(master_key: str | None = None) -> bytes:
    """Derive a 256-bit AES key using PBKDF2-HMAC-SHA256."""
    from backend.core.config import get_settings
    settings = get_settings()

    if master_key:
        salt = b"aihax-encryption-salt-v1"
        return hashlib.pbkdf2_hmac('sha256', master_key.encode(), salt, 100000)

    # Fallback — check AIHAX_MASTER_KEY env var
    key = os.environ.get("AIHAX_MASTER_KEY")
    if not key:
        if settings.environment in ("production", "cloud"):
            raise RuntimeError("AIHAX_MASTER_KEY environment variable is required in production")
        # Development fallback only
        return hashlib.sha256(b"aihax-dev-fallback-key-only").digest()

    salt = b"aihax-encryption-salt-v1"
    return hashlib.pbkdf2_hmac('sha256', key.encode(), salt, 100000)


def encrypt_data(data: dict[str, Any], master_key: str | None = None) -> str:
    """Encrypt a dictionary to a base64-encoded string."""
    plaintext_bytes = json.dumps(data).encode("utf-8")
    return encrypt_string(plaintext_bytes.decode("utf-8"), master_key)


def decrypt_data(encrypted: str, master_key: str | None = None) -> dict[str, Any]:
    """Decrypt a base64-encoded encrypted string back to a dictionary."""
    decrypted_str = decrypt_string(encrypted, master_key)
    return json.loads(decrypted_str)


def encrypt_string(plaintext: str, master_key: str | None = None) -> str:
    """Encrypt a string using AES-256-GCM with a unique 12-byte IV per call."""
    if plaintext is None:
        return None
    key = _derive_key(master_key)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # Unique cryptographically random IV
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


def decrypt_string(encrypted: str, master_key: str | None = None) -> str:
    """Decrypt a base64-encoded AES-256-GCM string. Fails safely on tampering."""
    if not encrypted:
        return encrypted
    try:
        key = _derive_key(master_key)
        aesgcm = AESGCM(key)
        raw = base64.b64decode(encrypted.encode("utf-8"))
        if len(raw) < 13:
            raise ValueError("Ciphertext too short")
        nonce, ciphertext = raw[:12], raw[12:]
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext_bytes.decode("utf-8")
    except Exception as e:
        raise ValueError(f"Decryption failed or authentication tag tampered: {str(e)}") from e


class CredentialVault:
    """Encrypted credential storage at ~/AihaX/config/vault.enc."""

    def __init__(self, config_path: str):
        self.vault_path = Path(config_path) / "vault.enc"
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)

    def save(self, data: dict[str, Any], master_key: str | None = None) -> None:
        encrypted = encrypt_data(data, master_key)
        self.vault_path.write_text(encrypted)

    def load(self, master_key: str | None = None) -> dict[str, Any]:
        if not self.vault_path.exists():
            return {}
        encrypted = self.vault_path.read_text()
        return decrypt_data(encrypted, master_key)

    def get(self, key: str, default: Optional[Any] = None, master_key: str | None = None) -> Any:
        data = self.load(master_key)
        return data.get(key, default)

    def set(self, key: str, value: Any, master_key: str | None = None) -> None:
        data = self.load(master_key)
        data[key] = value
        self.save(data, master_key)
