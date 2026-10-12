"""AES-256-GCM authenticated encryption."""
import os
from dataclasses import dataclass
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_BYTES = 12


class AuthenticationError(Exception):
    """Raised when GCM authentication fails; callers must fail closed."""


@dataclass(frozen=True)
class Ciphertext:
    nonce: bytes
    data: bytes  # ciphertext with the 16-byte GCM tag appended by cryptography


def _validate_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes) -> Ciphertext:
    _validate_key(key)
    if not isinstance(plaintext, bytes) or not isinstance(associated_data, bytes):
        raise TypeError("plaintext and associated_data must be bytes")
    nonce = os.urandom(NONCE_BYTES)  # fresh nonce for every operation
    return Ciphertext(nonce=nonce, data=AESGCM(key).encrypt(nonce, plaintext, associated_data))


def decrypt(key: bytes, ciphertext: Ciphertext, associated_data: bytes) -> bytes:
    _validate_key(key)
    if not isinstance(ciphertext, Ciphertext) or len(ciphertext.nonce) != NONCE_BYTES:
        raise ValueError("invalid ciphertext envelope")
    try:
        return AESGCM(key).decrypt(ciphertext.nonce, ciphertext.data, associated_data)
    except InvalidTag as error:
        raise AuthenticationError("AES-GCM authentication failed") from error
