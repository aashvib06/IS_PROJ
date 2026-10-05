"""X25519 key agreement. Private key material never leaves this module's API."""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey


def generate_private_key() -> X25519PrivateKey:
    return X25519PrivateKey.generate()


def public_key_bytes(public_key: X25519PublicKey) -> bytes:
    """Return the 32-byte public representation suitable for transmission."""
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def load_public_key(encoded: bytes) -> X25519PublicKey:
    if not isinstance(encoded, bytes) or len(encoded) != 32:
        raise ValueError("an X25519 public key must be exactly 32 bytes")
    return X25519PublicKey.from_public_bytes(encoded)


def derive_shared_secret(private_key: X25519PrivateKey, peer_public_key: X25519PublicKey) -> bytes:
    """Perform ECDH. Callers must feed the result into HKDF, never AES directly."""
    if not isinstance(private_key, X25519PrivateKey) or not isinstance(peer_public_key, X25519PublicKey):
        raise TypeError("X25519 private and public keys are required")
    return private_key.exchange(peer_public_key)
