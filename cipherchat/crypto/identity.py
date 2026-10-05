"""Minimal local identity abstraction.

Public-key exchange in this prototype is unauthenticated.  Basic ECDH without
authenticated identity verification is vulnerable to active MITM attacks.
"""
from dataclasses import dataclass
from uuid import uuid4
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from .key_exchange import generate_private_key, public_key_bytes


@dataclass
class Identity:
    identity_id: str
    private_key: X25519PrivateKey

    @classmethod
    def create(cls, identity_id: str | None = None) -> "Identity":
        return cls(identity_id or str(uuid4()), generate_private_key())

    @property
    def public_key(self) -> X25519PublicKey:
        return self.private_key.public_key()

    def public_material(self) -> dict[str, str]:
        """The only identity material intended to be transmitted."""
        return {"identity_id": self.identity_id, "public_key": public_key_bytes(self.public_key).hex()}
