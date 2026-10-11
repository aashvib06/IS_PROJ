"""Local identity keys for key agreement and digital signatures."""
from dataclasses import dataclass
from uuid import uuid4
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from .key_exchange import generate_private_key, public_key_bytes


@dataclass
class Identity:
    identity_id: str
    private_key: X25519PrivateKey
    signing_private_key: Ed25519PrivateKey

    @classmethod
    def create(cls, identity_id: str | None = None) -> "Identity":
        return cls(identity_id or str(uuid4()), generate_private_key(), Ed25519PrivateKey.generate())

    @property
    def public_key(self) -> X25519PublicKey:
        return self.private_key.public_key()

    @property
    def signing_public_key(self) -> Ed25519PublicKey:
        return self.signing_private_key.public_key()

    @property
    def signing_public_key_bytes(self) -> bytes:
        return self.signing_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def public_material(self) -> dict[str, str]:
        """The only identity material intended to be transmitted."""
        return {
            "identity_id": self.identity_id,
            "public_key": public_key_bytes(self.public_key).hex(),
            "signing_public_key": self.signing_public_key_bytes.hex(),
        }
