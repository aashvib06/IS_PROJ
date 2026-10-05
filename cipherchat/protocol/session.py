"""Pinned-key session establishment and bounded session replacement."""
from dataclasses import dataclass
from uuid import uuid4

from cipherchat.crypto.identity import Identity
from cipherchat.crypto.kdf import derive_session_key
from cipherchat.crypto.key_exchange import derive_shared_secret, load_public_key, public_key_bytes
from cipherchat.security.attacks import verify_expected_public_key
from .messages import ReceiverSession, SenderSession


@dataclass(frozen=True)
class SessionInfo:
    """Non-secret description of an established session."""
    session_id: str
    context: bytes


class SessionManager:
    """Owns the active directional sessions for one peer relationship.

    The caller supplies a previously verified/pinned peer public key. Every
    establishment verifies the presented key before X25519 is performed.
    Rekeying invalidates existing session objects before installing a new pair.
    """
    def __init__(self, identity: Identity, peer_id: str, expected_peer_public_key: bytes):
        self.identity = identity
        self.peer_id = peer_id
        self.expected_peer_public_key = expected_peer_public_key
        self.sender: SenderSession | None = None
        self.receiver: ReceiverSession | None = None
        self.info: SessionInfo | None = None

    def establish(self, presented_peer_public_key: bytes, *, session_id: str, context: bytes) -> SessionInfo:
        verify_expected_public_key(self.expected_peer_public_key, presented_peer_public_key)
        peer_public_key = load_public_key(presented_peer_public_key)
        key = derive_session_key(derive_shared_secret(self.identity.private_key, peer_public_key), context=context)
        self.invalidate()
        self.sender = SenderSession(key, session_id, self.identity.identity_id)
        self.receiver = ReceiverSession(key, session_id, self.peer_id)
        self.info = SessionInfo(session_id=session_id, context=context)
        return self.info

    def rekey(self, presented_peer_public_key: bytes, *, context: bytes, session_id: str | None = None) -> SessionInfo:
        """Replace active sessions using a fresh session ID and HKDF context."""
        return self.establish(presented_peer_public_key, session_id=session_id or str(uuid4()), context=context)

    def invalidate(self) -> None:
        if self.sender is not None:
            self.sender.invalidate()
        if self.receiver is not None:
            self.receiver.invalidate()

    @property
    def public_key_bytes(self) -> bytes:
        return public_key_bytes(self.identity.public_key)
