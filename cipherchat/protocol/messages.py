"""Authenticated JSON protocol messages and strict replay protection."""
import base64
import json
from dataclasses import dataclass
from uuid import uuid4
from cipherchat.crypto.encryption import Ciphertext, decrypt, encrypt

PROTOCOL_VERSION = 1


class ProtocolError(Exception): pass
class ReplayError(ProtocolError): pass
class ValidationError(ProtocolError): pass
class SessionInactiveError(ProtocolError): pass


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (AttributeError, ValueError) as error:
        raise ValidationError(f"{field} is not canonical base64") from error


@dataclass(frozen=True)
class EncryptedMessage:
    protocol_version: int
    session_id: str
    sender_id: str
    message_id: str
    sequence_number: int
    nonce: bytes
    ciphertext: bytes

    def aad(self) -> bytes:
        """Canonical UTF-8 JSON over authenticated clear-text metadata."""
        meta = {"message_id": self.message_id, "protocol_version": self.protocol_version,
                "sender_id": self.sender_id, "sequence_number": self.sequence_number,
                "session_id": self.session_id}
        return json.dumps(meta, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_dict(self) -> dict[str, object]:
        return {"protocol_version": self.protocol_version, "session_id": self.session_id,
                "sender_id": self.sender_id, "message_id": self.message_id,
                "sequence_number": self.sequence_number, "nonce": _b64(self.nonce),
                "ciphertext": _b64(self.ciphertext)}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> "EncryptedMessage":
        try:
            value = json.loads(raw)
        except (TypeError, json.JSONDecodeError) as error:
            raise ValidationError("invalid JSON message") from error
        required = {"protocol_version", "session_id", "sender_id", "message_id", "sequence_number", "nonce", "ciphertext"}
        if not isinstance(value, dict) or set(value) != required:
            raise ValidationError("message fields do not match protocol schema")
        msg = cls(value["protocol_version"], value["session_id"], value["sender_id"], value["message_id"],
                  value["sequence_number"], _unb64(value["nonce"], "nonce"), _unb64(value["ciphertext"], "ciphertext"))
        msg.validate()
        return msg

    def validate(self) -> None:
        if self.protocol_version != PROTOCOL_VERSION or not all(isinstance(x, str) and x for x in (self.session_id, self.sender_id, self.message_id)):
            raise ValidationError("invalid protocol metadata")
        if isinstance(self.sequence_number, bool) or not isinstance(self.sequence_number, int) or self.sequence_number < 1:
            raise ValidationError("sequence_number must be a positive integer")
        if len(self.nonce) != 12 or len(self.ciphertext) < 16:
            raise ValidationError("invalid encrypted payload")


class SenderSession:
    def __init__(self, key: bytes, session_id: str, sender_id: str):
        self.key, self.session_id, self.sender_id, self._next_sequence = key, session_id, sender_id, 1
        self._active = True

    def invalidate(self) -> None:
        """Permanently disable this key/session object after rekeying."""
        self._active = False

    def encrypt(self, plaintext: str) -> EncryptedMessage:
        if not self._active:
            raise SessionInactiveError("session has been invalidated")
        if not isinstance(plaintext, str): raise TypeError("plaintext must be str")
        msg_id, seq = str(uuid4()), self._next_sequence
        provisional = EncryptedMessage(PROTOCOL_VERSION, self.session_id, self.sender_id, msg_id, seq, b"", b"")
        payload = encrypt(self.key, plaintext.encode("utf-8"), provisional.aad())
        self._next_sequence += 1
        return EncryptedMessage(PROTOCOL_VERSION, self.session_id, self.sender_id, msg_id, seq, payload.nonce, payload.data)


class ReceiverSession:
    """Strict in-order receiver. Production transports often need a sliding window."""
    def __init__(self, key: bytes, session_id: str, expected_sender_id: str):
        self.key, self.session_id, self.expected_sender_id, self.highest_sequence = key, session_id, expected_sender_id, 0
        self._seen_message_ids: set[str] = set()
        self._active = True

    def invalidate(self) -> None:
        """Permanently disable this key/session object after rekeying."""
        self._active = False

    def decrypt(self, message: EncryptedMessage) -> str:
        if not self._active:
            raise SessionInactiveError("session has been invalidated")
        message.validate()
        if message.session_id != self.session_id or message.sender_id != self.expected_sender_id:
            raise ValidationError("message session or sender does not match")
        if message.sequence_number <= self.highest_sequence:
            raise ReplayError("message sequence was already accepted")
        if message.message_id in self._seen_message_ids:
            raise ReplayError("message identifier was already accepted")
        plaintext = decrypt(self.key, Ciphertext(message.nonce, message.ciphertext), message.aad())
        self.highest_sequence = message.sequence_number
        self._seen_message_ids.add(message.message_id)
        return plaintext.decode("utf-8")
