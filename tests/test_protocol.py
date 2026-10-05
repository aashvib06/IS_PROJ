from dataclasses import replace
import pytest
from cipherchat.crypto.encryption import AuthenticationError
from cipherchat.crypto.encryption import encrypt
from cipherchat.protocol.messages import EncryptedMessage, PROTOCOL_VERSION, ReceiverSession, ReplayError, SenderSession, SessionInactiveError

def test_message_roundtrip_replay_and_tampered_metadata():
    send, receive = SenderSession(b"a" * 32, "session", "alice"), ReceiverSession(b"a" * 32, "session", "alice")
    message = send.encrypt("hello")
    assert receive.decrypt(message) == "hello"
    with pytest.raises(ReplayError): receive.decrypt(message)
    altered = replace(send.encrypt("later"), sequence_number=77)
    with pytest.raises(AuthenticationError): receive.decrypt(altered)

def test_json_is_deterministic_and_validated():
    message = SenderSession(b"a" * 32, "session", "alice").encrypt("hello")
    assert message.from_json(message.to_json()) == message

def test_duplicate_message_id_is_rejected_independently_of_sequence():
    key = b"a" * 32
    sender, receiver = SenderSession(key, "session", "alice"), ReceiverSession(key, "session", "alice")
    first = sender.encrypt("first")
    assert receiver.decrypt(first) == "first"
    # This is a fully authenticated, forward-sequence message with a reused ID.
    draft = EncryptedMessage(PROTOCOL_VERSION, "session", "alice", first.message_id, 2, b"", b"")
    payload = encrypt(key, b"duplicate id", draft.aad())
    duplicate = EncryptedMessage(PROTOCOL_VERSION, "session", "alice", first.message_id, 2, payload.nonce, payload.data)
    with pytest.raises(ReplayError, match="identifier"):
        receiver.decrypt(duplicate)

def test_invalidated_sessions_fail_closed():
    sender, receiver = SenderSession(b"a" * 32, "session", "alice"), ReceiverSession(b"a" * 32, "session", "alice")
    message = sender.encrypt("hello")
    sender.invalidate(); receiver.invalidate()
    with pytest.raises(SessionInactiveError): sender.encrypt("after rekey")
    with pytest.raises(SessionInactiveError): receiver.decrypt(message)
