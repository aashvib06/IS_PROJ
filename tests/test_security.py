from dataclasses import replace
import pytest
from cipherchat.security.attacks import AttackType, KeySubstitutionError, verify_expected_public_key
from cipherchat.crypto.identity import Identity
from cipherchat.crypto.key_exchange import public_key_bytes
from cipherchat.protocol.messages import SessionInactiveError, ValidationError
from cipherchat.protocol.session import SessionManager
from cipherchat.security.evidence import EvidenceLog, verify_evidence_chain
from cipherchat.security.recovery import InvalidTransition, RecoveryMachine, RecoveryState

def test_evidence_chain_detects_change_and_reordering():
    log = EvidenceLog()
    one = log.record(session_id="s", attack_type=AttackType.REPLAY, description="replayed", timestamp="2026-01-01T00:00:00+00:00")
    two = log.record(session_id="s", attack_type=AttackType.TAMPERING, description="tag failed", timestamp="2026-01-01T00:00:01+00:00")
    checkpoint = log.checkpoint()
    assert verify_evidence_chain(log.records, checkpoint)
    assert not verify_evidence_chain([replace(one, description="changed"), two], checkpoint)
    assert not verify_evidence_chain([two, one], checkpoint)
    assert not verify_evidence_chain([one], checkpoint)  # trusted tip catches tail deletion

def test_bounded_recovery_valid_and_invalid_paths():
    machine = RecoveryMachine()
    with pytest.raises(InvalidTransition): machine.transition(RecoveryState.REKEYING)
    machine.report_violation(); machine.begin_verification(); machine.verification_succeeded(); machine.rekey_complete()
    assert machine.state is RecoveryState.SECURE
    machine.report_violation(); machine.begin_verification(); machine.verification_failed()
    assert machine.state is RecoveryState.BLOCKED
    with pytest.raises(InvalidTransition): machine.transition(RecoveryState.SECURE)

def test_key_substitution_is_detected_against_a_pinned_public_key():
    verify_expected_public_key(b"expected", b"expected")
    with pytest.raises(KeySubstitutionError):
        verify_expected_public_key(b"expected", b"unexpected")

def test_session_establishment_verifies_pin_and_rekey_invalidates_old_sessions():
    alice, bob, attacker = Identity.create("alice"), Identity.create("bob"), Identity.create("mallory")
    alice_manager = SessionManager(alice, "bob", public_key_bytes(bob.public_key), bob.signing_public_key_bytes)
    bob_manager = SessionManager(bob, "alice", public_key_bytes(alice.public_key), alice.signing_public_key_bytes)
    with pytest.raises(KeySubstitutionError):
        alice_manager.establish(public_key_bytes(attacker.public_key), attacker.signing_public_key_bytes, session_id="one", context=b"one")
    with pytest.raises(KeySubstitutionError):
        alice_manager.establish(public_key_bytes(bob.public_key), attacker.signing_public_key_bytes, session_id="one", context=b"one")
    alice_manager.establish(public_key_bytes(bob.public_key), bob.signing_public_key_bytes, session_id="one", context=b"one")
    bob_manager.establish(public_key_bytes(alice.public_key), alice.signing_public_key_bytes, session_id="one", context=b"one")
    old_sender, old_receiver = alice_manager.sender, bob_manager.receiver
    assert old_sender is not None and old_receiver is not None
    old_message = old_sender.encrypt("before rekey")
    assert old_receiver.decrypt(old_message) == "before rekey"
    alice_manager.rekey(public_key_bytes(bob.public_key), bob.signing_public_key_bytes, session_id="two", context=b"two")
    bob_manager.rekey(public_key_bytes(alice.public_key), alice.signing_public_key_bytes, session_id="two", context=b"two")
    with pytest.raises(SessionInactiveError): old_sender.encrypt("must fail")
    with pytest.raises(SessionInactiveError): old_receiver.decrypt(old_message)
    assert alice_manager.sender is not None and bob_manager.receiver is not None
    with pytest.raises(ValidationError):
        bob_manager.receiver.decrypt(old_message)
    new_message = alice_manager.sender.encrypt("after rekey")
    assert bob_manager.receiver.decrypt(new_message) == "after rekey"
