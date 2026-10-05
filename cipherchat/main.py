"""Run with: python -m cipherchat.main"""
from dataclasses import replace
from uuid import uuid4
from cipherchat.crypto.identity import Identity
from cipherchat.crypto.key_exchange import public_key_bytes
from cipherchat.protocol.session import SessionManager
from cipherchat.security.attacks import classify_failure
from cipherchat.security.evidence import EvidenceLog, verify_evidence_chain
from cipherchat.security.recovery import RecoveryMachine

def main() -> None:
    print("=== CipherChat Security Demo ===\n")
    alice, bob = Identity.create("alice"), Identity.create("bob")
    print("[+] Alice identity created\n[+] Bob identity created")
    context, session_id = b"demo-session", str(uuid4())
    alice_sessions = SessionManager(alice, bob.identity_id, public_key_bytes(bob.public_key))
    bob_sessions = SessionManager(bob, alice.identity_id, public_key_bytes(alice.public_key))
    alice_sessions.establish(public_key_bytes(bob.public_key), session_id=session_id, context=context)
    bob_sessions.establish(public_key_bytes(alice.public_key), session_id=session_id, context=context)
    print("[+] ECDH session established\n[+] Session key derived")
    sender, receiver = alice_sessions.sender, bob_sessions.receiver
    assert sender is not None and receiver is not None
    evidence, recovery = EvidenceLog(), RecoveryMachine()
    message = sender.encrypt("Hello Bob")
    print("\nAlice → Bob:\n    " + receiver.decrypt(message))
    print("\n[+] Message authenticated and decrypted successfully")
    replay = message
    clean = sender.encrypt("integrity protected")
    tampered = replace(clean, ciphertext=b"x" + clean.ciphertext[1:])
    for label, received in (("Replay", replay), ("Tampering", tampered)):
        try:
            receiver.decrypt(received)
        except Exception as error:
            attack = classify_failure(error)
            evidence.record(session_id=session_id, attack_type=attack, description=f"{label}: {error}", message_id=received.message_id, sequence_number=received.sequence_number)
            print(f"\n[!] {label} detected\n    Classification: {attack.value}\n    Action: QUARANTINE")
    checkpoint = evidence.checkpoint()
    print(f"\n[+] Incident evidence recorded\n[+] Evidence chain valid: {verify_evidence_chain(evidence.records, checkpoint)}")
    recovery.report_violation(); recovery.begin_verification(); recovery.verification_succeeded()
    rekey_session_id, rekey_context = str(uuid4()), b"rekey-" + uuid4().bytes
    alice_sessions.rekey(public_key_bytes(bob.public_key), session_id=rekey_session_id, context=rekey_context)
    bob_sessions.rekey(public_key_bytes(alice.public_key), session_id=rekey_session_id, context=rekey_context)
    recovery.rekey_complete()
    print("[+] Fresh session installed; old session objects invalidated")
    print("\nRecovery:\n    " + "\n      ↓\n    ".join(item.value for item in recovery.history))

if __name__ == "__main__": main()
