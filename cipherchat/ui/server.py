"""Local-only HTTP server exposing CipherChat execution traces for the demo UI."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

from cipherchat.crypto.identity import Identity
from cipherchat.crypto.key_exchange import public_key_bytes
from cipherchat.protocol.session import SessionManager
from cipherchat.security.recovery import RecoveryState
from cipherchat.security.simulator import AttackSimulator, TamperField

STATIC_DIR = Path(__file__).with_name("static")


@dataclass(frozen=True)
class ObservationEvent:
    timestamp: str
    category: str
    step: str
    title: str
    data: dict[str, object]
    explanation: str


def _event(category: str, step: str, title: str, data: dict[str, object], explanation: str) -> ObservationEvent:
    return ObservationEvent(datetime.now(timezone.utc).isoformat(timespec="milliseconds"), category, step, title, data, explanation)


class DemonstrationController:
    """Stateful local demo facade; all cryptographic values originate in Python."""
    def __init__(self) -> None:
        self.alice: Identity | None = None
        self.bob: Identity | None = None
        self.alice_sessions: SessionManager | None = None
        self.bob_sessions: SessionManager | None = None
        self.session_id: str | None = None
        self.events: list[ObservationEvent] = []
        self.establish()

    def establish(self) -> dict[str, object]:
        self.alice, self.bob = Identity.create("alice"), Identity.create("bob")
        self.alice_sessions = SessionManager(self.alice, self.bob.identity_id, public_key_bytes(self.bob.public_key))
        self.bob_sessions = SessionManager(self.bob, self.alice.identity_id, public_key_bytes(self.alice.public_key))
        self.session_id = str(uuid4())
        context = b"cipherchat-ui-demo:" + self.session_id.encode()
        self.alice_sessions.establish(public_key_bytes(self.bob.public_key), session_id=self.session_id, context=context)
        self.bob_sessions.establish(public_key_bytes(self.alice.public_key), session_id=self.session_id, context=context)
        sender = self.alice_sessions.sender
        assert sender is not None
        self.events = [
            _event("SESSION", "01", "SESSION CREATED", {"session_id": self.session_id}, "A fresh local demonstration session is ready."),
            _event("KEY_EXCHANGE", "02", "X25519 COMPLETE", {
                "alice_public_key": public_key_bytes(self.alice.public_key).hex(),
                "bob_public_key": public_key_bytes(self.bob.public_key).hex(),
                "private_keys": "NOT DISPLAYED",
            }, "Public keys are exchanged; long-term private identity keys remain hidden."),
            _event("KDF", "03", "HKDF SESSION KEY DERIVED", {
                "algorithm": "HKDF-SHA-256", "domain": "cipherchat-v1",
                "session_key": sender.key.hex(), "label": "LOCAL DEMONSTRATION VALUE",
            }, "The ECDH output is processed by HKDF before use as an AES key."),
        ]
        return self.snapshot()

    def snapshot(self) -> dict[str, object]:
        sender = self.alice_sessions.sender if self.alice_sessions else None
        return {
            "demonstration_mode": True,
            "session": {
                "session_id": self.session_id, "key_exchange": "X25519", "kdf": "HKDF-SHA-256",
                "encryption": "AES-256-GCM", "session_key": sender.key.hex() if sender else None,
                "alice_public_key": public_key_bytes(self.alice.public_key).hex() if self.alice else None,
                "bob_public_key": public_key_bytes(self.bob.public_key).hex() if self.bob else None,
                "private_keys": "NOT DISPLAYED",
            },
            "events": [asdict(event) for event in self.events],
        }

    def send(self, plaintext: str) -> dict[str, object]:
        if not isinstance(plaintext, str) or not plaintext.strip():
            raise ValueError("message must not be empty")
        assert self.alice_sessions and self.bob_sessions
        sender, receiver = self.alice_sessions.sender, self.bob_sessions.receiver
        assert sender and receiver
        message = sender.encrypt(plaintext)
        aad = message.aad()
        accepted = receiver.decrypt(message)
        self.events.extend([
            _event("MESSAGE", "04", "MESSAGE CREATED", {"sender": "Alice", "recipient": "Bob", "plaintext": plaintext, "message_id": message.message_id, "sequence_number": message.sequence_number}, "A random UUID and monotonically increasing sequence identify this message."),
            _event("AAD", "05", "CANONICAL AAD CONSTRUCTED", {"aad_json": json.loads(aad), "aad_utf8": aad.decode("utf-8")}, "AAD authenticates routing and replay metadata without encrypting it."),
            _event("ENCRYPTION", "06", "AES-256-GCM ENCRYPTION", {"algorithm": "AES-256-GCM", "nonce": message.nonce.hex(), "ciphertext": message.ciphertext[:-16].hex(), "authentication_tag": message.ciphertext[-16:].hex(), "ciphertext_and_tag": message.ciphertext.hex(), "session_key": sender.key.hex(), "label": "LOCAL DEMONSTRATION VALUES"}, "A fresh nonce and the session key protect the plaintext and authenticate the AAD."),
            _event("TRANSMISSION", "07", "MESSAGE TRANSMITTED", {"raw_protocol_message": message.to_dict(), "raw_json": message.to_json()}, "The serialized protocol message carries metadata, nonce, and ciphertext."),
            _event("RECEPTION", "08", "BOB RECEIVED MESSAGE", {"session_id": message.session_id, "sender_id": message.sender_id}, "Bob passed the received object to the real protocol receiver."),
            _event("VALIDATION", "09", "REPLAY AND SESSION VALIDATION", {"session_valid": True, "sender_valid": True, "message_id": message.message_id, "sequence_number": message.sequence_number, "replay_result": "NOT PREVIOUSLY ACCEPTED"}, "The receiver checks its session binding and replay caches before accepting the message."),
            _event("DECRYPTION", "10", "AES-GCM AUTHENTICATION AND DECRYPTION", {"authentication": "VALID", "plaintext_recovered": accepted}, "The GCM tag authenticated the ciphertext and AAD before plaintext was returned."),
            _event("MESSAGE", "11", "MESSAGE ACCEPTED", {"message_id": message.message_id, "sequence_number": message.sequence_number}, "Bob accepted the authenticated, non-replayed message."),
        ])
        return {**self.snapshot(), "message": message.to_dict(), "plaintext": accepted}

    def attack(self, name: str) -> dict[str, object]:
        simulator = AttackSimulator()
        if name == "replay": result = simulator.simulate_replay()
        elif name == "key_substitution": result = simulator.simulate_key_substitution()
        elif name.startswith("tamper_"):
            field = name.removeprefix("tamper_")
            if field not in {"ciphertext", "nonce", "sequence_number", "message_id", "session_id", "sender_id"}:
                raise ValueError("unsupported tampering field")
            result = simulator.simulate_tampering(field)  # actual controlled attack simulator
        else:
            raise ValueError("unsupported attack")
        result_data = {
            "attack_type": result.attack_type.value, "classification": result.classification.value,
            "detected": result.detected, "session_id": result.session_id, "message_id": result.message_id,
            "sequence_number": result.sequence_number, "evidence_generated": result.evidence_generated,
            "evidence_hash": result.evidence_hash, "checkpoint_valid": result.checkpoint_valid,
            "recovery_state": result.recovery_state.value, "recovery_history": [state.value for state in result.recovery_history],
            "rekeyed": result.rekeyed, "old_session_invalidated": result.old_session_invalidated,
            "detail": result.detail,
        }
        self.events.extend([
            _event("ATTACK", "12", "ATTACKER INTERCEPTED", {"attack": result.attack_type.value, "detail": result.detail, "message_id": result.message_id, "sequence_number": result.sequence_number}, "A controlled local attack scenario ran through the existing backend simulator."),
            _event("VALIDATION", "13", "SECURITY VIOLATION DETECTED", {"classification": result.classification.value, "detected": result.detected}, "The displayed classification is produced by the protocol's actual failure path."),
            _event("EVIDENCE", "14", "INCIDENT EVIDENCE GENERATED", {"evidence_hash": result.evidence_hash, "checkpoint_valid": result.checkpoint_valid, "session_id": result.session_id, "message_id": result.message_id, "sequence_number": result.sequence_number}, "The simulator recorded a real hash-chained incident record and checked its trusted checkpoint."),
            _event("RECOVERY", "15", "RECOVERY STATE TRANSITIONS", {"history": [state.value for state in result.recovery_history], "current_state": result.recovery_state.value}, "The existing bounded recovery state machine determined the next state."),
            _event("REKEY", "16", "REKEY OR BLOCK RESULT", {"rekeyed": result.rekeyed, "old_session_invalidated": result.old_session_invalidated, "new_session_active": result.recovered, "state": result.recovery_state.value}, "Recoverable scenarios install a new session; key substitution remains blocked."),
        ])
        return {**self.snapshot(), "attack": result_data}


class _Handler(SimpleHTTPRequestHandler):
    controller = DemonstrationController()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/state":
            self._json(self.controller.snapshot()); return
        if parsed.path == "/api/reset":
            self._json(self.controller.establish()); return
        if parsed.path == "/":
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
            if parsed.path == "/api/send": response = self.controller.send(payload.get("message", ""))
            elif parsed.path == "/api/attack": response = self.controller.attack(payload.get("attack", ""))
            else: self.send_error(HTTPStatus.NOT_FOUND); return
            self._json(response)
        except (ValueError, json.JSONDecodeError) as error:
            self._json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)

    def _json(self, payload: dict[str, object], status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status); self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def translate_path(self, path: str) -> str:
        if path.startswith("/api/"): return str(STATIC_DIR / "index.html")
        return str(STATIC_DIR / path.lstrip("/"))


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 8000), _Handler)
    print("CipherChat local demonstration UI: http://127.0.0.1:8000")
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()


if __name__ == "__main__": main()
