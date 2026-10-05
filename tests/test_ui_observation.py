import base64

from cipherchat.ui.server import DemonstrationController


def test_normal_message_generates_actual_observation_events():
    controller = DemonstrationController()
    result = controller.send("Hello observation")
    names = [event["title"] for event in result["events"]]
    assert "MESSAGE CREATED" in names
    assert "CANONICAL AAD CONSTRUCTED" in names
    assert "AES-256-GCM ENCRYPTION" in names
    assert "AES-GCM AUTHENTICATION AND DECRYPTION" in names
    assert result["plaintext"] == "Hello observation"
    encryption = next(event for event in result["events"] if event["title"] == "AES-256-GCM ENCRYPTION")
    assert encryption["data"]["nonce"] == base64.b64decode(result["message"]["nonce"]).hex()


def test_attack_observations_use_simulator_evidence_and_recovery():
    controller = DemonstrationController()
    result = controller.attack("replay")
    attack = result["attack"]
    assert attack["detected"] and attack["classification"] == "REPLAY"
    assert attack["evidence_generated"] and attack["checkpoint_valid"]
    assert attack["rekeyed"] and attack["old_session_invalidated"]
    names = [event["title"] for event in result["events"]]
    assert "ATTACKER INTERCEPTED" in names
    assert "INCIDENT EVIDENCE GENERATED" in names
    assert "RECOVERY STATE TRANSITIONS" in names


def test_key_substitution_observation_shows_blocked_session():
    result = DemonstrationController().attack("key_substitution")
    assert result["attack"]["classification"] == "KEY_SUBSTITUTION"
    assert result["attack"]["recovery_state"] == "BLOCKED"
    assert not result["attack"]["rekeyed"]
