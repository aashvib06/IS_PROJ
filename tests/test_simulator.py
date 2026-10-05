import pytest

from cipherchat.security.attacks import AttackType
from cipherchat.security.recovery import RecoveryState
from cipherchat.security.simulator import AttackSimulator, TAMPER_FIELDS


def test_replay_simulation_uses_real_detection_evidence_recovery_and_rekey():
    result = AttackSimulator().simulate_replay()
    assert result.detected
    assert result.classification is AttackType.REPLAY
    assert result.evidence_generated and result.evidence_hash and result.checkpoint_valid
    assert result.recovery_state is RecoveryState.SECURE
    assert result.recovered and result.rekeyed and result.old_session_invalidated
    assert result.recovery_history == (
        RecoveryState.SECURE, RecoveryState.SUSPECTED_ATTACK, RecoveryState.QUARANTINED,
        RecoveryState.VERIFYING, RecoveryState.REKEYING, RecoveryState.SECURE,
    )


@pytest.mark.parametrize("field", TAMPER_FIELDS)
def test_tampering_simulations_reject_every_supported_field(field):
    result = AttackSimulator().simulate_tampering(field)
    assert result.attack_type is AttackType.TAMPERING
    assert result.detected
    assert result.classification in {AttackType.TAMPERING, AttackType.INVALID_AUTHENTICATION}
    assert result.evidence_generated and result.checkpoint_valid
    assert result.recovery_state is RecoveryState.SECURE
    assert result.rekeyed and result.old_session_invalidated


def test_key_substitution_simulation_blocks_and_records_real_evidence():
    result = AttackSimulator().simulate_key_substitution()
    assert result.detected
    assert result.classification is AttackType.KEY_SUBSTITUTION
    assert result.evidence_generated and result.checkpoint_valid
    assert result.recovery_state is RecoveryState.BLOCKED
    assert not result.recovered and not result.rekeyed


def test_metrics_match_the_simulated_events():
    report = AttackSimulator().run_all()
    metrics = report.metrics
    assert len(report.results) == 8
    assert metrics.total_attacks == 8
    assert metrics.attacks_detected == 8
    assert metrics.attacks_missed == 0
    assert metrics.replay_attacks == 1
    assert metrics.tampering_attacks == 6
    assert metrics.key_substitutions == 1
    assert metrics.evidence_records_generated == 8
    assert metrics.successful_recoveries == 7
    assert metrics.blocked_sessions == 1
    assert metrics.rekeys_performed == 7
    assert metrics.detection_rate == 1.0
    assert metrics.recovery_success_rate == 7 / 8
