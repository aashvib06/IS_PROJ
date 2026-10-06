# CipherChat

An educational prototype for attack-aware encrypted messaging: protocol violations
become privacy-preserving, hash-chained incident evidence and drive an explicit,
bounded recovery state machine.

## Run

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pytest
python -m cipherchat.main
# Reproducible security-property evaluation and structured logs
python -m cipherchat.security.evaluation
# Local teaching UI (open http://127.0.0.1:8000)
python -m cipherchat.ui.server
```

The evaluation writes `security_test_results/SECURITY_TEST_REPORT.md` and a
machine-readable `security_test_results/security_evaluation.jsonl` containing
one interpreted result per tested security property. No plaintext or key
material is included in that log.

See [UI_OBSERVATION_GUIDE.md](UI_OBSERVATION_GUIDE.md) for the local
cryptographic observation interface and its demonstration-mode boundaries.

## Design

The cryptographic path is **X25519 ECDH → HKDF-SHA-256 → AES-256-GCM**. Each
message has an unpredictable UUID, a strict monotonically increasing sequence
number, a fresh random 96-bit GCM nonce, and canonical JSON AAD over the
protocol version, session ID, sender ID, message ID, and sequence number.
Receivers reject a sequence at or below the highest accepted sequence; this is
a deliberately simple in-order policy. A production transport may use a
bounded sliding window for out-of-order delivery.

Public key material is deliberately unauthenticated in this phase. Basic ECDH
without authenticated identity verification is vulnerable to active
man-in-the-middle attacks. An authentication failure establishes only a
cryptographic verification failure; it is not proof of a MITM attack.

Evidence excludes plaintext, private keys, session keys, and raw shared
secrets. SHA-256 chaining detects modifications and reordering relative to the
stored chain. It does not prove authorship or protect against an attacker who
can rewrite both the records and the trusted chain reference.

Recovery only permits:

`SECURE → SUSPECTED_ATTACK → QUARANTINED → VERIFYING → REKEYING → SECURE`

Verification can instead lead to `BLOCKED`. There is no automatic retry loop;
fresh ECDH material is required before resuming after rekeying.
