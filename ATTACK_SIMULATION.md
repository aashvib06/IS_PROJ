# CipherChat Attack Simulation

This is a controlled local experiment layer. It exercises existing CipherChat
objects directly; it adds no networking, UI, database, or cryptographic
primitives.

Run all scenarios:

```bash
python -m cipherchat.security.simulator
```

## Architecture

```text
Attack generator
  → CipherChat protocol/key verification
  → detection and classification
  → EvidenceLog record and checkpoint verification
  → RecoveryMachine
  → rekey to SECURE, or BLOCKED
```

`AttackSimulator` exposes individual scenario methods and `run_all()`. Every
attempt returns a machine-readable `AttackResult`; `SimulationMetrics` derives
the reported totals from those results.

## Scenarios

### Replay

A valid Alice message is delivered normally, then delivered again to the real
receiver. Its sequence/message-ID checks raise `ReplayError`. The simulator
records evidence, validates the checkpoint, drives recovery, rekeys both local
session managers, and confirms old session objects are inactive.

### Tampering

The simulator modifies one legitimate message field at a time: `ciphertext`,
`nonce`, `sequence_number`, `message_id`, `session_id`, or `sender_id`. Payload
and AAD changes fail AES-GCM; session/sender changes fail receiver binding.
Each rejection creates actual evidence and enters bounded recovery.

### Key substitution

Mallory's public key is offered where Alice expects Bob's pinned X25519 key.
`SessionManager.establish` uses the existing pin check before ECDH, rejects the
key, records `KEY_SUBSTITUTION` evidence, and takes the failed-verification
path to `BLOCKED` without automatic rekeying.

This detects departure from a trusted pin. It does not claim complete MITM
prevention: safe key provisioning remains outside this prototype.

## Metrics

The simulator reports total, detected, and missed attacks; replay, tampering,
and substitution counts; evidence records; successful recoveries; blocked
sessions; rekeys; detection rate; and recovery success rate. The default run
has eight attempts: one replay, six tampering variants, and one substitution.
Cryptographic values are random, but scenario outcomes and metric counts are
repeatable.

## Limitations

This is not a penetration test or real-world attack framework. It does not
transport messages, discover systems, or exploit vulnerabilities. It retains
the core system's strict ordering, pinned-key assumptions, in-memory replay
cache, and requirement that evidence checkpoints be stored independently.
