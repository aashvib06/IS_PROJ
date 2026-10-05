"""Privacy-preserving, tamper-evident incident record hash chain."""
import hashlib
import json
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from uuid import uuid4
from .attacks import AttackType

GENESIS_HASH = "0" * 64

@dataclass(frozen=True)
class IncidentEvidence:
    incident_id: str
    timestamp: str
    session_id: str
    attack_type: str
    message_id: str | None
    sequence_number: int | None
    description: str
    previous_evidence_hash: str
    evidence_hash: str

    def material(self) -> dict[str, object]:
        data = asdict(self); data.pop("evidence_hash")
        return data

@dataclass(frozen=True)
class EvidenceCheckpoint:
    """A chain tip and length retained independently from the evidence store."""
    record_count: int
    evidence_hash: str

def _hash(record: IncidentEvidence) -> str:
    return hashlib.sha256(json.dumps(record.material(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()

class EvidenceLog:
    def __init__(self) -> None: self.records: list[IncidentEvidence] = []

    def record(self, *, session_id: str, attack_type: AttackType, description: str, message_id: str | None = None, sequence_number: int | None = None, timestamp: str | None = None) -> IncidentEvidence:
        previous = self.records[-1].evidence_hash if self.records else GENESIS_HASH
        draft = IncidentEvidence(str(uuid4()), timestamp or datetime.now(timezone.utc).isoformat(), session_id, attack_type.value, message_id, sequence_number, description, previous, "")
        item = replace(draft, evidence_hash=_hash(draft))
        self.records.append(item)
        return item

    def checkpoint(self) -> EvidenceCheckpoint:
        """Export this value to trusted/independent storage to detect truncation."""
        tip = self.records[-1].evidence_hash if self.records else GENESIS_HASH
        return EvidenceCheckpoint(record_count=len(self.records), evidence_hash=tip)

def verify_evidence_chain(records: list[IncidentEvidence], checkpoint: EvidenceCheckpoint | None = None) -> bool:
    previous = GENESIS_HASH
    for record in records:
        if record.previous_evidence_hash != previous or record.evidence_hash != _hash(record): return False
        previous = record.evidence_hash
    if checkpoint is not None and (len(records) != checkpoint.record_count or previous != checkpoint.evidence_hash):
        return False
    return True
