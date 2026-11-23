"""The controller's in-process Alethic integration."""

from dataclasses import dataclass, asdict
from pathlib import Path
from uuid import uuid4

from alethic import Kernel, SqliteStore, SymbolicValidator, ValidationResult


@dataclass(frozen=True)
class NormalizedAction:
    workload_id: str
    generation: int
    policy_digest: str
    epoch: int
    operation: str
    target: str
    payload_sha256: str
    data_labels: tuple[str, ...]
    request_id: str
    idempotency_key: str


@dataclass(frozen=True)
class PolicySnapshot:
    digest: str
    allowed_target: str


@dataclass(frozen=True)
class GovernanceDecision:
    ok: bool
    trace_id: str
    code: str
    proposal_id: str
    action_id: str | None = None
    evidence_id: str | None = None


class GuardPolicyValidator:
    validator_id = "guard_policy_snapshot"

    def __init__(self, snapshot: PolicySnapshot):
        self.snapshot = snapshot

    def validate_action(self, action, committed_beliefs, constraints, context):
        allowed = (
            action["policy_digest"] == self.snapshot.digest
            and action["operation"] == "collector.publish"
            and action["target"] == self.snapshot.allowed_target
            and action["data_labels"] == ["public"]
        )
        return ValidationResult(
            allowed,
            "OK" if allowed else "GUARD_POLICY_DENIED",
            "Action matched policy" if allowed else "Action outside the policy snapshot",
        )


class AlethicAdapter:
    def __init__(self, store_path: Path):
        self.store = SqliteStore(str(store_path))

    def evaluate_action(self, action: NormalizedAction, snapshot: PolicySnapshot) -> GovernanceDecision:
        # Each authorization attempt receives its own server-owned trace.
        # Bound validators consume only the already-loaded immutable policy.
        trace_id = str(uuid4())
        kernel = Kernel(
            store=self.store,
            action_validators=[SymbolicValidator(), GuardPolicyValidator(snapshot)],
        )
        payload = asdict(action)
        payload["data_labels"] = list(action.data_labels)
        proposal = kernel.write("planner", "actions", "PROPOSE", action.operation, payload, trace_id)
        decision = kernel.decide_action(proposal.id, trace_id)
        if not decision.ok:
            return GovernanceDecision(False, trace_id, decision.code, proposal.id)

        matches = [
            record for record in self.store.list_slot("actions")
            if record.prov.trace_id == trace_id and record.mode == "COMMIT"
        ]
        if len(matches) == 1 and len(matches[0].evidence_refs) == 1:
            record = matches[0]
            evidence = self.store.get(record.evidence_refs[0])
            if (
                evidence is not None and evidence.slot == "evidence" and evidence.mode == "COMMIT"
                and evidence.prov.trace_id == trace_id and evidence.payload.get("proposal_id") == proposal.id
                and record.payload == payload
            ):
                return GovernanceDecision(True, trace_id, decision.code, proposal.id, record.id, evidence.id)
        return GovernanceDecision(False, trace_id, "EVIDENCE_LINK_INVALID", proposal.id)
