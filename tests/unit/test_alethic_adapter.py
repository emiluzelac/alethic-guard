from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest

from alethic_guard.alethic_adapter import AlethicAdapter, NormalizedAction, PolicySnapshot


def action():
    return NormalizedAction(
        workload_id=str(uuid4()), generation=1, policy_digest="sha256:" + "a" * 64,
        epoch=0, operation="collector.publish", target="https://collector.example/test",
        payload_sha256="a" * 64, data_labels=("public",), request_id=str(uuid4()),
        idempotency_key=str(uuid4()),
    )


def test_action_evidence_links_to_original_proposal(tmp_path: Path):
    proposal = action()
    adapter = AlethicAdapter(tmp_path / "kernel.sqlite3")
    decision = adapter.evaluate_action(proposal, PolicySnapshot(proposal.policy_digest, proposal.target))
    assert decision.ok
    assert decision.trace_id
    assert decision.proposal_id
    assert decision.action_id
    assert decision.evidence_id
    assert len({decision.proposal_id, decision.action_id, decision.evidence_id}) == 3
    assert adapter.store.get(decision.evidence_id).payload["proposal_id"] == decision.proposal_id
    assert adapter.store.get(decision.action_id).evidence_refs == [decision.evidence_id]


def test_untrusted_labels_or_target_do_not_govern(tmp_path: Path):
    proposal = action()
    adapter = AlethicAdapter(tmp_path / "kernel.sqlite3")
    snapshot = PolicySnapshot(proposal.policy_digest, proposal.target)
    for modified in (replace(proposal, data_labels=("sensitive",)),
                     replace(proposal, target="https://wrong.example/test")):
        decision = adapter.evaluate_action(modified, snapshot)
        assert not decision.ok
        assert decision.action_id is None
