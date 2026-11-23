import hashlib
import json
from pathlib import Path

import pytest

from alethic_guard.evidence import verify_file


def _event(sequence, prior):
    event = {"sequence": sequence, "workload_id": "6c9cf14a-8226-41ea-8fa6-311abf2f6b6d",
             "event_type": "TEST_EVENT", "prev_event_hash": prior, "event_hash": ""}
    event["event_hash"] = "sha256:" + hashlib.sha256(json.dumps(event, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return event


def test_checkpoint_detects_truncation(tmp_path: Path):
    first = _event(1, "")
    second = _event(2, first["event_hash"])
    event_path = tmp_path / "evidence.jsonl"
    event_path.write_text(json.dumps(first) + "\n" + json.dumps(second) + "\n")
    checkpoint = verify_file(event_path).checkpoint
    event_path.write_text(json.dumps(first) + "\n")
    with pytest.raises(ValueError, match="checkpoint"):
        verify_file(event_path, checkpoint)
    assert verify_file(event_path).coverage == "UNANCHORED"


def test_local_chain_detects_modified_event(tmp_path: Path):
    first = _event(1, "")
    first["event_type"] = "CHANGED"
    event_path = tmp_path / "evidence.jsonl"
    event_path.write_text(json.dumps(first) + "\n")
    with pytest.raises(ValueError, match="hash"):
        verify_file(event_path)
