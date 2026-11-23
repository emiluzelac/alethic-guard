"""Verify exported Guard evidence and independently retained checkpoints."""

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path


@dataclass(frozen=True)
class Verification:
    count: int
    checkpoint: dict
    coverage: str


def verify_file(path: Path, checkpoint: dict | None = None) -> Verification:
    previous = ""
    count = 0
    workload = None
    covered = False
    with path.open("rb") as source:
        while frame := source.readline(65_537):
            if len(frame) > 65_536 or not frame.endswith(b"\n"):
                raise ValueError("invalid evidence record length or delimiter")
            event = json.loads(frame)
            count += 1
            if workload is None:
                workload = event["workload_id"]
            if (
                event["workload_id"] != workload or event["sequence"] != count
                or event["prev_event_hash"] != previous
            ):
                raise ValueError("evidence sequence, workload, or prior hash differs")
            previous, event["event_hash"] = event["event_hash"], ""
            canonical = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
            if previous != "sha256:" + hashlib.sha256(canonical).hexdigest():
                raise ValueError("evidence hash differs")
            if checkpoint is not None and checkpoint["sequence"] == count:
                if checkpoint["workload_id"] != workload or checkpoint["event_hash"] != previous:
                    raise ValueError("evidence does not match checkpoint")
                covered = True
    if not count:
        raise ValueError("no evidence records")
    if checkpoint is not None and not covered:
        raise ValueError("evidence ends before the checkpoint")
    end = {"workload_id": workload, "sequence": count, "event_hash": previous}
    coverage = "UNANCHORED" if not covered else ("CHECKPOINT_HEAD" if checkpoint == end else "CHECKPOINT_PREFIX")
    return Verification(count, end, coverage)
