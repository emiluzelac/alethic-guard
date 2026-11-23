"""Measure shutdown on a dedicated qualification host with real KVM."""

from contextlib import ExitStack
import json
from math import ceil
from statistics import median
import subprocess
import sys
from time import monotonic

from recovery import call, observe, start_guard, stop


def create():
    return call("create", profile="offline-research", image="minimal.qcow2")["enrollment"]["id"]


def sample(id, neighbor):
    call("start", id=id)
    before = observe(id)
    assert before["domain"] and before["pids"], before
    moment = monotonic()
    try:
        report = call("terminate", id=id, emergency=True)
        ms = round((monotonic() - moment) * 1000, 3)
    except TimeoutError:
        report = {"shutdown": "TIMEOUT"}
        ms = None
    after = observe(id)
    if neighbor:
        assert observe(neighbor[0]) == neighbor[1]
    contained = call("terminate", id=id)
    assert contained["shutdown"] == "VERIFIED", contained
    call("release", id=id)
    return {"guard": report, "before": before, "after": after, "latency_ms": ms}


def measure(case, repeats):
    with ExitStack() as cleanup:
        neighbor = None
        if case == "concurrent":
            neighbor_id = create()
            call("start", id=neighbor_id)
            neighbor = neighbor_id, observe(neighbor_id)
            assert neighbor[1]["domain"] and neighbor[1]["pids"]
            cleanup.callback(call, "terminate", id=neighbor_id)
        if case == "cpu_contention":
            for _ in range(2):
                process = subprocess.Popen([sys.executable, "-c", "while True: pass"])
                cleanup.callback(stop, process)
        id = create()
        samples = [sample(id, neighbor) for _ in range(repeats)]
        good = [
            result["latency_ms"] for result in samples
            if result["guard"]["shutdown"] == "VERIFIED"
            and result["after"] == {"domain": False, "pids": []}
            and result["guard"]["admissions"] == "VERIFIED"
            and result["guard"]["broker_cutoff"] == "VERIFIED"
        ]
        good.sort()
        return {
            "case": case,
            "n": len(samples),
            "verified": len(good),
            "failed_or_unverified": len(samples) - len(good),
            "unknown": sum(result["guard"]["shutdown"] == "UNKNOWN" for result in samples),
            "timeouts": sum(result["guard"]["shutdown"] == "TIMEOUT" for result in samples),
            "over_5s": sum(latency > 5000 for latency in good),
            "median_ms": median(good) if good else None,
            "p95_ms": good[ceil(len(good) * .95) - 1] if good else None,
            "p99_ms": good[ceil(len(good) * .99) - 1] if good else None,
            "worst_ms": max(good) if good else None,
            "samples": samples,
        }


def main():
    repeats = int(sys.argv[1])
    with ExitStack() as cleanup:
        guard = start_guard()
        cleanup.callback(stop, guard)
        for case in ("idle", "concurrent", "cpu_contention"):
            report = measure(case, repeats)
            print(json.dumps(report), flush=True)
            assert report["verified"] == repeats and report["over_5s"] == 0, case


if __name__ == "__main__":
    main()
