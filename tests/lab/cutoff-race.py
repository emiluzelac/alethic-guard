"""Qualify emergency cutoff with the synthetic broker guest on the isolated lab host."""

import argparse
from contextlib import ExitStack
from decimal import Decimal
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import uuid


TOOLS = Path(__file__).resolve().parent
SOCKET = Path("/run/alethic-guard/operator.sock")
FIXTURE = {
    "profile": "broker-lab",
    "image": "noble-lab.qcow2",
    "input": "broker-probe.img",
}
IMAGE = "/var/lib/alethic-guard/images/noble-lab.qcow2"


def operator(command, data, emergency=False):
    path = SOCKET.with_suffix(".sock.emergency") if emergency else SOCKET
    return [sys.executable, str(TOOLS / "operator.py"), str(path), command, json.dumps(data)]


def call(command, data, emergency=False):
    return json.loads(subprocess.check_output(operator(command, data, emergency), text=True))


def record(output, name, result):
    (output / f"{name}.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def until(condition, seconds, description):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if result := condition():
            return result
        time.sleep(0.01)
    raise RuntimeError(f"timed out waiting for {description}")


def stop(process, signum):
    if process.poll() is not None:
        return
    process.send_signal(signum)
    try:
        process.wait(timeout=4)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def daemon_reading_image(pid):
    for path in Path(f"/proc/{pid}/fd").iterdir():
        try:
            target = path.readlink()
        except FileNotFoundError:
            continue
        if str(target) == IMAGE:
            return True
    return False


def verify_release_race(output, workload, daemon_pid):
    with subprocess.Popen(operator("release", workload), stderr=subprocess.PIPE, text=True) as release:
        until(lambda: daemon_reading_image(daemon_pid), 5, "ordinary release hashing")
        cutoff = record(output, "release-race-cutoff", call("cutoff", workload, emergency=True))
        assert cutoff["broker_cutoff"] == cutoff["admissions"] == "VERIFIED", cutoff
        assert release.poll() is None and daemon_reading_image(daemon_pid), "release completed before cutoff"
        _, error = release.communicate(timeout=120)
        (output / "release-race-refused.txt").write_text(error)
        assert release.returncode and "newer emergency cutoff" in error, error
    status = record(output, "release-race-status", call("status", workload))
    assert status["mode"] == "TERMINATED", status
    start = subprocess.run(operator("start", workload), capture_output=True, text=True)
    assert start.returncode and "cutoff is latched" in start.stderr, start.stderr
    released = record(output, "explicit-release", call("release", workload))
    assert released["mode"] == "READY", released


def qualify(args):
    output = args.output.absolute()
    receipts = output / "receipts"
    receipts.mkdir(parents=True)
    barrier = output / "collector"
    workload = {"id": str(args.id)}
    pcap = output / "uplink.pcap"
    backlog = None
    table = f"guard_lab_{os.getpid()}"
    with ExitStack() as stack:
        subprocess.run(["nft", "-f", "-"], input=f"""
table inet {table} {{
    chain host_output {{
        type filter hook output priority -15; policy accept;
        oifname "guard-observe" ip6 daddr 2602:ff16::2 tcp dport 443 tcp flags & rst == rst counter;
    }}
}}
""", text=True, check=True)
        stack.callback(subprocess.run, ["nft", "delete", "table", "inet", table], check=True)
        collector_log = stack.enter_context((output / "collector.log").open("w"))
        collector = subprocess.Popen([
            "ip", "netns", "exec", "guard-race-collector", sys.executable,
            str(TOOLS / "collector.py"), "443", str(args.cert.absolute()),
            str(args.key.absolute()), str(receipts), "--phase", args.phase,
            "--barrier", str(barrier),
        ], stdout=collector_log, stderr=subprocess.STDOUT)
        stack.callback(stop, collector, signal.SIGTERM)
        capture_log = stack.enter_context((output / "tcpdump.log").open("w"))
        capture = subprocess.Popen([
            "tcpdump", "-n", "-i", "guard-observe", "-Q", "out", "-U", "-w", str(pcap),
            "ip6 and host 2602:ff16::2 and tcp dst port 443",
        ], stderr=capture_log)
        stack.callback(stop, capture, signal.SIGINT)
        until(lambda: "listening on" in (output / "tcpdump.log").read_text(), 4, "capture")
        record(output, "start", call("start", workload))
        console_path = output / "console.log"
        console = subprocess.Popen([
            "script", "-q", "-c", f"timeout -k 2s 165s virsh console {args.id}", str(console_path),
        ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        stack.callback(stop, console, signal.SIGTERM)
        ready = barrier.with_suffix(".ready")
        until(lambda: ready.exists() and ready.stat().st_size, 140, "collector barrier")
        ready_at = int(ready.read_text())
        if args.phase == "handshake":
            backlog = subprocess.Popen(operator("create", FIXTURE), stdout=subprocess.PIPE, text=True)
            stack.callback(stop, backlog, signal.SIGTERM)
            until(lambda: daemon_reading_image(args.daemon_pid), 1, "ordinary enrollment hashing")
        start = time.monotonic()
        cutoff = record(output, "cutoff", call("cutoff", workload, emergency=True))
        elapsed = time.monotonic() - start
        pending = backlog is not None and backlog.poll() is None
        record(output, "timing", {
            "phase": args.phase, "collector_barrier_unix_ns": ready_at,
            "cutoff_rtt_seconds": elapsed, "normal_enrollment_pending": pending,
        })
        assert cutoff["broker_cutoff"] == cutoff["admissions"] == "VERIFIED", cutoff
        assert 0 < cutoff["observed_at_unix_ns"] - ready_at < 3_000_000_000, cutoff
        assert elapsed < 3, f"cutoff acknowledgment took {elapsed:.3f} seconds"
        if backlog is not None:
            assert pending and daemon_reading_image(args.daemon_pid), "ordinary hashing completed before cutoff"
        barrier.with_suffix(".continue").touch()
        if backlog is not None:
            enrolled, _ = backlog.communicate(timeout=120)
            assert backlog.returncode == 0, "queued enrollment failed"
            record(output, "parallel-enrollment", json.loads(enrolled))
        time.sleep(3.2)
        record(output, "contain", call("contain", workload))
        terminated = record(output, "terminate", call("terminate", workload))
        assert terminated["shutdown"] == terminated["broker_cutoff"] == "VERIFIED", terminated
        start_again = subprocess.run(operator("start", workload), capture_output=True, text=True)
        (output / "restart-refused.txt").write_text(start_again.stderr)
        assert start_again.returncode and "cutoff is latched" in start_again.stderr, start_again
        receipt_files = list(receipts.glob("*.json"))
        assert len(receipt_files) == (args.phase == "receipt"), receipt_files
        if args.phase == "receipt":
            request = {**workload, "request": re.search(
                r"GUARD_BROKER request_id=([0-9a-f-]{36})", console_path.read_text(errors="replace"),
            )[1]}
            receipt = json.loads(receipt_files[0].read_text())
            effect = record(output, "effect", call("effect_status", request))
            assert effect["outcome"] == "OUTCOME_UNKNOWN", effect
            assert effect["idempotency_key"] == receipt["idempotency_key"], effect
            result = record(output, "reconciled", call("reconcile_receipt", {
                **request, "key": receipt["idempotency_key"], "payload_sha256": receipt["payload_sha256"],
            }))
            assert result["outcome"] == "SUCCEEDED", result
        events = record(output, "evidence", call("evidence_page", {**workload, "after": 0}))
        assert events["events"], "empty evidence export"
        stop(capture, signal.SIGINT)
        assert capture.returncode == 0, (output / "tcpdump.log").read_text()
        assert re.search(r"^0 packets dropped by kernel$", (output / "tcpdump.log").read_text(), re.M)
        observed = json.loads(subprocess.check_output(["nft", "-j", "list", "table", "inet", table]))
        record(output, "host-output", observed)
        local_resets = next(
            expr["counter"]["packets"]
            for entry in observed["nftables"] if "rule" in entry
            for expr in entry["rule"]["expr"] if "counter" in expr
        )
    packets = subprocess.check_output(["tcpdump", "-n", "-tt", "-r", str(pcap)], text=True)
    (output / "packets.txt").write_text(packets)
    resets = sum(bool(re.search(r"Flags \[R\.?\].*length 0$", line)) for line in packets.splitlines())
    assert resets == local_resets, (resets, local_resets)
    forwarded = [line for line in packets.splitlines() if not re.search(r"Flags \[R\.?\].*length 0$", line)]
    times = [int(Decimal(line.split()[0]) * 1_000_000_000) for line in forwarded]
    pre = sum(timestamp < cutoff["observed_at_unix_ns"] for timestamp in times)
    post = len(times) - pre
    record(output, "packet-counts", {"before_cutoff": pre, "at_or_after_cutoff": post, "host_resets": local_resets})
    assert pre and not post, (pre, post)
    print(f"{args.phase}: {pre} forwarded packets before cutoff, {post} after, {len(receipt_files)} receipts")
    if args.phase == "handshake":
        verify_release_race(output, workload, args.daemon_pid)
        print("A release already hashing its image could not erase the newer cutoff")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("handshake", "receipt"))
    parser.add_argument("id", type=uuid.UUID)
    parser.add_argument("output", type=Path)
    parser.add_argument("cert", type=Path)
    parser.add_argument("key", type=Path)
    parser.add_argument("--daemon-pid", type=int)
    args = parser.parse_args()
    if args.phase == "handshake" and args.daemon_pid is None:
        parser.error("the handshake case requires --daemon-pid and a slow enrollment image")
    qualify(args)
