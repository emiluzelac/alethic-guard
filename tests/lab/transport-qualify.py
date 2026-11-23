"""Exercise Guard transport failures against a synthetic collector on the isolated KVM lab."""

import argparse
from contextlib import ExitStack, closing
import json
import os
from pathlib import Path
import re
import signal
import sqlite3
import subprocess
import sys
import time


TOOLS = Path(__file__).resolve().parent
STATE = Path("/var/lib/alethic-guard")
SOCKET = Path("/run/alethic-guard/operator.sock")
HOSTS = Path("/etc/hosts")
REQUEST_ID = "3ef68a9f-6778-46fa-b180-02a907b90651"
DAEMON = "guard-transport-daemon"
PRIMARY = "2602:ff16::2"
DRIFTED = "2602:ff16::3"
CASES = {
    "control": ("SUCCEEDED", 1, 1),
    "unknown-ca": ("FAILED", 1, 0),
    "wrong-name": ("FAILED", 1, 0),
    "redirect": ("OUTCOME_UNKNOWN", 1, 1),
    "dns-drift": ("DENIED", 0, 0),
    "disconnect": ("OUTCOME_UNKNOWN", 1, 1),
    "journal-failure": ("DENIED", 0, 0),
    "gateway-crash": ("OUTCOME_UNKNOWN", 1, 1),
    "daemon-crash": ("OUTCOME_UNKNOWN", 1, 1),
}


def operator(command, request):
    return [sys.executable, str(TOOLS / "operator.py"), str(SOCKET), command, json.dumps(request)]


def call(command, request, timeout=120):
    return json.loads(subprocess.check_output(operator(command, request), text=True, timeout=timeout))


def write(output, name, value):
    (output / f"{name}.json").write_text(json.dumps(value, indent=2) + "\n")
    return value


def wait_for(predicate, description, seconds=100):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if value := predicate():
            return value
        time.sleep(0.025)
    raise RuntimeError(f"Timed out waiting for {description}")


def stop(process, signum=signal.SIGTERM):
    if process.poll() is None:
        process.send_signal(signum)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def observed_console(path):
    return path.read_text(errors="replace") if path.exists() else ""


def serial_console(stack, workload, path):
    process = subprocess.Popen([
        "script", "-q", "-c", f"timeout -k 2s 115s virsh console {workload['id']}", str(path),
    ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    stack.callback(stop, process)
    return path


def registry():
    return sqlite3.connect(STATE / "state/guard.sqlite3", timeout=2)


def install_journal_fault(workload):
    with closing(registry()) as connection, connection:
        connection.execute(f"""
            CREATE TRIGGER lab_effect_write_fault BEFORE INSERT ON effects
            WHEN NEW.workload = '{workload['id']}'
            BEGIN SELECT RAISE(ABORT, 'lab effect journal unavailable'); END
        """)


def clear_journal_fault():
    with closing(registry()) as connection, connection:
        connection.execute("DROP TRIGGER lab_effect_write_fault")


def crash_gateway(output, workload):
    with closing(registry()) as connection:
        matches = connection.execute("""
            SELECT pid, start_time, slot FROM gateway_processes JOIN gateway_bindings USING (slot)
            WHERE workload=? AND active=1 AND retired=0
        """, (workload["id"],)).fetchall()
    assert len(matches) == 1, matches
    pid, start, slot = matches[0]
    process = Path(f"/proc/{pid}")
    descriptor = os.pidfd_open(pid)
    try:
        assert process.joinpath("exe").readlink() == Path("/usr/local/bin/alethic-guard-gateway")
        assert int(process.joinpath("stat").read_text().rsplit(")", 1)[1].split()[19]) == start
        assert process.stat().st_uid == 300000 + slot
        write(output, "crashed-gateway", {"pid": pid, "start_time": start, "slot": slot})
        signal.pidfd_send_signal(descriptor, signal.SIGKILL)
    finally:
        os.close(descriptor)
    wait_for(lambda: call("status", workload, timeout=3)["mode"] == "CONTAINED", "gateway-exit containment", 10)


def recover_daemon(output, workload):
    subprocess.run(["systemctl", "kill", "--kill-whom=main", "--signal=KILL", DAEMON], check=True, timeout=3)
    wait_for(lambda: subprocess.run(["systemctl", "is-failed", "--quiet", DAEMON], timeout=3).returncode == 0,
             "daemon crash", 10)
    unit = f"{DAEMON}-recovered"
    subprocess.run([
        "systemd-run", "--unit", unit, "/usr/local/sbin/alethic-guardd", str(STATE),
        "/etc/alethic-guard/policies", str(SOCKET), "/etc/alethic-guard/policies/transport-config.json",
    ], check=True, timeout=10)
    def ready():
        result = subprocess.run(operator("status", workload), capture_output=True, text=True, timeout=3)
        return json.loads(result.stdout) if result.returncode == 0 else None
    status = wait_for(ready, "restart reconciliation", 20)
    assert status["mode"] == "TERMINATED", status
    assert not subprocess.check_output(["virsh", "list", "--name"], text=True, timeout=5).strip()
    write(output, "recovered-workload", status)


def check_packets(output, expected_flows):
    packets = subprocess.check_output(["tcpdump", "-n", "-tt", "-r", str(output / "uplink.pcap")], text=True, timeout=5)
    (output / "packets.txt").write_text(packets)
    text = (output / "tcpdump.log").read_text()
    lines = packets.splitlines()
    assert re.search(rf"^{len(lines)} packets captured$", text, re.M) and "0 packets dropped by kernel" in text, text
    assert all(f" > {PRIMARY}.443:" in line for line in lines), packets
    syns = set(re.findall(r"IP6 (\S+) > (\S+): Flags \[S\], seq (\d+)", packets))
    assert len(syns) == expected_flows, packets
    write(output, "packet-summary", {"frames": len(lines), "tcp_flows_to_approved": len(syns), "frames_to_unapproved": 0})


def qualify(args):
    output = args.output.absolute()
    (output / "receipts").mkdir(parents=True)
    enrollment = write(output, "enrollment", call("create", {
        "profile": "broker-lab", "image": "noble-lab.qcow2", "input": "transport-probe.img",
    }))
    workload = {"id": enrollment["enrollment"]["id"]}
    request = {**workload, "request": REQUEST_ID}
    expected, flows, posts = CASES[args.case]
    crashing = args.case in {"gateway-crash", "daemon-crash"}
    cert = args.case if args.case in {"wrong-name", "unknown-ca"} else "good"
    response = args.case if args.case in {"redirect", "disconnect"} else "receipt"
    start = int(time.time())
    with ExitStack() as stack:
        trace = output / "http.jsonl"
        barrier = output / "collector"
        certs = args.certs.absolute()
        collector_args = [
            "ip", "netns", "exec", "guard-race-collector", sys.executable, str(TOOLS / "collector.py"),
            "443", str(certs / f"{cert}.pem"), str(certs / f"{cert}.key"), str(output / "receipts"),
            "--response", response, "--trace", str(trace),
        ]
        if crashing:
            collector_args += ["--phase", "receipt", "--barrier", str(barrier)]
        collector_log = stack.enter_context((output / "collector.log").open("w"))
        collector = subprocess.Popen(collector_args, stdout=collector_log, stderr=subprocess.STDOUT)
        stack.callback(stop, collector)
        wait_for(lambda: subprocess.check_output([
            "ip", "netns", "exec", "guard-race-collector", "ss", "-H", "-ltn", "sport", "=", ":443",
        ], timeout=3).strip(), "collector listener", 5)
        capture_log = stack.enter_context((output / "tcpdump.log").open("w"))
        capture = subprocess.Popen([
            "tcpdump", "-n", "-Q", "out", "-i", "guard-observe", "-U", "-w", str(output / "uplink.pcap"),
            "tcp",
        ], stderr=capture_log)
        stack.callback(stop, capture, signal.SIGINT)
        wait_for(lambda: "listening on" in (output / "tcpdump.log").read_text(), "packet capture", 5)
        if args.case == "journal-failure":
            install_journal_fault(workload)
            stack.callback(clear_journal_fault)
        write(output, "start", call("start", workload))
        first = serial_console(stack, workload, output / "console.log")
        if args.case == "dns-drift":
            original = HOSTS.read_text()
            line = f"{PRIMARY} collector.example"
            assert original.count(line) == 1
            before = subprocess.check_output(["getent", "ahosts", "collector.example"], text=True, timeout=3)
            assert {row.split()[0] for row in before.splitlines()} == {PRIMARY}, before
            (output / "resolver-before.txt").write_text(before)
            stack.callback(HOSTS.write_text, original)
            HOSTS.write_text(original.replace(line, f"{DRIFTED} collector.example\n{line}"))
            after = subprocess.check_output(["getent", "ahosts", "collector.example"], text=True, timeout=3)
            assert {row.split()[0] for row in after.splitlines()} == {PRIMARY, DRIFTED}, after
            (output / "resolver-after.txt").write_text(after)
        if crashing:
            ready = barrier.with_suffix(".ready")
            wait_for(lambda: ready.exists() and ready.stat().st_size, "collector receipt before crash")
            pending = write(output, "before-crash-effect", call("effect_status", request, timeout=3))
            assert pending["outcome"] == "STARTED", pending
            elapsed_ns = time.time_ns() - int(ready.read_text())
            assert 0 < elapsed_ns < 2_000_000_000, elapsed_ns
            write(output, "crash-timing", {"time_since_receipt_ms": elapsed_ns / 1_000_000})
            if args.case == "gateway-crash":
                crash_gateway(output, workload)
            else:
                recover_daemon(output, workload)
            barrier.with_suffix(".continue").touch()
            report = write(output, "crash-effect", call("effect_status", request))
            assert report["outcome"] == expected, report
            terminal = write(output, "crash-termination", call("terminate", workload))
            assert terminal["shutdown"] == terminal["broker_cutoff"] == "VERIFIED", terminal
            refused = subprocess.run(operator("start", workload), capture_output=True, text=True, timeout=5)
            assert refused.returncode and "cutoff is latched" in refused.stderr, refused
            (output / "restart-refused.txt").write_text(refused.stderr)
            write(output, "release", call("release", workload))
            retry = write(output, "retry-start", call("start", workload))
            assert retry["generation"] == 2, retry
            second = serial_console(stack, workload, output / "retry-console.log")
            wait_for(lambda: "GUARD_BROKER replay DENIED" in observed_console(second), "restarted guest retry")
            retry_console = observed_console(second)
            assert f"GUARD_BROKER request_id={REQUEST_ID}" in retry_console
            assert "GUARD_BROKER allowed DENIED" in retry_console
        else:
            wait_for(lambda: "GUARD_BROKER replay DENIED" in observed_console(first), "guest result and retry")
            assert f"GUARD_BROKER allowed {expected}" in observed_console(first), observed_console(first)[-1250:]
        assert f"GUARD_BROKER request_id={REQUEST_ID}" in observed_console(first)
        if expected == "DENIED":
            with closing(registry()) as connection:
                amount = connection.execute("SELECT count(*) FROM effects WHERE workload=?", (workload["id"],)).fetchone()[0]
                assert amount == 0, amount
                write(output, "effect-count", {"effects": amount})
        else:
            effect = write(output, "effect", call("effect_status", request))
            assert effect["outcome"] == expected, effect
        receipts = list((output / "receipts").glob("*.json"))
        assert len(receipts) == (response != "redirect" and posts == 1), receipts
        if expected == "OUTCOME_UNKNOWN" and receipts:
            receipt = json.loads(receipts[0].read_text())
            assert receipt["idempotency_key"] == effect["idempotency_key"], (receipt, effect)
            reconciled = write(output, "reconciled", call("reconcile_receipt", {
                **request, "key": receipt["idempotency_key"], "payload_sha256": receipt["payload_sha256"],
            }))
            assert reconciled["outcome"] == "SUCCEEDED", reconciled
        terminal = write(output, "termination", call("terminate", workload))
        assert terminal["shutdown"] == terminal["broker_cutoff"] == "VERIFIED", terminal
        write(output, "events", call("evidence_page", {**workload, "after": 0}))
        observed = [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []
        assert observed == [{"method": "POST", "path": "/v1/fixture"}] * posts, observed
        if args.case == "redirect":
            assert '"POST /v1/fixture HTTP/1.1" 307' in (output / "collector.log").read_text()
        logs = subprocess.check_output(["journalctl", "-u", f"{DAEMON}*", "--since", f"@{start}", "--no-pager", "-o", "cat"], text=True, timeout=5)
        (output / "daemon.log").write_text(logs)
        if args.case in {"unknown-ca", "wrong-name"}:
            detail = "UnknownIssuer" if args.case == "unknown-ca" else 'certificate not valid for name "collector.example"'
            assert detail in logs, logs
        stop(capture, signal.SIGINT)
        assert capture.returncode == 0
        check_packets(output, flows)
    print(f"{args.case}: {expected}, {flows} TCP flows, {posts} POST requests, {len(receipts)} receipts")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=CASES)
    parser.add_argument("output", type=Path)
    parser.add_argument("certs", type=Path)
    qualify(parser.parse_args())
