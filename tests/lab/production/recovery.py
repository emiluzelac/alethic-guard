"""Run only in the dedicated, disposable production qualification environment."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import socket
import subprocess
from time import monotonic, sleep
from uuid import uuid4

DAEMON = os.environ.get("GUARD_DAEMON", "/opt/alethic-guard/current/bin/alethic-guardd")
SOCKET = Path("/run/alethic-guard/operator.sock")
STATE = Path("/var/lib/alethic-guard/state")


def request(command, *, emergency=False, **options):
    path = f"{SOCKET}.emergency" if emergency else str(SOCKET)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(35)
        channel.connect(path)
        channel.sendall(json.dumps({"command": command, **options}).encode() + b"\n")
        with channel.makefile("rb") as stream:
            return json.loads(stream.readline())


def call(command, **options):
    reply = request(command, **options)
    assert reply["ok"], reply
    return reply["result"]


def start_guard():
    process = subprocess.Popen([DAEMON])
    for _ in range(200):
        assert process.poll() is None
        try:
            reply = request("status", id=str(uuid4()))
        except (FileNotFoundError, ConnectionRefusedError):
            sleep(.05)
        else:
            assert reply["ok"], reply
            return process
    raise RuntimeError("Guard did not start")


def observe(id):
    domains = subprocess.check_output(["virsh", "-c", "qemu:///system", "list", "--all", "--uuid"], text=True)
    pids = []
    for path in Path("/proc").glob("[0-9]*/cmdline"):
        try:
            args = path.read_bytes().split(b"\x00")
        except FileNotFoundError:
            continue
        if args[0].endswith(b"/qemu-system-x86_64") and id.encode() in args:
            pids.append(int(path.parent.name))
    return {"domain": id in domains.splitlines(), "pids": pids}


def recover(id, expected):
    begin = monotonic()
    process = subprocess.run([DAEMON, "--recover", id], check=False, text=True, capture_output=True, timeout=20)
    observed = json.loads(process.stdout)
    assert all(observed[key] == value for key, value in expected.items()), observed
    assert (process.returncode == 0) == all(value == "VERIFIED" for value in expected.values())
    return {"response": observed, "ms": round((monotonic() - begin) * 1000, 3)}


def stop(process):
    if process.poll() is None:
        process.kill()
        process.wait(timeout=5)


def main():
    with ExitStack() as cleanup:
        guard = start_guard()
        cleanup.callback(stop, guard)
        target = call("create", profile="offline-research", image="noble-lab.qcow2")["enrollment"]["id"]
        neighbor = call("create", profile="offline-research", image="minimal.qcow2")["enrollment"]["id"]
        call("start", id=target)
        call("start", id=neighbor)
        live = observe(target)
        assert live["domain"] and live["pids"], live
        unrelated = observe(neighbor)
        assert unrelated["domain"] and unrelated["pids"], unrelated

        busy = subprocess.run([DAEMON, "--recover", target], check=False, text=True, capture_output=True, timeout=5)
        assert busy.returncode and "locked by a running daemon" in busy.stderr
        assert observe(target) == live
        stop(guard)
        assert observe(target) == live
        absent = {"domain": False, "pids": []}
        unknown = str(uuid4())
        result = subprocess.run([DAEMON, "--recover", unknown], check=False, text=True, capture_output=True, timeout=5)
        assert result.returncode and "unknown workload" in result.stderr
        assert not (STATE / "emergency" / unknown).exists()
        assert observe(target) == live
        expected = {key: "VERIFIED" for key in ("admissions", "broker_cutoff", "shutdown", "record")}
        first = recover(target, expected)
        assert observe(target) == absent
        assert observe(neighbor) == unrelated
        assert recover(target, expected)["response"] == first["response"]
        print(json.dumps({"case": "daemon_down", "before": live, "after": observe(target),
                          "neighbor_unchanged": True, "live_daemon_refused": True,
                          "unknown_workload_refused": True, **first}), flush=True)

        guard = start_guard()
        cleanup.callback(stop, guard)
        assert call("status", id=target)["mode"] == "TERMINATED"
        assert observe(target) == absent
        assert not request("start", id=target)["ok"]
        events = call("evidence_page", id=target, after=0)
        assert "HOST_RECOVERY_OBSERVED" in json.dumps(events)
        call("release", id=target)
        assert call("status", id=target)["mode"] == "READY"
        print(json.dumps({"case": "startup_reconciliation", "explicit_release_required": True}), flush=True)

        call("release", id=neighbor)
        call("start", id=neighbor)
        stop(guard)
        fence = STATE / "emergency"
        backup = STATE / "qualification-fence-snapshot"
        fence.rename(backup)
        try:
            fence.touch(mode=0o600)
            partial = recover(neighbor, {**expected, "admissions": "UNKNOWN"})
            assert observe(neighbor) == absent
        finally:
            fence.unlink()
            backup.rename(fence)
        guard = start_guard()
        cleanup.callback(stop, guard)
        assert not request("start", id=neighbor)["ok"]
        assert call("status", id=neighbor)["mode"] == "TERMINATED"
        print(json.dumps({"case": "fence_storage_unavailable", "after": observe(neighbor), **partial}), flush=True)


if __name__ == "__main__":
    main()
