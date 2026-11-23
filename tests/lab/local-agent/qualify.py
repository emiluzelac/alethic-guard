"""Exercise the local model and emergency stop on a dedicated Guard lab."""

from contextlib import ExitStack
import hashlib
import http.client
import json
from pathlib import Path
import re
import signal
import socket
import ssl
import subprocess
import sys
import time

ROOT = Path("/var/lib/alethic-guard")
SOCKET = Path("/run/alethic-guard/operator.sock")
PYTHON = "/opt/alethic-guard/bin/python"
CLI = "/opt/alethic-guard/bin/alethic-guard"
FIT = ROOT / "images/noble-lab.qcow2"
CONFIG = "/etc/alethic-guard/policies/release-collector.json"
FIXTURE = {"profile": "broker-lab", "image": FIT.name, "input": "local-agent.img"}


def until(check, description, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if value := check():
            return value
        time.sleep(.02)
    raise RuntimeError(f"timed out waiting for {description}")


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def call(*arguments):
    return json.loads(subprocess.check_output(arguments, text=True, timeout=150))


def ordinary(command, params):
    return [PYTHON, "guard-operator.py", str(SOCKET), command, json.dumps(params)]


def workload(verb, id):
    return [CLI, "workload", verb, id]


def process_reading(pid):
    for fd in Path(f"/proc/{pid}/fd").iterdir():
        try:
            if fd.readlink() == FIT:
                return True
        except FileNotFoundError:
            continue
    return False


def qemu_pids(id):
    active = []
    for path in Path("/proc").glob("[0-9]*/cmdline"):
        try:
            fields = path.read_bytes().split(b"\x00")
        except FileNotFoundError:
            continue
        if fields[0].endswith(b"/qemu-system-x86_64") and id.encode() in fields:
            active.append(path.parent.name)
    return active


def verify_receipt(effect):
    tls = ssl.create_default_context(cafile="ca.pem")
    client = http.client.HTTPSConnection("collector.example", 8443, context=tls, timeout=3)
    stage = ROOT / "collector"
    token = (stage / "reader").read_text()
    try:
        client.request("GET", "/v1/release-evidence/" + effect["idempotency_key"],
                       headers={"Authorization": "Bearer " + token})
        response = client.getresponse()
        body = json.loads(response.read())
        assert response.status == 200 and body == {
            "idempotency_key": effect["idempotency_key"],
            "payload_sha256": hashlib.sha256(Path("approved-record.json").read_bytes()).hexdigest(),
        }
        assert effect["payload_sha256"] == body["payload_sha256"]
        return body
    finally:
        client.close()


def main(output):
    output.mkdir()
    operator = ROOT / "controller"
    stage = ROOT / "collector"

    def save(name, content):
        (output / (name + ".json")).write_text(json.dumps(content, indent=2) + "\n")
        return content

    with ExitStack() as stack:
        def launch(name, args):
            log = stack.enter_context((output / (name + ".log")).open("w"))
            process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
            stack.callback(stop, process)
            return process

        launch("controller", [
            "setpriv", "--reuid", "guard-controller", "--regid", "guard-controller",
            "--clear-groups", "--no-new-privs", PYTHON, "-I", "-m", "alethic_guard.api",
            str(operator / "controller.sock"), str(operator / "kernel.sqlite3"),
        ])
        until(lambda: (operator / "controller.sock").is_socket(), "governance controller")
        daemon = launch("daemon", [
            "/usr/local/sbin/alethic-guardd", str(ROOT),
            "/etc/alethic-guard/policies", str(SOCKET), CONFIG,
        ])
        until(SOCKET.is_socket, "Guard operator socket")

        launch("collector", [
            "ip", "netns", "exec", "guard-release-collector", "setpriv",
            "--reuid", "guard-collector", "--regid", "guard-collector", "--clear-groups",
            "--no-new-privs", PYTHON, "-I", "-m", "alethic_guard.release_evidence_collector",
            "--host", "2602:ff16::2", "--port", "8443", "--database", str(stage / "collector.sqlite3"),
            "--cert", str(stage / "tls.pem"), "--key", str(stage / "tls.key"),
            "--writer-token-file", str(stage / "writer"), "--reader-token-file", str(stage / "reader"),
        ])

        # Calibrate a lab-only listener and capture before testing direct access.
        sink = launch("network-sink", [
            "ip", "netns", "exec", "guard-release-collector", sys.executable,
            "-m", "http.server", "--bind", "fd42:abcd::2", "--directory", "/lab/empty", "9080",
        ])
        trace = output / "network-denial.pcap"
        capture = launch("packet-capture", [
            "tcpdump", "-n", "-U", "-i", "guard-observe", "-w", str(trace),
            "ip6 and tcp and host fd42:abcd::2 and port 9080",
        ])
        until(lambda: "listening on" in (output / "packet-capture.log").read_text(), "packet capture")
        def calibrated():
            client = http.client.HTTPConnection("fd42:abcd::2", 9080, timeout=2)
            try:
                client.request("GET", "/")
                response = client.getresponse()
                response.read()
                return response.status == 200
            except OSError:
                return False
            finally:
                client.close()
        until(calibrated, "lab listener calibration")

        first = save("enrolled", call(*ordinary("create", FIXTURE)))
        id = first["enrollment"]["id"]
        save("started", call(*workload("start", id)))
        xml = subprocess.check_output(["virsh", "dumpxml", id], text=True)
        (output / "domain.xml").write_text(xml)
        assert "<interface" not in xml and "dev.alethic.guard.1" in xml
        kvm = save("kvm", call("virsh", "qemu-monitor-command", id, '{"execute":"query-kvm"}'))
        assert kvm["return"] == {"enabled": True, "present": True}
        save("pid-before", qemu_pids(id))
        assert len(qemu_pids(id)) == 1

        console = output / "console.txt"
        launch("console", [
            "script", "-q", "-f", "-c", f"timeout --foreground -k 2s 125s virsh console {id}",
            str(console),
        ])
        until(lambda: console.exists() and "GUARD_AGENT active" in console.read_text(errors="replace"),
              "model task and broker checks", 100)
        log = console.read_text(errors="replace")
        assert re.search(r"GUARD_AGENT inference .*\bDana\b", log)
        for marker in (
            "unmounted_input DENIED", "direct_network DENIED", "undeclared_tool DENIED",
            "approved_delivery SUCCEEDED",
        ):
            assert "GUARD_AGENT " + marker in log, marker
        request = re.search(r"GUARD_AGENT request_id ([0-9a-f-]+)", log)[1]
        effect = save("approved-effect", call(*ordinary("effect_status", {"id": id, "request": request})))
        assert effect["outcome"] == "SUCCEEDED"
        save("collector-receipt", verify_receipt(effect))

        capture.send_signal(signal.SIGINT)
        assert capture.wait(timeout=5) == 0
        capture_log = (output / "packet-capture.log").read_text()
        assert "0 packets dropped by kernel" in capture_log
        packets = subprocess.check_output(["tcpdump", "-n", "-r", str(trace)], text=True)
        assert packets.strip(), "calibration produced no packets"
        # This host-only GET is the sole connection. A direct guest TCP
        # attempt would add a second SYN on the collector link.
        syns = sum("Flags [S]," in line for line in packets.splitlines())
        assert syns == 1, packets
        save("direct-network-observation", {"calibration_syns": 1, "guest_syns": syns - 1})
        stop(sink)

        with (
            subprocess.Popen(ordinary("create", FIXTURE), stdout=subprocess.PIPE, text=True) as pending,
            socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as queued,
        ):
            until(lambda: process_reading(daemon.pid), "ordinary enrollment hashing the lab image")
            queued.settimeout(80)
            queued.connect(str(SOCKET))
            queued.sendall(json.dumps({"command": "status", "id": id}).encode() + b"\n")
            begin = time.monotonic()
            ended = save("emergency-termination", call(*workload("emergency-terminate", id)))
            elapsed = time.monotonic() - begin
            still_pending = pending.poll() is None
            queued.setblocking(False)
            try:
                queued.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
            except BlockingIOError:
                status_queued = True
            else:
                status_queued = False
            finally:
                queued.settimeout(80)
            save("emergency-timing", {
                "elapsed_seconds": elapsed,
                "ordinary_request_pending": still_pending,
                "ordinary_status_queued": status_queued,
            })
            assert ended["admissions"] == ended["broker_cutoff"] == ended["shutdown"] == "VERIFIED", ended
            assert still_pending and status_queued and elapsed < 5, "ordinary operator ordering differs"
            assert not qemu_pids(id)
            assert id not in subprocess.check_output(["virsh", "list", "--all", "--uuid"], text=True).split()
            pending.communicate(timeout=80)
            assert pending.returncode == 0
            with queued.makefile("rb") as incoming:
                assert json.loads(incoming.readline(65_537))["ok"] is True

        libvirt_pid = int(subprocess.check_output(["pgrep", "-x", "libvirtd"], text=True).strip())
        subprocess.run(["kill", "-STOP", str(libvirt_pid)], check=True)
        try:
            unavailable = save("unavailable-observer", call(*workload("emergency-terminate", id)))
            assert unavailable["admissions"] == unavailable["broker_cutoff"] == "VERIFIED"
            assert unavailable["shutdown"] == "UNKNOWN"
        finally:
            subprocess.run(["kill", "-CONT", str(libvirt_pid)], check=True)

        # Check the emergency fence before normal cleanup can set it again.
        blocked = subprocess.run(workload("start", id), capture_output=True, text=True, timeout=5)
        assert blocked.returncode and "cutoff is latched" in blocked.stderr, blocked.stderr
        (output / "restart-refused.txt").write_text(blocked.stderr)
        durable = save("cleanup", call(*workload("terminate", id)))
        assert durable["shutdown"] == durable["broker_cutoff"] == "VERIFIED"
        absent = save("already-absent", call(*workload("emergency-terminate", id)))
        assert absent["shutdown"] == "VERIFIED"
        save("released", call(*workload("release", id)))
        events = output / "events.jsonl"
        head = output / "head.json"
        save("export", call(CLI, "evidence", "export", id, "--output", str(events)))
        save("verification", call(CLI, "evidence", "verify", str(events), "--write-checkpoint", str(head)))
        (output / "approved-record.json").write_bytes(Path("approved-record.json").read_bytes())
    print("Local inference, scoped delivery, fixed denials, emergency shutdown, and evidence export passed.")


if __name__ == "__main__":
    if any(subprocess.check_output(["ip", family, "route", "show", "default"], text=True)
           for family in ("-4", "-6")):
        raise SystemExit("local model qualification requires private lab networking")
    main(Path(sys.argv[1]).absolute())
