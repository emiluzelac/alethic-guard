#!/usr/bin/python3
"""Ask the real daemon for a grant and observe rejection after a controlled delay."""

import json
from pathlib import Path
import socket
import sys
import time


FIXTURE = Path("/var/lib/guard-release-fixtures")
MODE = (FIXTURE / "permit-mode").read_text().strip()
assert MODE in {"expired", "stale-controller"}


def call(request):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(sys.argv[1])
        sock.sendall(json.dumps(request).encode() + b"\n")
        with sock.makefile("rb") as response:
            return json.loads(response.readline(65_537))


def delayed_redeem(request):
    prepared = call({"command": "broker_prepare", "request": request})
    if not prepared.get("ok"):
        raise RuntimeError(prepared.get("error", "permit was not issued"))
    print(f"GUARD_PERMIT {MODE} ISSUED {request['request_id']}", flush=True)
    elapsed = time.monotonic()
    if MODE == "expired":
        time.sleep(10.2)
    else:
        until = elapsed + 6
        while not (FIXTURE / "controller-replaced").exists() and time.monotonic() < until:
            time.sleep(0.025)
        assert (FIXTURE / "controller-replaced").exists(), "controller replacement did not complete"
    elapsed_ms = int((time.monotonic() - elapsed) * 1000)
    result = call({
        "command": "broker_redeem",
        "nonce": prepared["result"]["nonce"],
        "action": prepared["result"]["action"],
    })
    print("GUARD_PERMIT " + json.dumps({
        "mode": MODE, "request_id": request["request_id"], "elapsed_ms": elapsed_ms,
        "redeemed": result.get("ok"), "error": result.get("error"),
    }), flush=True)
    return "DENIED" if result.get("ok") is False else "FAILED"


with socket.socket(fileno=3) as channel, channel.makefile("rb") as incoming:
    attempted = False
    while line := incoming.readline(2049):
        request = json.loads(line)
        allowed = request.keys() == {"request_id", "operation", "fixture_id"} and request["fixture_id"] == "public-demo"
        outcome = "DENIED"
        if allowed and not attempted:
            attempted = True
            outcome = delayed_redeem(request)
        channel.sendall(json.dumps({"outcome": outcome}).encode() + b"\n")
