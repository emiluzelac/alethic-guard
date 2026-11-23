"""Tiny JSON client for running qualification against an installed guardd."""

import json
import socket
import sys

path, operation, *parameters = sys.argv[1:]
request = {"command": operation}
if parameters:
    request.update(json.loads(parameters[0]))
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.settimeout(180)
    client.connect(path)
    client.sendall(json.dumps(request).encode() + b"\n")
    with client.makefile("rb") as response:
        result = json.loads(response.readline(65_537))
if not result["ok"]:
    raise SystemExit(result["error"])
print(json.dumps(result["result"], sort_keys=True))
