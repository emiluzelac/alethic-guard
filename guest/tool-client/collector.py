"""Request a host-approved collector record from inside the enrolled VM."""
import argparse
import json
import os
import uuid

parser = argparse.ArgumentParser()
parser.add_argument("--request-id", type=uuid.UUID, default=uuid.uuid4())
parser.add_argument("--fixture", choices=("public-demo", "release-evidence"), default="public-demo")
options = parser.parse_args()
request = {"request_id": str(options.request_id), "operation": "collector.publish", "fixture_id": options.fixture}
with open("/dev/virtio-ports/dev.alethic.guard.1", "r+b", buffering=0) as channel:
    channel.write(json.dumps(request).encode() + b"\n")
    reply = bytearray()
    while len(reply) < 2048:
        byte = channel.read(1)
        if not byte:
            break
        reply.extend(byte)
        if byte == b"\n":
            break
print(os.fsdecode(reply).strip())
