"""Exercise the typed guest API with synthetic requests only."""

import json
import time
import uuid

channel = "/dev/virtio-ports/dev.alethic.guard.1"

def send(incoming):
    with open(channel, "r+b", buffering=0) as port:
        port.write(json.dumps(incoming).encode() + b"\n")
        frame = bytearray()
        while len(frame) < 2048:
            byte = port.read(1)
            if not byte:
                break
            frame.extend(byte)
            if byte == b"\n":
                break
        return json.loads(frame)["outcome"]

good = {"request_id": str(uuid.uuid4()), "operation": "collector.publish", "fixture_id": "public-demo"}
print(f"GUARD_BROKER request_id={good['request_id']}", flush=True)
print("GUARD_BROKER forged_role", send({**good, "role": "kernel"}), flush=True)
time.sleep(1.2)
print("GUARD_BROKER forbidden_fixture", send({**good, "fixture_id": "private-canary"}), flush=True)
time.sleep(1.2)
print("GUARD_BROKER allowed", send(good), flush=True)
time.sleep(1.2)
print("GUARD_BROKER replay", send(good), flush=True)
