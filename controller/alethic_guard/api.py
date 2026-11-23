"""Host-only governance RPC for guardd."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import socket
import struct
from uuid import uuid4

from alethic_guard.alethic_adapter import AlethicAdapter, NormalizedAction, PolicySnapshot

_MAX_FRAME = 16_384


def serve(path: Path, store: Path) -> None:
    adapter = AlethicAdapter(store)
    session = str(uuid4())
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        if path.exists() and path.is_socket():
            path.unlink()
        listener.bind(str(path))
        path.chmod(0o600)
        listener.listen()
        while True:
            client, _ = listener.accept()
            with client:
                client.settimeout(2)
                credentials = client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
                _, uid, _ = struct.unpack("3i", credentials)
                if uid != 0:
                    continue
                try:
                    with client.makefile("rb") as incoming:
                        frame = incoming.readline(_MAX_FRAME + 1)
                    if not frame.endswith(b"\n") or len(frame) > _MAX_FRAME:
                        continue
                    request = json.loads(frame)
                    if request == {"op": "ping"}:
                        result = {"ok": True, "session": session}
                    else:
                        if set(request) != {"action", "snapshot"}:
                            continue
                        action = NormalizedAction(**request["action"])
                        decision = adapter.evaluate_action(action, PolicySnapshot(**request["snapshot"]))
                        result = {**asdict(decision), "session": session}
                    client.sendall(json.dumps(result).encode() + b"\n")
                except (ValueError, TypeError, KeyError, OSError):
                    # A malformed or interrupted exchange grants no authority.
                    continue


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("socket", type=Path)
    parser.add_argument("store", type=Path)
    args = parser.parse_args()
    serve(args.socket, args.store)


if __name__ == "__main__":
    main()
