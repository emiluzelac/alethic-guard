"""Synthetic guest-root probes with fixed lab addresses and no user data."""

import os
from pathlib import Path
import socket
import subprocess

print(f"GUARD_PROBE uid={os.getuid()} links={','.join(sorted(p.name for p in Path('/sys/class/net').iterdir()))}", flush=True)
successful = []
for family, address in ((socket.AF_INET, "198.18.0.2"), (socket.AF_INET6, "fd42:abcd::2")):
    for protocol, port, label in (
        (socket.SOCK_STREAM, 40441, "tcp"),
        (socket.SOCK_DGRAM, 40441, "udp"),
        (socket.SOCK_DGRAM, 53, "dns"),
        (socket.SOCK_DGRAM, 443, "quic-transport"),
    ):
        with socket.socket(family, protocol) as probe:
            probe.settimeout(2)
            try:
                probe.connect((address, port))
                probe.sendall(b"GUARD-SYNTHETIC-OFFLINE-PROBE")
            except OSError as error:
                print(f"GUARD_PROBE {family} {label} blocked errno={error.errno}", flush=True)
            else:
                successful.append((family, label))
    ping = subprocess.run(["ping", "-4" if family == socket.AF_INET else "-6", "-c", "1", "-W", "2", address],
                          capture_output=True, check=False)
    if ping.returncode == 0:
        successful.append((family, "icmp"))
print(f"GUARD_PROBE complete successful={successful}", flush=True)
