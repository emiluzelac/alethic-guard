#!/usr/bin/python3
"""Deliver a deliberately mismatched, still-paused domain on the isolated qualification VM."""

import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET


FIXTURE = Path("/var/lib/guard-release-fixtures")
REAL = "/opt/guard-release-fixtures/virsh-real"
args = sys.argv[1:]
assert args[:2] == ["-c", "qemu:///system"]
command = args[2]
setting = json.loads((FIXTURE / "paused-case.json").read_text())
if command == "resume" and args[3] == setting["uuid"]:
    (FIXTURE / "unexpected-resume").touch()
    raise SystemExit("qualification fixture held the paused domain")
if command != "create" or args[3:] != ["/dev/stdin", "--paused", "--validate"]:
    os.execv(REAL, [REAL, *args])
original = sys.stdin.buffer.read()
domain = ET.fromstring(original)
if domain.findtext("uuid") != setting["uuid"]:
    raise SystemExit(subprocess.run([REAL, *args], input=original, timeout=10).returncode)
devices = domain.find("devices")
match setting["case"]:
    case "restart":
        domain.find("on_reboot").text = "restart"
    case "interface":
        interface = ET.SubElement(devices, "interface", {"type": "bridge"})
        ET.SubElement(interface, "source", {"bridge": "guard-drift0"})
        ET.SubElement(interface, "link", {"state": "down"})
    case "input":
        disk = next(item for item in devices.findall("disk") if item.find("readonly") is not None)
        disk.find("source").set("file", "/var/lib/alethic-guard/images/alternate-probe.img")
    case "mount":
        mount = ET.SubElement(devices, "filesystem", {"type": "mount", "accessmode": "passthrough"})
        ET.SubElement(mount, "source", {"dir": "/var/lib/guard-release-fixtures/empty-mount"})
        ET.SubElement(mount, "target", {"dir": "guard-qualification-empty"})
        ET.SubElement(mount, "readonly")
    case _:
        raise SystemExit("unknown paused qualification fixture")
subprocess.run([REAL, *args], input=ET.tostring(domain), check=True, timeout=10)
for name in ("domstate", "dumpxml"):
    seen = subprocess.check_output([REAL, *args[:2], name, setting["uuid"]], timeout=5)
    (FIXTURE / f"paused-{name}").write_bytes(seen)
