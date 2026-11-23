"""Local operator control with a bounded Unix socket protocol."""

from dataclasses import asdict
import argparse
import json
from pathlib import Path
import socket
import sys
import uuid

from alethic_guard.evidence import verify_file
from alethic_guard.policy import BackendCapabilities, compile_policy

_MAX_FRAME = 65_536
_EMERGENCY_TIMEOUT = 10
_EMERGENCY_SHUTDOWN_TIMEOUT = 25


def daemon_call(path: Path, request: dict, timeout: float = 140) -> dict:
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            client.connect(str(path))
            client.sendall(json.dumps(request, separators=(",", ":")).encode() + b"\n")
            with client.makefile("rb") as response:
                line = response.readline(_MAX_FRAME + 1)
    except OSError as error:
        raise ValueError(f"daemon connection failed: {error}") from error
    if not line.endswith(b"\n") or len(line) > _MAX_FRAME:
        raise ValueError("invalid daemon response frame")
    envelope = json.loads(line)
    if envelope.get("ok") is not True:
        raise ValueError(envelope.get("error", "daemon rejected the request"))
    return envelope["result"]


def _profile(args: argparse.Namespace) -> dict:
    with args.file.open("rb") as source:
        policy = compile_policy(source.read(65_537), BackendCapabilities(mediated_api=args.mediated_api))
    if args.verb == "compile":
        with args.output.open("xb") as output:
            output.write(policy.canonical)
    return {"name": policy.name, "profile": policy.profile, "digest": policy.digest}


def _workload(args: argparse.Namespace) -> dict:
    request = {"command": args.verb}
    if args.verb == "create":
        request.update(profile=args.profile, image=args.image, input=args.input)
    else:
        request["id"] = str(args.id)
        if args.verb in {"effect-status", "reconcile-receipt"}:
            request["command"] = args.verb.replace("-", "_")
            request["request"] = str(args.request)
            if args.verb == "reconcile-receipt":
                with args.receipt.open("rb") as source:
                    record = json.loads(source.read(4097))
                if set(record) != {"idempotency_key", "payload_sha256"}:
                    raise ValueError("invalid controlled collector receipt")
                request.update(key=record["idempotency_key"], payload_sha256=record["payload_sha256"])
    if args.verb not in {"cutoff", "contain", "terminate", "emergency-terminate"}:
        return daemon_call(args.socket, request)

    emergency_socket = args.socket.with_name(args.socket.name + ".emergency")
    if args.verb == "emergency-terminate":
        return daemon_call(
            emergency_socket,
            {"command": "terminate", "id": request["id"]},
            timeout=_EMERGENCY_SHUTDOWN_TIMEOUT,
        )
    cutoff = {"command": "cutoff", "id": request["id"]}
    if args.verb == "cutoff":
        return daemon_call(emergency_socket, cutoff, timeout=_EMERGENCY_TIMEOUT)
    try:
        early_cutoff = daemon_call(emergency_socket, cutoff, timeout=_EMERGENCY_TIMEOUT)
    except ValueError as error:
        early_cutoff = {"broker_cutoff": "UNKNOWN", "error": str(error)}
    try:
        result = daemon_call(args.socket, request)
    except ValueError as error:
        status = early_cutoff["broker_cutoff"]
        raise ValueError(f"{error}. Emergency broker cutoff: {status}") from error
    return {**result, "emergency": early_cutoff}


def _evidence(args: argparse.Namespace) -> dict:
    if args.verb == "export":
        sequence = 0
        with args.output.open("x", encoding="utf-8") as output:
            while True:
                records = daemon_call(args.socket, {
                    "command": "evidence_page", "id": str(args.id), "after": sequence,
                })["events"]
                if not records:
                    break
                for record in records:
                    output.write(json.dumps(record, separators=(",", ":")) + "\n")
                sequence = records[-1]["sequence"]
        return {"events": sequence, "output": str(args.output)}
    checkpoint = json.loads(args.checkpoint.read_bytes()) if args.checkpoint else None
    verification = verify_file(args.file, checkpoint)
    if args.write_checkpoint:
        with args.write_checkpoint.open("x", encoding="utf-8") as output:
            json.dump(verification.checkpoint, output, sort_keys=True)
            output.write("\n")
    return asdict(verification)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="alethic-guard")
    parser.add_argument("--socket", type=Path, default=Path("/run/alethic-guard/operator.sock"))
    commands = parser.add_subparsers(dest="command", required=True)
    profile = commands.add_parser("profile").add_subparsers(dest="verb", required=True)
    validate = profile.add_parser("validate")
    validate.add_argument("file", type=Path)
    validate.add_argument("--mediated-api", action="store_true")
    compiler = profile.add_parser("compile")
    compiler.add_argument("file", type=Path)
    compiler.add_argument("--mediated-api", action="store_true")
    compiler.add_argument("--output", type=Path, required=True)
    workload = commands.add_parser("workload").add_subparsers(dest="verb", required=True)
    enroll = workload.add_parser("create")
    enroll.add_argument("--profile", required=True)
    enroll.add_argument("--image", required=True, help="approved image filename")
    enroll.add_argument("--input", help="approved raw input image filename")
    for verb in (
        "start", "status", "verify", "pause", "resume", "cutoff", "contain",
        "terminate", "emergency-terminate", "release",
    ):
        workload.add_parser(verb).add_argument("id", type=uuid.UUID)
    for verb in ("effect-status", "reconcile-receipt"):
        command = workload.add_parser(verb)
        command.add_argument("id", type=uuid.UUID)
        command.add_argument("--request", type=uuid.UUID, required=True)
        if verb == "reconcile-receipt":
            command.add_argument("--receipt", type=Path, required=True)
    evidence = commands.add_parser("evidence").add_subparsers(dest="verb", required=True)
    export = evidence.add_parser("export")
    export.add_argument("id", type=uuid.UUID)
    export.add_argument("--format", choices=("jsonl",), default="jsonl")
    export.add_argument("--output", type=Path, required=True)
    verify = evidence.add_parser("verify")
    verify.add_argument("file", type=Path)
    verify.add_argument("--checkpoint", type=Path)
    verify.add_argument("--write-checkpoint", type=Path)
    args = parser.parse_args(argv)
    try:
        handlers = {"profile": _profile, "workload": _workload, "evidence": _evidence}
        result = handlers[args.command](args)
    except (KeyError, OSError, TypeError, ValueError) as error:
        print(f"alethic-guard: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
