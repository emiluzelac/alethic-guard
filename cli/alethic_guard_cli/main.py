"""Local operator command line."""

import argparse
import json
from pathlib import Path
import sys

from alethic_guard.policy import BackendCapabilities, PolicyError, compile_policy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="alethic-guard")
    commands = parser.add_subparsers(dest="command", required=True)
    profile = commands.add_parser("profile").add_subparsers(dest="verb", required=True)
    profile.add_parser("validate").add_argument("file", type=Path)
    args = parser.parse_args(argv)
    try:
        with args.file.open("rb") as source:
            policy = compile_policy(source.read(65_537), BackendCapabilities())
    except (OSError, PolicyError) as error:
        print(f"alethic-guard: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"name": policy.name, "profile": policy.profile, "digest": policy.digest}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
