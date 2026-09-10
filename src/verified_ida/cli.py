"""Unified source-checkout command for the Verified IDA harness."""

from __future__ import annotations

import importlib
import sys
from typing import Callable, Sequence


COMMANDS = {
    "analyze": (
        "verified_ida.commands.analyze",
        "Start a new investigation or resume an existing project.",
    ),
    "review": (
        "verified_ida.commands.review",
        "Run independent final review and verified application.",
    ),
    "replay-review-wave": (
        "verified_ida.commands.replay_review_wave",
        "Replay one finding from a frozen final-review plan.",
    ),
    "finalize-review": (
        "verified_ida.commands.finalize_review",
        "Retry closure finalization after all review findings are resolved.",
    ),
    "conformance": (
        "verified_ida.commands.conformance",
        "Verify mutation, readback, and persistence behavior.",
    ),
}


def _usage() -> str:
    rows = [
        "usage: verified-ida <command> [arguments]",
        "",
        "commands:",
    ]
    width = max(len(name) for name in COMMANDS)
    rows.extend(
        "  %-*s  %s" % (width, name, description)
        for name, (_module, description) in COMMANDS.items()
    )
    rows.extend([
        "",
        "Run 'verified-ida <command> --help' for command-specific arguments.",
    ])
    return "\n".join(rows)


def _command_main(module_name: str) -> Callable[[Sequence[str]], int]:
    module = importlib.import_module(module_name)
    command = getattr(module, "main", None)
    if not callable(command):
        raise RuntimeError("Command module has no callable main: %s" % module_name)
    return command


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0] in {"-h", "--help", "help"}:
        print(_usage())
        return 0
    command_name = arguments.pop(0)
    command = COMMANDS.get(command_name)
    if command is None:
        print("Unknown Verified IDA command: %s\n" % command_name, file=sys.stderr)
        print(_usage(), file=sys.stderr)
        return 2
    command_main = _command_main(command[0])
    original_program = sys.argv[0]
    sys.argv[0] = "verified-ida %s" % command_name
    try:
        return int(command_main(arguments))
    finally:
        sys.argv[0] = original_program


if __name__ == "__main__":
    raise SystemExit(main())
