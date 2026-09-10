#!/usr/bin/env python3
"""Run apply/readback/reopen conformance against a disposable IDA database copy."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from verified_ida.source_provenance import describe_source


ROOT = Path(__file__).resolve().parents[3]
RUN_IDA = ROOT / "scripts" / "run_ida_script_no_network.sh"
APPLY = ROOT / "scripts" / "apply_verified_ida_operations.py"
VERIFY = ROOT / "scripts" / "verify_verified_ida_persistence.py"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Exercise Verified IDA operations through apply, readback, save, and fresh reopen."
    )
    parser.add_argument("--input", required=True, type=Path, help="Baseline IDB/I64. It is never modified.")
    parser.add_argument("--operations", required=True, type=Path, help="Operation-batch JSON.")
    parser.add_argument("--artifact", required=True, type=Path, help="Expected artifact-identity JSON.")
    parser.add_argument("--output-dir", required=True, type=Path, help="New directory for the disposable test.")
    return parser.parse_args(argv)


def run(command: list[str]) -> None:
    subprocess.run(command, cwd=ROOT, check=True)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    for path in (args.input, args.operations, args.artifact):
        if not path.is_file():
            raise FileNotFoundError(path)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    working_input = args.output_dir / ("baseline" + args.input.suffix)
    working_output = args.output_dir / ("verified" + args.input.suffix)
    receipts = args.output_dir / "receipts.json"
    persisted = args.output_dir / "receipts_persisted.json"
    registry = args.output_dir / "operation_registry.json"
    claimed = [working_input, working_output, receipts, persisted, registry]
    if any(path.exists() for path in claimed):
        raise FileExistsError(
            "output directory already contains conformance artifacts; choose a new directory"
        )
    shutil.copy2(args.input, working_input)
    run(
        [
            str(RUN_IDA),
            "--log",
            str(args.output_dir / "apply.ida.log"),
            str(working_input),
            str(APPLY),
            "--operations",
            str(args.operations.resolve()),
            "--artifact",
            str(args.artifact.resolve()),
            "--receipts",
            str(receipts),
            "--registry",
            str(registry),
            "--save-as",
            str(working_output),
        ]
    )
    run(
        [
            str(RUN_IDA),
            "--log",
            str(args.output_dir / "persistence.ida.log"),
            str(working_output),
            str(VERIFY),
            "--receipts",
            str(receipts),
            "--output",
            str(persisted),
        ]
    )
    result = json.loads(persisted.read_text(encoding="utf-8"))
    summary = {
        "output_dir": str(args.output_dir),
        "source": describe_source(ida_backend="process"),
        **result.get("summary", {}),
    }
    (args.output_dir / "conformance_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2))
    return 0 if (result.get("summary") or {}).get("status") == "verified" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
