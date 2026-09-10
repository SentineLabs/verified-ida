#!/usr/bin/env python3
"""Export annotations from a disposable candidate IDB with drift checks."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from verified_ida.export_safety import (  # noqa: E402
    safe_export_annotations,
    subprocess_ida_executor,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--idb", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    execute = subprocess_ida_executor(
        runner=ROOT / "scripts" / "run_ida_script_no_network.sh",
        annotation_script=(
            ROOT / "scripts" / "verified_ida_annotations_export_ida.py"
        ),
        semantic_script=(
            ROOT / "scripts" / "export_verified_ida_semantic_snapshot_ida.py"
        ),
    )
    result = safe_export_annotations(
        source_idb=args.idb,
        annotations_path=args.output,
        provenance_path=args.provenance,
        execute=execute,
        overwrite=args.overwrite,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
