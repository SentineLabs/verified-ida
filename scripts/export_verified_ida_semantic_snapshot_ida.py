"""Export canonical semantic state from an IDB opened by the no-network runner.

This CLI deliberately reuses the persistent worker's exporter. It does not save
the database; callers must still use disposable copies because IDA can infer
additional state while opening or inspecting an IDB.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
sys.path.insert(0, str(SCRIPT_DIR.parent / "src"))

from ida_reader import load_binary
from export_verified_ida_semantic_state import export_semantic_state


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="Disposable IDB already opened by IDA.")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    load_binary(args.input)
    result = export_semantic_state()
    if not result.get("semantic_digest"):
        raise RuntimeError("Canonical semantic exporter returned no digest")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    # IDAPython treats even SystemExit(0) as a script error. Normal return is
    # successful; exceptions still fail the headless invocation.
    main(sys.argv[1:])
