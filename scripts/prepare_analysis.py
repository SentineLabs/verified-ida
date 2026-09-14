"""Prepare a clean IDB with IDA autoanalysis, without analyst heuristics."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ida_backend import save_database
from ida_reader import get_binary_metadata, get_entry_points, load_binary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input")
    parser.add_argument("--save-as", required=True)
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    load_binary(args.input)
    result = {
        "schema": "verified_ida.preparation.v1",
        "policy": "native_autoanalysis_only",
        "binary": get_binary_metadata(),
        "entry_points": get_entry_points(),
        "analyst_annotations_applied": False,
        "heuristic_collapse_applied": False,
    }
    save_database(args.save_as)
    rendered = json.dumps(result, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
