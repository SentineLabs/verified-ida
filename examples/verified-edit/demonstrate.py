"""Demonstrate the host feedback loop with real IDA and no model/API call."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from verified_ida.runtime import VerifiedIdaRuntime


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=Path, required=True, help="Compiled specimen.c (not executed).")
    parser.add_argument("--clean-idb", type=Path, required=True)
    parser.add_argument("--function", required=True, help="Hex address of specimen_clamp in this build.")
    parser.add_argument("--project-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.project_dir.exists() and any(args.project_dir.iterdir()):
        raise ValueError("Use a new or empty project directory")
    before = digest(args.clean_idb)
    runtime = VerifiedIdaRuntime.initialize(args.project_dir, binary_path=args.sample,
        clean_idb_path=args.clean_idb, checkpoint_interval=1,
        project_objective="Demonstrate verified edits to the supplied harmless clamp function.")
    try:
        evidence = runtime.inspect(query="inspect_function", target=args.function)
        rename = runtime.apply_edit(target_ref=evidence["target_ref"], kind="function.rename",
            value={"name": "ClampRequestedSize"}, evidence_refs=[evidence["evidence_id"]],
            reason="The supplied C fixture clamps an unsigned input to 512.")
        assert rename["status"] in {"verified", "verified_existing"}
        missing = [row for row in rename.get("must_review", []) if row.get("gap_kind") == "missing_behavior_comment"]
        assert missing, "Expected feedback: the verified name still needs a behavior comment"

        # The edit advanced the revision. Fetch current evidence before the next
        # operation, just as the investigator must do through its tools.
        current = runtime.inspect(query="inspect_function", target=args.function)
        explanation = runtime.apply_edit(target_ref=current["target_ref"], kind="function.comment.set",
            value={"comment": "Returns the unsigned input when it is at most 512; otherwise returns 512.", "repeatable": True},
            evidence_refs=[current["evidence_id"]], reason="Persist the behavior already demonstrated by the fixture.")
        assert explanation["status"] in {"verified", "verified_existing"}
        assert not any(row.get("gap_kind") == "missing_behavior_comment" for row in explanation.get("must_review", []))
        checkpoint = runtime.checkpoint(reason="Public verified-edit example")
        assert checkpoint["status"] == "verified"
        result = {"status": "passed", "model_requests": 0,
            "rename_operation": rename["operation_id"], "comment_operation": explanation["operation_id"],
            "feedback_after_rename": missing, "missing_comment_resolved": True,
            "checkpoint": checkpoint, "clean_input_unchanged": digest(args.clean_idb) == before}
        assert result["clean_input_unchanged"]
        (args.project_dir / "example_result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
    finally:
        runtime.close()


if __name__ == "__main__":
    main()
