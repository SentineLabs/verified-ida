"""Reopen an IDB and mark Verified IDA receipts with persistence results."""

from __future__ import annotations

import argparse
import json
import os
import sys

SCRIPT_DIR = os.path.dirname(__file__)
sys.path.insert(0, SCRIPT_DIR)
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", "src"))

from ida_reader import load_binary
from apply_verified_ida_operations import _compare_operation, read_state
from verified_ida.contracts import build_receipt, summarize_receipts


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Verify saved Verified IDA receipts in a fresh IDA process.")
    parser.add_argument("input", help="Saved IDB or I64 to reopen.")
    parser.add_argument("--receipts", required=True, help="Receipt batch to verify.")
    parser.add_argument("--output", required=True, help="Output receipt batch with persistence results.")
    return parser.parse_args(argv)


def _operation_from_receipt(receipt):
    return {
        "schema": "verified_ida.operation.v1",
        "operation_id": receipt["operation_id"],
        "work_item_id": receipt.get("work_item_id"),
        "kind": receipt["kind"],
        "artifact": receipt["artifact"],
        "target": receipt["target"],
        "desired": receipt["desired"],
        "preconditions": {},
        "evidence": receipt.get("evidence") or [],
        "depends_on": [],
        "metadata": {},
    }


def main(argv):
    args = parse_args(argv)
    load_binary(args.input)
    with open(args.receipts, encoding="utf-8") as handle:
        result = json.load(handle)
    persisted_receipts = []
    for receipt in result.get("receipts") or []:
        if receipt.get("status") not in {"verified", "verified_existing"}:
            persisted_receipts.append(receipt)
            continue
        operation = _operation_from_receipt(receipt)
        observed = read_state(operation)
        matches, normalization = _compare_operation(operation, observed)
        errors = []
        recovery = None
        status = receipt["status"]
        if not matches:
            status = "ineffective"
            errors.append({"code": "persistence_failed", "message": "Desired state did not survive IDB reopen"})
            recovery = "Reapply the operation and inspect the database save path."
        persisted_receipts.append(
            build_receipt(
                operation,
                status,
                "persistence",
                before=receipt.get("before"),
                observed=observed,
                execution=receipt.get("execution") or {},
                normalization=normalization,
                effects={**(receipt.get("effects") or {}), "readback_receipt_id": receipt.get("receipt_id")},
                persistence="verified" if matches else "failed",
                semantic_review=receipt.get("semantic_review") or "unreviewed",
                errors=errors,
                recovery=recovery,
                implementation={
                    "name": "ida-harness",
                    "standard_version": "0.1",
                    "persistence_verifier": "fresh_ida_process",
                },
            )
        )
    result["receipts"] = persisted_receipts
    persistable = [row for row in persisted_receipts if row.get("stage") == "persistence"]
    result["persistence"] = {
        "checked": len(persistable),
        "verified": sum(row.get("persistence") == "verified" for row in persistable),
        "failed": sum(row.get("persistence") == "failed" for row in persistable),
    }
    result["summary"] = summarize_receipts(persisted_receipts)
    parent = os.path.dirname(os.path.abspath(args.output))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps(result["persistence"], indent=2, sort_keys=True))
    return 0 if not result["persistence"]["failed"] else 2


if __name__ == "__main__":
    main(sys.argv[1:])
