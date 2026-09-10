"""Persistent, no-network IDA worker for Verified IDA host tools.

One worker owns one open IDB.  Requests are serialized by the host.  The
worker performs live inspection, mutation, decompiler refresh, canonical
readback, and save before replying.  It does not call a model or access the
host journal.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import traceback

SCRIPT_DIR = os.path.dirname(__file__)
sys.path.insert(0, SCRIPT_DIR)
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", "src"))

import ida_auto
import ida_nalt

from apply_verified_ida_operations import (
    _compare_operation,
    execute_batch,
    read_state,
)
from ida_backend import save_database
from ida_reader import load_binary
from ida_structural_queries import execute_task
from export_verified_ida_semantic_state import export_semantic_state
from verified_ida.contracts import validate_operation


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Serve one persistent Verified IDA database session.")
    parser.add_argument("input", help="Working IDB/I64 to open and mutate.")
    parser.add_argument(
        "--input-binary",
        help="Host-registered component binary used for bounded file-backed queries.",
    )
    parser.add_argument("--request-fifo", required=True)
    parser.add_argument("--response-fifo", required=True)
    return parser.parse_args(argv)


def _wait_for_analysis():
    ida_auto.auto_wait()


def _handle(request, *, input_path, input_binary_path, operation_registry):
    method = str(request.get("method") or "")
    params = request.get("params") or {}
    if method == "ping":
        digest = ida_nalt.retrieve_input_file_sha256()
        return {
            "ok": True, "input": os.path.abspath(input_path),
            "input_identity": {
                "source": "ida_nalt.retrieve_input_file_sha256",
                "sha256": bytes(digest).hex() if digest else None,
                "meaning": "original_loader_input_not_current_patched_database_bytes",
            },
        }
    if method == "query":
        task = params.get("task")
        if not isinstance(task, dict):
            raise ValueError("query requires one task object")
        result = execute_task(task, input_file_path=input_binary_path)
        return {"ok": True, "result": result}
    if method == "apply":
        operation = params.get("operation")
        artifact = params.get("artifact")
        if not isinstance(operation, dict) or not isinstance(artifact, dict):
            raise ValueError("apply requires operation and artifact objects")
        validate_operation(operation, expected_artifact=artifact)
        result = execute_batch(
            [operation],
            artifact,
            replace_existing_named_types=bool(
                params.get("replace_existing_named_types", False)
            ),
            operation_registry=operation_registry,
        )
        _wait_for_analysis()
        save_database(input_path)
        return {"ok": True, "result": result, "saved": True}
    if method == "read_operation":
        operation = params.get("operation")
        if not isinstance(operation, dict):
            raise ValueError("read_operation requires an operation object")
        observed = read_state(operation)
        matches, normalization = _compare_operation(operation, observed)
        return {
            "ok": True,
            "observed": observed,
            "matches": bool(matches),
            "normalization": normalization,
        }
    if method == "save":
        save_database(input_path)
        return {"ok": True, "saved": True}
    if method == "semantic_export":
        selected_locals = params.get("selected_local_functions") or []
        selected_globals = params.get("selected_global_addresses") or []
        if not isinstance(selected_locals, list):
            raise ValueError("semantic_export selected_local_functions must be an array")
        if not isinstance(selected_globals, list):
            raise ValueError("semantic_export selected_global_addresses must be an array")
        return {
            "ok": True,
            **export_semantic_state(selected_locals, selected_globals),
        }
    if method == "close":
        save_database(input_path)
        return {"ok": True, "saved": True, "close": True}
    raise ValueError("unsupported session method: %s" % method)


def _write(stream, request_id, *, result=None, error=None):
    response = {"id": request_id}
    if error is None:
        response["result"] = result
    else:
        response["error"] = error
    stream.write(json.dumps(response, separators=(",", ":")) + "\n")
    stream.flush()


def serve(input_path, request_stream, response_stream, *, input_binary_path=None):
    operation_registry = {}
    for line in request_stream:
        request = None
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError("request must be an object")
            request_id = request.get("id")
            result = _handle(
                request,
                input_path=input_path,
                input_binary_path=input_binary_path,
                operation_registry=operation_registry,
            )
            _write(response_stream, request_id, result=result)
            if result.get("close"):
                break
        except Exception as exc:
            _write(
                response_stream,
                request.get("id") if isinstance(request, dict) else None,
                error={
                    "type": type(exc).__name__,
                    "message": str(exc),
                    "traceback": traceback.format_exc(limit=8),
                },
            )


def main(argv):
    args = parse_args(argv)
    load_binary(args.input)
    _wait_for_analysis()
    with open(args.request_fifo, "r", encoding="utf-8") as request_stream:
        with open(args.response_fifo, "w", encoding="utf-8") as response_stream:
            serve(
                args.input,
                request_stream,
                response_stream,
                input_binary_path=args.input_binary,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
