"""Validation and wrappers for model-authored static byte extractors."""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping


MAX_SCRIPT_BYTES = 128 * 1024
MAX_SCRIPT_NODES = 50_000
MAX_INPUT_COUNT = 16
MAX_TOTAL_INPUT_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_REPORT_BYTES = 1024 * 1024
INPUT_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")

# The supported API, not complete modules with accidental transitive exports.
APPROVED_MEMBERS = {
    "base64": "b64decode b64encode urlsafe_b64decode urlsafe_b64encode b32decode b32encode b16decode b16encode a85decode b85decode",
    "binascii": "hexlify unhexlify crc32 a2b_hex b2a_hex a2b_base64 b2a_base64",
    "hashlib": "md5 sha1 sha224 sha256 sha384 sha512 blake2b blake2s",
    "json": "loads dumps",
    "math": "ceil floor sqrt log log2 log10 pow gcd factorial isfinite isnan pi e",
    "re": "compile search match fullmatch findall finditer split sub escape IGNORECASE MULTILINE DOTALL ASCII",
    "struct": "pack unpack pack_into unpack_from iter_unpack calcsize",
    "zlib": "compress decompress crc32 adler32 MAX_WBITS",
}

BLOCKED_NAMES = {
    "__import__",
    "breakpoint",
    "compile",
    "delattr",
    "dir",
    "eval",
    "exec",
    "exit",
    "getattr",
    "globals",
    "help",
    "input",
    "locals",
    "open",
    "quit",
    "setattr",
    "vars",
}


def validate_static_extractor_script(source: str) -> dict[str, Any]:
    """Reject filesystem, process, network, and dynamic-code primitives."""
    encoded = source.encode("utf-8")
    if not encoded or len(encoded) > MAX_SCRIPT_BYTES:
        raise ValueError(
            "static extractor must contain 1..%d UTF-8 bytes" % MAX_SCRIPT_BYTES
        )
    tree = ast.parse(source, mode="exec")
    nodes = list(ast.walk(tree))
    if len(nodes) > MAX_SCRIPT_NODES:
        raise ValueError("static extractor exceeds the AST complexity limit")
    errors: list[str] = []
    assigns_artifact = False
    for node in nodes:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            errors.append("imports are not allowed; approved byte utilities are preloaded")
        if isinstance(node, ast.ClassDef):
            errors.append("class definitions are not allowed")
        if isinstance(node, ast.Name) and node.id in BLOCKED_NAMES:
            errors.append("blocked name: %s" % node.id)
        if isinstance(node, ast.Attribute) and node.attr.startswith("_"):
            errors.append("private/dunder attributes are not allowed")
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id in APPROVED_MEMBERS and node.attr not in APPROVED_MEMBERS[node.value.id].split():
                errors.append("unsupported %s member: %s" % (node.value.id, node.attr))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in BLOCKED_NAMES:
                errors.append("blocked call: %s" % node.func.id)
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id == "artifact" for target in targets):
                assigns_artifact = True
    if not assigns_artifact:
        errors.append("static extractor must assign recovered bytes to artifact")
    if errors:
        raise ValueError("; ".join(sorted(set(errors))))
    return {
        "schema": "ida_harness.static_extractor.validation.v1",
        "script_bytes": len(encoded),
        "script_sha256": hashlib.sha256(encoded).hexdigest(),
        "node_count": len(nodes),
        "imports_allowed": False,
        "file_access_allowed": False,
        "malware_execution_allowed": False,
    }


def stage_static_extractor(
    *,
    source: str,
    scratch_dir: Path,
    inputs: Mapping[str, bytes],
    parameters: Mapping[str, Any],
) -> dict[str, Any]:
    """Stage trusted wrapper inputs without exposing host paths to model code."""
    validation = validate_static_extractor_script(source)
    if not inputs or len(inputs) > MAX_INPUT_COUNT:
        raise ValueError("static extractor requires 1..%d inputs" % MAX_INPUT_COUNT)
    total_size = sum(len(value) for value in inputs.values())
    if total_size > MAX_TOTAL_INPUT_BYTES:
        raise ValueError("static extractor inputs exceed the safety limit")
    for name, value in inputs.items():
        if not INPUT_NAME_RE.fullmatch(str(name)):
            raise ValueError("invalid static extractor input name: %s" % name)
        if not isinstance(value, bytes):
            raise ValueError("static extractor inputs must contain bytes")
    try:
        json.dumps(parameters, ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise ValueError("static extractor parameters must be JSON-compatible") from exc

    scratch_dir.mkdir(parents=True, exist_ok=True)
    input_dir = scratch_dir / "inputs"
    input_dir.mkdir(exist_ok=True)
    manifest_inputs = []
    for name, value in sorted(inputs.items()):
        path = input_dir / ("%s.bin" % name)
        path.write_bytes(value)
        manifest_inputs.append({
            "name": name,
            "path": str(path),
            "size": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
        })
    manifest_path = scratch_dir / "input_manifest.json"
    manifest_path.write_text(
        json.dumps(
            {"inputs": manifest_inputs, "parameters": dict(parameters)},
            indent=2,
            sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )
    artifact_path = scratch_dir / "artifact.bin"
    result_path = scratch_dir / "result.json"
    wrapper_path = scratch_dir / "static_extractor_wrapper.py"
    artifact_path.unlink(missing_ok=True)
    result_path.unlink(missing_ok=True)
    # A prior attempt deliberately leaves the trusted wrapper read/execute-only.
    # Remove it before staging an exact retry instead of trying to overwrite it.
    wrapper_path.unlink(missing_ok=True)
    encoded_source = base64.b64encode(source.encode("utf-8")).decode("ascii")
    wrapper = '''#!/usr/bin/env python3
import base64
import binascii
import bz2
import gzip
import hashlib
import json
import lzma
import math
import re
import struct
import zlib
from types import SimpleNamespace

%s

SOURCE = base64.b64decode(%s).decode("utf-8")
MANIFEST_PATH = %s
ARTIFACT_PATH = %s
RESULT_PATH = %s
MAX_OUTPUT_BYTES = %d
MAX_REPORT_BYTES = %d

SAFE_BUILTINS = {
    "Exception": Exception,
    "ValueError": ValueError,
    "abs": abs,
    "all": all,
    "any": any,
    "bool": bool,
    "bytes": bytes,
    "bytearray": bytearray,
    "chr": chr,
    "dict": dict,
    "enumerate": enumerate,
    "filter": filter,
    "float": float,
    "hex": hex,
    "int": int,
    "isinstance": isinstance,
    "len": len,
    "list": list,
    "map": map,
    "max": max,
    "min": min,
    "next": next,
    "oct": oct,
    "ord": ord,
    "pow": pow,
    "range": range,
    "repr": repr,
    "reversed": reversed,
    "round": round,
    "set": set,
    "slice": slice,
    "sorted": sorted,
    "str": str,
    "sum": sum,
    "tuple": tuple,
    "zip": zip,
}

payload = {"ok": False}
try:
    with open(MANIFEST_PATH, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    inputs = {}
    for row in manifest["inputs"]:
        with open(row["path"], "rb") as handle:
            value = handle.read()
        if len(value) != row["size"] or hashlib.sha256(value).hexdigest() != row["sha256"]:
            raise ValueError("staged input integrity mismatch: %%s" %% row["name"])
        inputs[row["name"]] = value
    approved = %s
    modules = {name: globals()[name] for name in approved}
    scope = {
        "__builtins__": SAFE_BUILTINS,
        "inputs": inputs,
        "parameters": manifest.get("parameters") or {},
        "bz2_decompress": bz2.decompress,
        "gzip_decompress": gzip.decompress,
        "lzma_decompress": lzma.decompress,
        **{name: SimpleNamespace(**{member: getattr(module, member)
                                   for member in approved[name].split()})
           for name, module in modules.items()},
    }
    # All input is already in memory. Only the two declared outputs are open;
    # the model cannot open other files or launch/execute native code afterward.
    artifact_handle = open(ARTIFACT_PATH, "wb")
    result_handle = open(RESULT_PATH, "w", encoding="utf-8")
    install_compute_filter()
    exec(compile(SOURCE, "<model-static-extractor>", "exec"), scope, scope)
    artifact = scope.get("artifact")
    if not isinstance(artifact, (bytes, bytearray)):
        raise ValueError("artifact must be bytes or bytearray")
    artifact = bytes(artifact)
    if not artifact:
        raise ValueError("artifact is empty")
    if len(artifact) > MAX_OUTPUT_BYTES:
        raise ValueError("artifact exceeds the output safety limit")
    artifact_handle.write(artifact)
    artifact_handle.close()
    report = scope.get("report")
    report_json = json.dumps(report, default=str)
    if len(report_json.encode("utf-8")) > MAX_REPORT_BYTES:
        raise ValueError("report exceeds the diagnostics safety limit")
    report = json.loads(report_json)
    payload = {
        "ok": True,
        "artifact_size": len(artifact),
        "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
        "report": report,
    }
except Exception as exc:
    payload = {"ok": False, "error": "%%s: %%s" %% (type(exc).__name__, exc)}
if "result_handle" not in globals():
    result_handle = open(RESULT_PATH, "w", encoding="utf-8")
json.dump(payload, result_handle, indent=2, sort_keys=True, default=str)
result_handle.close()
''' % (
        Path(__file__).with_name("static_extractor_safety.py").read_text(encoding="utf-8"),
        json.dumps(encoded_source),
        json.dumps(str(manifest_path)),
        json.dumps(str(artifact_path)),
        json.dumps(str(result_path)),
        MAX_OUTPUT_BYTES,
        MAX_REPORT_BYTES,
        repr(APPROVED_MEMBERS),
    )
    wrapper_path.write_text(wrapper, encoding="utf-8")
    wrapper_path.chmod(0o500)
    return {
        "validation": validation,
        "manifest_path": manifest_path,
        "wrapper_path": wrapper_path,
        "artifact_path": artifact_path,
        "result_path": result_path,
        "inputs": [
            {key: row[key] for key in ("name", "size", "sha256")}
            for row in manifest_inputs
        ],
        "total_input_bytes": total_size,
    }
