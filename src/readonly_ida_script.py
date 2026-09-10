"""Documented, validated wrappers for model-authored read-only IDAPython.

The model normally uses the Verified IDA query service.  This module provides a
bounded escape hatch for sample-specific aggregate questions that the query
service cannot yet express.  Model code runs against a disposable IDB copy,
receives only allowlisted IDA APIs plus a stable ``verified`` helper, and must
return one JSON-compatible ``result`` value.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


MAX_SCRIPT_BYTES = 32 * 1024
MAX_SCRIPT_NODES = 20_000
MAX_OUTPUT_BYTES = 64 * 1024
MAX_RESULT_ITEMS = 1_000
MAX_HELPER_SCAN_ITEMS = 100_000
MAX_WALL_SECONDS = 90


class ReadonlyScriptValidationError(ValueError):
    """A model-correctable rejection with structured diagnostics."""

    def __init__(self, errors: list[dict[str, str]]):
        self.errors = errors
        super().__init__("; ".join(error["message"] for error in errors))


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

SAFE_BUILTIN_CALLS = {
    "abs",
    "all",
    "any",
    "bool",
    "bytes",
    "bytearray",
    "chr",
    "dict",
    "enumerate",
    "filter",
    "float",
    "hex",
    "int",
    "isinstance",
    "len",
    "list",
    "map",
    "max",
    "min",
    "next",
    "oct",
    "ord",
    "pow",
    "range",
    "repr",
    "reversed",
    "round",
    "set",
    "slice",
    "sorted",
    "str",
    "sum",
    "tuple",
    "zip",
}

SAFE_VALUE_METHODS = {
    "add",
    "append",
    "count",
    "decode",
    "endswith",
    "extend",
    "find",
    "get",
    "hex",
    "index",
    "items",
    "join",
    "keys",
    "lower",
    "lstrip",
    "partition",
    "replace",
    "reverse",
    "rfind",
    "rpartition",
    "rsplit",
    "rstrip",
    "split",
    "splitlines",
    "startswith",
    "strip",
    "sort",
    "update",
    "setdefault",
    "upper",
    "values",
}

HELPER_METHODS = {
    "bytes",
    "callees",
    "callers",
    "function",
    "input_metadata",
    "instructions",
    "iter_functions",
    "iter_names",
    "iter_strings",
    "pseudocode",
    "segments",
    "type_at",
    "xrefs_from",
    "xrefs_to",
    "bytes_to_int",
    "int_to_bytes",
    "is_ascii_alpha",
    "value_kind",
}

RAW_API_TOPICS: dict[str, dict[str, Any]] = {
    "bounded_values": {
        "summary": (
            "Perform common bounded conversions without relying on Python "
            "methods that are outside the read-only allowlist."
        ),
        "helper_methods": [
            "bytes_to_int",
            "int_to_bytes",
            "is_ascii_alpha",
            "value_kind",
        ],
        "raw_calls": {},
        "examples": [
            "result = verified.bytes_to_int(params['hex_bytes'], byteorder='little')",
            "result = verified.int_to_bytes(params['value'], params['length'], byteorder='little')",
            "result = verified.is_ascii_alpha(params['value'])",
            "result = verified.value_kind(params.get('value'))",
        ],
    },
    "functions": {
        "summary": "Enumerate functions and inspect immutable function metadata.",
        "helper_methods": ["iter_functions", "function"],
        "raw_calls": {
            "idautils.Functions": "Iterate function start addresses.",
            "idautils.FuncItems": "Iterate instruction addresses in one function.",
            "ida_funcs.get_func": "Return the function containing an address.",
            "ida_funcs.get_func_qty": "Return the number of functions.",
            "ida_funcs.getn_func": "Return a function by ordinal.",
            "idc.get_func_name": "Read a function name.",
            "idc.get_func_cmt": "Read a function comment.",
            "idc.get_type": "Read the type at an address.",
        },
        "examples": [
            "result = [f for f in verified.iter_functions() if f['size'] >= params.get('minimum_size', 256)]",
            "result = verified.function(params['address'])",
        ],
    },
    "references": {
        "summary": "Follow code and data references and direct call relationships.",
        "helper_methods": ["xrefs_to", "xrefs_from", "callers", "callees"],
        "raw_calls": {
            "idautils.CodeRefsTo": "Iterate code references to an address.",
            "idautils.CodeRefsFrom": "Iterate code references from an address.",
            "idautils.DataRefsTo": "Iterate data references to an address.",
            "idautils.DataRefsFrom": "Iterate data references from an address.",
            "idautils.XrefsTo": "Iterate typed references to an address.",
            "idautils.XrefsFrom": "Iterate typed references from an address.",
        },
        "examples": [
            "result = verified.callers(params['address'])",
            "result = {'code': verified.xrefs_to(params['address'], kind='code'), 'data': verified.xrefs_to(params['address'], kind='data')}",
        ],
    },
    "instructions": {
        "summary": "Read decoded instructions, operands, and bounded byte ranges.",
        "helper_methods": ["instructions", "bytes"],
        "raw_calls": {
            "idc.generate_disasm_line": "Render one disassembly line.",
            "idc.print_insn_mnem": "Read an instruction mnemonic.",
            "idc.print_operand": "Render an instruction operand.",
            "idc.get_operand_type": "Read an operand type code.",
            "idc.get_operand_value": "Read an operand value.",
            "ida_bytes.get_bytes": "Read mapped bytes.",
            "ida_bytes.get_byte": "Read one mapped byte.",
            "ida_bytes.get_word": "Read one mapped word.",
            "ida_bytes.get_dword": "Read one mapped dword.",
            "ida_bytes.get_qword": "Read one mapped qword.",
        },
        "examples": [
            "result = [i for i in verified.instructions(params['address']) if i['mnemonic'] == 'call']",
            "result = verified.bytes(params['address'], params.get('size', 64))",
        ],
    },
    "catalogs": {
        "summary": "Enumerate segments, names, and detected strings.",
        "helper_methods": ["segments", "iter_names", "iter_strings"],
        "raw_calls": {
            "idautils.Segments": "Iterate segment start addresses.",
            "idautils.Names": "Iterate named addresses.",
            "idautils.Strings": "Iterate detected strings.",
            "ida_segment.getseg": "Return the segment containing an address.",
            "ida_segment.get_segm_by_name": "Return a segment by name.",
            "ida_segment.get_segm_name": "Read a segment name.",
            "ida_segment.get_segm_qty": "Return the number of segments.",
            "ida_segment.getnseg": "Return a segment by ordinal.",
            "ida_name.get_name": "Read the name at an address.",
            "ida_name.get_name_ea": "Resolve a name to an address.",
        },
        "examples": [
            "result = verified.segments()",
            "result = [s for s in verified.iter_strings() if params.get('needle', '').lower() in s['text'].lower()]",
        ],
    },
    "types": {
        "summary": "Read existing types without creating or applying them.",
        "helper_methods": ["type_at"],
        "raw_calls": {
            "idc.get_type": "Read the printed type at an address.",
            "ida_typeinf.get_tinfo": "Read existing type information into a local tinfo object.",
            "ida_typeinf.tinfo_t": "Construct an empty local type-information object.",
        },
        "examples": [
            "result = {'address': params['address'], 'type': verified.type_at(params['address'])}",
        ],
    },
    "decompiler": {
        "summary": "Read Hex-Rays pseudocode on demand; no user metadata is modified.",
        "helper_methods": ["pseudocode"],
        "raw_calls": {
            "ida_hexrays.decompile": "Decompile the function containing an address.",
            "ida_hexrays.init_hexrays_plugin": "Check that Hex-Rays is available.",
        },
        "examples": [
            "result = verified.pseudocode(params['address'])",
        ],
    },
    "metadata": {
        "summary": "Read database, processor, and runtime identity.",
        "helper_methods": ["input_metadata"],
        "raw_calls": {
            "idaapi.get_kernel_version": "Read the installed IDA kernel version.",
            "ida_hexrays.get_hexrays_version": "Read the installed Hex-Rays version.",
            "idc.get_input_file_path": "Read the analyzed input path inside the disposable snapshot.",
            "idc.get_idb_path": "Read the disposable IDB path.",
        },
        "examples": ["result = verified.input_metadata()"],
    },
}

RAW_ALLOWED_ATTRIBUTES = {
    "idaapi.BADADDR",
    "idc.BADADDR",
}

MUTATION_RECOVERY = {
    "ida_name.set_name": "Use ida_name.get_name to inspect names; apply renames with edit_ida.",
    "idc.set_name": "Use idc.get_func_name or ida_name.get_name; apply renames with edit_ida.",
    "idc.SetType": "Use verified.type_at to inspect types; apply types with edit_ida.",
    "idc.set_type": "Use verified.type_at to inspect types; apply types with edit_ida.",
    "idc.set_func_cmt": "Use idc.get_func_cmt to inspect comments; apply comments with edit_ida.",
    "ida_bytes.patch_bytes": "Read bytes with verified.bytes; binary patching is outside the read-only IDAPython interface.",
    "ida_hexrays.rename_lvar": "Inspect locals with inspect_ida_local; rename them with edit_ida.",
    "ida_hexrays.modify_user_lvar_info": "Inspect locals with inspect_ida_local; retype them with edit_ida.",
}


def _all_raw_calls(*, allow_decompiler: bool) -> set[str]:
    calls = {
        name
        for topic in RAW_API_TOPICS.values()
        for name in topic["raw_calls"]
    }
    if not allow_decompiler:
        calls -= set(RAW_API_TOPICS["decompiler"]["raw_calls"])
    return calls


def _root_name(node: ast.AST) -> str | None:
    current = node
    while isinstance(current, ast.Attribute):
        current = current.value
    return current.id if isinstance(current, ast.Name) else None


def _qualified_name(node: ast.AST) -> str | None:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    return ".".join(reversed(parts))


def _validation_error(
    code: str,
    message: str,
    *,
    recovery: str,
) -> dict[str, str]:
    return {"code": code, "message": message, "recovery": recovery}


def capability_catalog(
    topic: str | None = None,
    *,
    runtime: Mapping[str, Any] | None = None,
    allow_decompiler: bool = True,
) -> dict[str, Any]:
    """Return the exact, compact documentation for the permitted surface."""

    if topic and topic not in RAW_API_TOPICS:
        raise ValueError(
            "unknown IDAPython capability topic %r; choose one of: %s"
            % (topic, ", ".join(sorted(RAW_API_TOPICS)))
        )
    selected = [topic] if topic else sorted(RAW_API_TOPICS)
    topics: dict[str, Any] = {}
    for name in selected:
        if name == "decompiler" and not allow_decompiler:
            continue
        value = RAW_API_TOPICS[name]
        topics[name] = {
            "summary": value["summary"],
            "helper_methods": list(value["helper_methods"]),
            "raw_calls": dict(value["raw_calls"]),
            "examples": list(value["examples"]),
        }
    return {
        "schema": "verified_ida.readonly_idapython.capabilities.v1",
        "runtime": dict(runtime or {}),
        "topics": topics,
        "contract": {
            "input": "Read JSON-compatible values from params.",
            "output": "Assign one JSON-compatible value to result.",
            "execution": "A disposable copy of the current component IDB is used.",
            "mutation": "Prohibited; durable changes must use edit_ida.",
            "imports": "Prohibited; verified and allowlisted IDA module proxies are preloaded.",
        },
        "limits": {
            "script_bytes": MAX_SCRIPT_BYTES,
            "ast_nodes": MAX_SCRIPT_NODES,
            "output_bytes": MAX_OUTPUT_BYTES,
            "result_items": MAX_RESULT_ITEMS,
            "helper_scan_items": MAX_HELPER_SCAN_ITEMS,
            "wall_clock_seconds": MAX_WALL_SECONDS,
        },
    }


def validate_readonly_script(
    source: str,
    *,
    allow_decompiler: bool = True,
) -> dict[str, Any]:
    """Validate model code against a positive read-only API contract."""

    encoded = source.encode("utf-8")
    if not encoded or len(encoded) > MAX_SCRIPT_BYTES:
        raise ReadonlyScriptValidationError([
            _validation_error(
                "script_size",
                "read-only IDAPython must contain 1..%d UTF-8 bytes" % MAX_SCRIPT_BYTES,
                recovery="Submit one smaller aggregate analysis script.",
            )
        ])
    try:
        tree = ast.parse(source, mode="exec")
    except SyntaxError as exc:
        raise ReadonlyScriptValidationError([
            _validation_error(
                "syntax_error",
                "Python syntax error at line %s: %s" % (exc.lineno, exc.msg),
                recovery="Correct the reported Python syntax and retry.",
            )
        ]) from None
    nodes = list(ast.walk(tree))
    if len(nodes) > MAX_SCRIPT_NODES:
        raise ReadonlyScriptValidationError([
            _validation_error(
                "script_complexity",
                "read-only IDAPython exceeds the AST node limit",
                recovery="Split the analysis into smaller bounded scripts.",
            )
        ])

    raw_calls = _all_raw_calls(allow_decompiler=allow_decompiler)
    raw_modules = {name.split(".", 1)[0] for name in raw_calls}
    raw_modules.update({name.split(".", 1)[0] for name in RAW_ALLOWED_ATTRIBUTES})
    user_functions = {
        node.name for node in nodes if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    errors: list[dict[str, str]] = []
    helper_calls: set[str] = set()
    observed_raw_calls: set[str] = set()
    assigns_result = False

    for node in nodes:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            errors.append(_validation_error(
                "imports_blocked",
                "imports are not allowed; verified helpers and approved IDA modules are preloaded",
                recovery="Call describe_idapython_capabilities for the preloaded surface.",
            ))
        if isinstance(node, (ast.ClassDef, ast.AsyncFunctionDef, ast.Await, ast.Yield, ast.YieldFrom)):
            errors.append(_validation_error(
                "unsupported_syntax",
                "%s is not supported in bounded read-only IDAPython" % type(node).__name__,
                recovery="Use synchronous functions, loops, and comprehensions.",
            ))
        if isinstance(node, ast.Delete):
            errors.append(_validation_error(
                "unsupported_syntax",
                "delete statements are not supported in bounded read-only IDAPython",
                recovery="Build a new local JSON-compatible value instead of deleting state.",
            ))
        if isinstance(node, ast.Name) and node.id in BLOCKED_NAMES:
            errors.append(_validation_error(
                "blocked_name",
                "blocked Python name: %s" % node.id,
                recovery="Use params, verified helpers, and JSON-compatible local values only.",
            ))
        if isinstance(node, ast.Attribute) and node.attr.startswith("_"):
            errors.append(_validation_error(
                "private_attribute",
                "private or dunder attribute access is not allowed: %s" % node.attr,
                recovery="Use documented public helper methods and fields.",
            ))
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Attribute):
                    errors.append(_validation_error(
                        "attribute_assignment_blocked",
                        "attribute assignment is not allowed in read-only IDAPython",
                        recovery="Compute a local result; use edit_ida for durable IDA changes.",
                    ))
                if isinstance(target, ast.Name) and target.id == "result":
                    assigns_result = True
                if isinstance(target, ast.Name) and target.id in ({"verified", "params"} | raw_modules):
                    errors.append(_validation_error(
                        "protected_binding",
                        "cannot rebind protected read-only name: %s" % target.id,
                        recovery="Store intermediate state under a different local variable.",
                    ))
        if not isinstance(node, ast.Attribute):
            continue
        root = _root_name(node)
        qualified = _qualified_name(node)
        if root in raw_modules and qualified not in raw_calls and qualified not in RAW_ALLOWED_ATTRIBUTES:
            recovery = MUTATION_RECOVERY.get(
                str(qualified),
                "Use describe_idapython_capabilities to choose an allowlisted read-only API.",
            )
            errors.append(_validation_error(
                "blocked_ida_api",
                "IDA API is not in the read-only allowlist: %s" % qualified,
                recovery=recovery,
            ))

    for node in nodes:
        if not isinstance(node, ast.Call):
            continue
        qualified = _qualified_name(node.func)
        root = _root_name(node.func)
        if isinstance(node.func, ast.Name):
            if node.func.id not in SAFE_BUILTIN_CALLS and node.func.id not in user_functions:
                errors.append(_validation_error(
                    "call_not_allowed",
                    "call target is not allowlisted: %s" % node.func.id,
                    recovery="Use a safe builtin, a locally defined synchronous function, or verified helper.",
                ))
        elif root == "verified":
            method = str(qualified or "").split(".", 1)[-1]
            if qualified not in {"verified.%s" % name for name in HELPER_METHODS}:
                errors.append(_validation_error(
                    "helper_not_allowed",
                    "unknown verified helper: %s" % qualified,
                    recovery="Call describe_idapython_capabilities for helper documentation.",
                ))
            else:
                helper_calls.add(method)
        elif root in raw_modules:
            if qualified in raw_calls:
                observed_raw_calls.add(str(qualified))
        elif isinstance(node.func, ast.Attribute) and node.func.attr not in SAFE_VALUE_METHODS:
            method_recovery = {
                "from_bytes": "Use verified.bytes_to_int(value, byteorder=..., signed=...).",
                "to_bytes": "Use verified.int_to_bytes(value, length, byteorder=..., signed=...).",
                "isalpha": "Use verified.is_ascii_alpha(value).",
            }.get(
                node.func.attr,
                "Use documented verified helpers or JSON-compatible value methods.",
            )
            errors.append(_validation_error(
                "method_not_allowed",
                "method call is not allowed on model values: %s" % node.func.attr,
                recovery=method_recovery,
            ))
        elif not isinstance(node.func, (ast.Attribute, ast.Name)):
            errors.append(_validation_error(
                "dynamic_call",
                "dynamic call targets are not allowed",
                recovery="Call a documented helper or direct allowlisted API.",
            ))

    if not assigns_result:
        errors.append(_validation_error(
            "missing_result",
            "read-only IDAPython must assign a JSON-compatible value to result",
            recovery="End the script by assigning the bounded report to result.",
        ))
    if errors:
        deduped = []
        seen = set()
        for error in errors:
            key = (error["code"], error["message"])
            if key not in seen:
                seen.add(key)
                deduped.append(error)
        raise ReadonlyScriptValidationError(deduped)
    return {
        "schema": "verified_ida.readonly_idapython.validation.v1",
        "node_count": len(nodes),
        "script_bytes": len(encoded),
        "script_sha256": hashlib.sha256(encoded).hexdigest(),
        "decompiler_access": bool(allow_decompiler),
        "helper_calls": sorted(helper_calls),
        "raw_idapython_calls": sorted(observed_raw_calls),
        "imports_allowed": False,
        "mutation_allowed": False,
    }


def _runtime_source(*, allow_decompiler: bool) -> str:
    """Return trusted IDA-side helper code embedded in the generated wrapper."""

    raw_by_module: dict[str, set[str]] = {}
    for qualified in _all_raw_calls(allow_decompiler=allow_decompiler):
        module, attribute = qualified.split(".", 1)
        raw_by_module.setdefault(module, set()).add(attribute)
    for qualified in RAW_ALLOWED_ATTRIBUTES:
        module, attribute = qualified.split(".", 1)
        raw_by_module.setdefault(module, set()).add(attribute)
    allowed_json = json.dumps(
        {name: sorted(values) for name, values in raw_by_module.items()},
        sort_keys=True,
    )
    return r'''
class _ReadOnlyModuleProxy:
    __slots__ = ("_module", "_allowed", "_name")

    def __init__(self, name, module, allowed):
        object.__setattr__(self, "_name", name)
        object.__setattr__(self, "_module", module)
        object.__setattr__(self, "_allowed", frozenset(allowed))

    def __getattribute__(self, attribute):
        if attribute in {"_module", "_allowed", "_name", "__class__"}:
            return object.__getattribute__(self, attribute)
        allowed = object.__getattribute__(self, "_allowed")
        if attribute not in allowed:
            name = object.__getattribute__(self, "_name")
            raise AttributeError("%%s.%%s is not available in read-only IDAPython" %% (name, attribute))
        return getattr(object.__getattribute__(self, "_module"), attribute)

    def __setattr__(self, _name, _value):
        raise AttributeError("read-only module proxies cannot be modified")


def _parse_ea(value):
    if isinstance(value, str):
        return int(value, 0)
    return int(value)


def _hex_ea(value):
    return None if value is None or int(value) == int(idaapi.BADADDR) else hex(int(value))


def _function_row(func):
    if func is None:
        return None
    start = int(func.start_ea)
    end = int(func.end_ea)
    return {
        "address": hex(start),
        "end": hex(end),
        "size": max(0, end - start),
        "name": idc.get_func_name(start) or "",
        "type": idc.get_type(start) or "",
        "comment": idc.get_func_cmt(start, 1) or idc.get_func_cmt(start, 0) or "",
        "flags": int(func.flags),
    }


class _VerifiedReadOnly:
    __slots__ = ("_allow_decompiler",)

    def __init__(self, allow_decompiler):
        object.__setattr__(self, "_allow_decompiler", bool(allow_decompiler))

    def __setattr__(self, _name, _value):
        raise AttributeError("verified helper is read-only")

    def input_metadata(self):
        try:
            hexrays_version = ida_hexrays.get_hexrays_version()
        except Exception:
            hexrays_version = None
        return {
            "ida_version": idaapi.get_kernel_version(),
            "hexrays_version": hexrays_version,
            "processor": ida_ida.inf_get_procname(),
            "input_file": idc.get_input_file_path(),
            "idb_path": idc.get_idb_path(),
            "image_base": _hex_ea(ida_nalt.get_imagebase()),
        }

    def bytes_to_int(self, value, byteorder="little", signed=False):
        if byteorder not in {"little", "big"}:
            raise ValueError("byteorder must be 'little' or 'big'")
        if isinstance(value, str):
            text = value.strip().replace(" ", "")
            if len(text) > 2097152:
                raise ValueError("hex input exceeds 1048576 bytes")
            value = bytes.fromhex(text)
        elif isinstance(value, (list, tuple)):
            if len(value) > 1048576:
                raise ValueError("byte sequence exceeds 1048576 bytes")
            value = bytes(value)
        elif isinstance(value, bytearray):
            value = bytes(value)
        if not isinstance(value, bytes):
            raise ValueError("value must be bytes, a byte list, or a hex string")
        if len(value) > 1048576:
            raise ValueError("byte sequence exceeds 1048576 bytes")
        return int.from_bytes(value, byteorder=byteorder, signed=bool(signed))

    def int_to_bytes(self, value, length, byteorder="little", signed=False):
        count = int(length)
        if count < 0 or count > 1048576:
            raise ValueError("length must be between 0 and 1048576")
        if byteorder not in {"little", "big"}:
            raise ValueError("byteorder must be 'little' or 'big'")
        return int(value).to_bytes(
            count,
            byteorder=byteorder,
            signed=bool(signed),
        ).hex()

    def is_ascii_alpha(self, value):
        text = str(value)
        return bool(text) and all(
            ("A" <= character <= "Z") or ("a" <= character <= "z")
            for character in text
        )

    def value_kind(self, value):
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, int):
            return "integer"
        if isinstance(value, float):
            return "number"
        if isinstance(value, str):
            return "string"
        if isinstance(value, (list, tuple)):
            return "array"
        if isinstance(value, dict):
            return "object"
        if isinstance(value, (bytes, bytearray)):
            return "bytes"
        return "unsupported"

    def iter_functions(self, start=None, end=None, limit=%d):
        lower = None if start is None else _parse_ea(start)
        upper = None if end is None else _parse_ea(end)
        bounded = max(1, min(int(limit), %d))
        count = 0
        for ea in idautils.Functions():
            value = int(ea)
            if lower is not None and value < lower:
                continue
            if upper is not None and value >= upper:
                continue
            row = _function_row(ida_funcs.get_func(value))
            if row is not None:
                yield row
                count += 1
                if count >= bounded:
                    break

    def function(self, address):
        return _function_row(ida_funcs.get_func(_parse_ea(address)))

    def segments(self):
        rows = []
        for ea in idautils.Segments():
            seg = ida_segment.getseg(ea)
            if seg is None:
                continue
            rows.append({
                "name": ida_segment.get_segm_name(seg) or "",
                "start": hex(int(seg.start_ea)),
                "end": hex(int(seg.end_ea)),
                "size": max(0, int(seg.end_ea - seg.start_ea)),
                "permissions": int(seg.perm),
            })
        return rows

    def iter_names(self, limit=%d):
        bounded = max(1, min(int(limit), %d))
        for index, (ea, name) in enumerate(idautils.Names()):
            if index >= bounded:
                break
            yield {"address": hex(int(ea)), "name": str(name)}

    def iter_strings(self, limit=%d):
        bounded = max(1, min(int(limit), %d))
        strings = idautils.Strings()
        try:
            strings.setup(strtypes=[0, 1, 2, 3, 4, 5, 6, 7])
        except Exception:
            pass
        for index, item in enumerate(strings):
            if index >= bounded:
                break
            yield {
                "address": hex(int(item.ea)),
                "length": int(item.length),
                "type": int(item.strtype),
                "text": str(item),
            }

    def xrefs_to(self, address, kind="both", limit=1000):
        ea = _parse_ea(address)
        bounded = max(1, min(int(limit), %d))
        rows = []
        if kind in {"both", "code"}:
            rows.extend({"from": hex(int(ref)), "kind": "code"} for ref in idautils.CodeRefsTo(ea, False))
        if kind in {"both", "data"}:
            rows.extend({"from": hex(int(ref)), "kind": "data"} for ref in idautils.DataRefsTo(ea))
        return rows[:bounded]

    def xrefs_from(self, address, kind="both", limit=1000):
        ea = _parse_ea(address)
        bounded = max(1, min(int(limit), %d))
        rows = []
        if kind in {"both", "code"}:
            rows.extend({"to": hex(int(ref)), "kind": "code"} for ref in idautils.CodeRefsFrom(ea, False))
        if kind in {"both", "data"}:
            rows.extend({"to": hex(int(ref)), "kind": "data"} for ref in idautils.DataRefsFrom(ea))
        return rows[:bounded]

    def callers(self, address, limit=1000):
        func = ida_funcs.get_func(_parse_ea(address))
        if func is None:
            return []
        starts = set()
        for ref in idautils.CodeRefsTo(func.start_ea, False):
            caller = ida_funcs.get_func(ref)
            if caller is not None:
                starts.add(int(caller.start_ea))
        return [_function_row(ida_funcs.get_func(ea)) for ea in sorted(starts)[:max(1, min(int(limit), %d))]]

    def callees(self, address, limit=1000):
        func = ida_funcs.get_func(_parse_ea(address))
        if func is None:
            return []
        starts = set()
        for item_ea in idautils.FuncItems(func.start_ea):
            for ref in idautils.CodeRefsFrom(item_ea, False):
                callee = ida_funcs.get_func(ref)
                if callee is not None:
                    starts.add(int(callee.start_ea))
        return [_function_row(ida_funcs.get_func(ea)) for ea in sorted(starts)[:max(1, min(int(limit), %d))]]

    def instructions(self, address, limit=10000):
        func = ida_funcs.get_func(_parse_ea(address))
        if func is None:
            return []
        rows = []
        bounded = max(1, min(int(limit), %d))
        for item_ea in idautils.FuncItems(func.start_ea):
            operands = []
            for index in range(8):
                text = idc.print_operand(item_ea, index)
                if not text:
                    break
                operands.append({
                    "text": text,
                    "type": int(idc.get_operand_type(item_ea, index)),
                    "value": int(idc.get_operand_value(item_ea, index)),
                })
            rows.append({
                "address": hex(int(item_ea)),
                "mnemonic": idc.print_insn_mnem(item_ea) or "",
                "text": idc.generate_disasm_line(item_ea, 0) or "",
                "operands": operands,
            })
            if len(rows) >= bounded:
                break
        return rows

    def bytes(self, address, size):
        count = int(size)
        if count < 0 or count > 1048576:
            raise ValueError("verified.bytes size must be between 0 and 1048576")
        data = ida_bytes.get_bytes(_parse_ea(address), count) or b""
        return {"address": hex(_parse_ea(address)), "size": len(data), "hex": data.hex()}

    def type_at(self, address):
        return idc.get_type(_parse_ea(address)) or ""

    def pseudocode(self, address):
        if not object.__getattribute__(self, "_allow_decompiler"):
            raise ValueError("decompiler access is disabled for this run")
        if not ida_hexrays.init_hexrays_plugin():
            raise ValueError("Hex-Rays is unavailable")
        return str(ida_hexrays.decompile(_parse_ea(address)))


_RAW_ALLOWED = %s
_RAW_MODULES = {
    "ida_bytes": ida_bytes,
    "ida_funcs": ida_funcs,
    "ida_hexrays": ida_hexrays,
    "ida_name": ida_name,
    "ida_segment": ida_segment,
    "ida_typeinf": ida_typeinf,
    "idaapi": idaapi,
    "idautils": idautils,
    "idc": idc,
}
verified = _VerifiedReadOnly(%s)
raw_scope = {
    name: _ReadOnlyModuleProxy(name, module, _RAW_ALLOWED.get(name, []))
    for name, module in _RAW_MODULES.items()
}
''' % (
        MAX_HELPER_SCAN_ITEMS,
        MAX_HELPER_SCAN_ITEMS,
        MAX_HELPER_SCAN_ITEMS,
        MAX_HELPER_SCAN_ITEMS,
        MAX_HELPER_SCAN_ITEMS,
        MAX_HELPER_SCAN_ITEMS,
        MAX_HELPER_SCAN_ITEMS,
        MAX_HELPER_SCAN_ITEMS,
        MAX_HELPER_SCAN_ITEMS,
        MAX_HELPER_SCAN_ITEMS,
        MAX_HELPER_SCAN_ITEMS,
        allowed_json,
        "True" if allow_decompiler else "False",
    )


def write_readonly_wrapper(
    *,
    source: str,
    destination: Path,
    output_path: Path,
    parameters: Mapping[str, Any] | None = None,
    allow_decompiler: bool = True,
    max_output_bytes: int = MAX_OUTPUT_BYTES,
    max_result_items: int = MAX_RESULT_ITEMS,
) -> dict[str, Any]:
    """Write one trusted wrapper for execution against a disposable IDB."""

    validation = validate_readonly_script(source, allow_decompiler=allow_decompiler)
    try:
        parameters_text = json.dumps(dict(parameters or {}), sort_keys=True, ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise ValueError("read-only IDAPython parameters must be JSON-compatible") from exc
    encoded_source = base64.b64encode(source.encode("utf-8")).decode("ascii")
    encoded_parameters = base64.b64encode(parameters_text.encode("utf-8")).decode("ascii")
    trusted_runtime = _runtime_source(allow_decompiler=allow_decompiler)
    rendered = '''#!/usr/bin/env python3
import base64
import json
import sys

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_ida
import ida_name
import ida_nalt
import ida_pro
import ida_segment
import ida_typeinf
import idaapi
import idautils
import idc

SOURCE = base64.b64decode(%s).decode("utf-8")
PARAMETERS = json.loads(base64.b64decode(%s).decode("utf-8"))
OUTPUT = %s
MAX_OUTPUT_BYTES = %d
MAX_RESULT_ITEMS = %d

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

%s

def _normalize_result(value, state, depth=0):
    if depth > 32:
        raise ValueError("result nesting exceeds 32 levels")
    if state["items"] >= MAX_RESULT_ITEMS:
        state["truncated"] = True
        return {"__truncated__": True}
    state["items"] += 1
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (list, tuple)):
        normalized = []
        for item in value:
            if state["items"] >= MAX_RESULT_ITEMS:
                state["truncated"] = True
                normalized.append({"__truncated__": True})
                break
            normalized.append(_normalize_result(item, state, depth + 1))
        return normalized
    if isinstance(value, dict):
        normalized = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("result object keys must be strings")
            if state["items"] >= MAX_RESULT_ITEMS:
                state["truncated"] = True
                normalized["__truncated__"] = True
                break
            normalized[key] = _normalize_result(item, state, depth + 1)
        return normalized
    raise ValueError("result contains non-JSON value: %%s" %% type(value).__name__)

payload = {"ok": False, "stage": "execution"}
try:
    scope = {
        "__builtins__": SAFE_BUILTINS,
        "params": PARAMETERS,
        "verified": verified,
        **raw_scope,
    }
    exec(compile(SOURCE, "<model-readonly-idapython>", "exec"), scope, scope)
    if "result" not in scope:
        raise ValueError("script did not assign result")
    payload["stage"] = "result_validation"
    result_state = {"items": 0, "truncated": False}
    normalized = _normalize_result(scope["result"], result_state)
    if result_state["truncated"]:
        normalized = {
            "schema": "verified_ida.readonly_idapython.bounded_result.v1",
            "data": normalized,
            "has_more": True,
            "returned_aggregate_items": result_state["items"],
            "recovery": (
                "Narrow the query or aggregate the result inside IDA before "
                "returning it."
            ),
        }
    result_text = json.dumps(normalized, sort_keys=True, ensure_ascii=False, allow_nan=False)
    if len(result_text.encode("utf-8")) > MAX_OUTPUT_BYTES:
        normalized = {
            "schema": "verified_ida.readonly_idapython.bounded_result.v1",
            "data": None,
            "has_more": True,
            "serialized_bytes": len(result_text.encode("utf-8")),
            "maximum_output_bytes": MAX_OUTPUT_BYTES,
            "recovery": (
                "The result was valid but too large to transport. Narrow the "
                "query or return counts and a bounded sample."
            ),
        }
        result_text = json.dumps(normalized, sort_keys=True, ensure_ascii=False)
    payload = {
        "ok": True,
        "stage": "completed",
        "result": normalized,
        "runtime": verified.input_metadata(),
        "output_bytes": len(result_text.encode("utf-8")),
    }
except Exception as exc:
    payload["error"] = {"type": type(exc).__name__, "message": str(exc)}

with open(OUTPUT, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=False)
    handle.write("\\n")
ida_pro.qexit(0 if payload["ok"] else 1)
''' % (
        json.dumps(encoded_source),
        json.dumps(encoded_parameters),
        json.dumps(str(output_path)),
        max(1, int(max_output_bytes)),
        max(1, int(max_result_items)),
        trusted_runtime,
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(rendered, encoding="utf-8")
    destination.chmod(0o500)
    return validation
