"""Apply Verified IDA operations and emit independently read-back receipts.

This module runs inside IDA/idat. It contains no model or network access.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from typing import Mapping

SCRIPT_DIR = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", "src"))
sys.path.insert(0, SCRIPT_DIR)

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_netnode
import ida_pro
import ida_typeinf
import idaapi
import idc
import idautils

from ida_backend import save_database
from ida_reader import load_binary
from verified_ida.canonical import (
    canonical_declaration,
    canonical_text,
    compare_desired,
    relationship_key,
    upsert_prefixed_line,
)
from verified_ida.contracts import (
    ContractError,
    build_receipt,
    operation_digest,
    summarize_receipts,
    validate_operation,
)
from verified_ida.backend_limits import function_comment_limits, validate_function_comment

import verified_ida_function_annotations_ida as annotation_adapter
import verified_ida_type_updates_ida as type_adapter


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Apply and verify typed IDA mutations.")
    parser.add_argument("input", help="IDB or I64 to mutate.")
    parser.add_argument("--operations", required=True, help="Verified IDA operation batch JSON.")
    parser.add_argument("--artifact", required=True, help="Open-database artifact identity JSON.")
    parser.add_argument("--receipts", required=True, help="Output receipt batch JSON.")
    parser.add_argument("--registry", help="Persistent operation-id registry JSON.")
    parser.add_argument("--save-as", required=True, help="Output IDB or I64 path.")
    parser.add_argument("--replace-existing-named-types", action="store_true")
    return parser.parse_args(argv)


def _load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _write_json(path, data):
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")


def _parse_address(value):
    if isinstance(value, str):
        return int(value, 0)
    return int(value)


def _target_address(target):
    for key in ("address", "function_address"):
        if target.get(key) not in (None, ""):
            return _parse_address(target[key])
    return None


def _function_start(ea):
    func = ida_funcs.get_func(ea)
    return None if func is None else int(func.start_ea)


def _function_byte_hash(ea):
    func = ida_funcs.get_func(ea)
    if func is None:
        return None
    size = max(0, int(func.end_ea - func.start_ea))
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        chunk_size = min(64 * 1024, size - offset)
        raw = ida_bytes.get_bytes(func.start_ea + offset, chunk_size) or b""
        digest.update(raw)
        if len(raw) < chunk_size:
            digest.update(b"\x00" * (chunk_size - len(raw)))
        offset += chunk_size
    return digest.hexdigest()


def _decompile_digest(ea):
    start = _function_start(ea)
    if start is None:
        return {"available": False, "error": "not_a_function"}
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return {"available": False, "error": "hexrays_unavailable"}
        pseudocode = str(ida_hexrays.decompile(start))
        return {
            "available": True,
            "sha256": hashlib.sha256(pseudocode.encode("utf-8", errors="replace")).hexdigest(),
            "length": len(pseudocode),
        }
    except Exception as exc:
        return {"available": False, "error": str(exc)}


def _refresh_function(ea):
    start = _function_start(ea)
    if start is None:
        return
    try:
        ida_hexrays.mark_cfunc_dirty(start, True)
        ida_hexrays.clear_cached_cfuncs()
    except Exception:
        pass
    try:
        ida_auto.auto_wait()
        ida_hexrays.decompile(start)
    except Exception:
        pass


def _affected_function_addresses(operation):
    kind = operation["kind"]
    target = operation["target"]
    candidates = []
    if kind == "relationship.annotate":
        candidates.extend([target.get("source_address"), target.get("destination_address")])
    elif target.get("function_address") is not None:
        candidates.append(target.get("function_address"))
    elif target.get("address") is not None:
        candidates.append(target.get("address"))
    for value in operation.get("metadata", {}).get("affected_functions") or []:
        candidates.append(value)

    starts = set()
    for value in candidates[:256]:
        try:
            start = _function_start(_parse_address(value))
        except Exception:
            start = None
        if start is not None:
            starts.add(start)

    if kind in {"function.rename", "function.prototype.set"}:
        primary = _function_start(_target_address(target))
        if primary is not None:
            for xref in idautils.CodeRefsTo(primary, False):
                caller = _function_start(int(xref))
                if caller is not None:
                    starts.add(caller)
    elif kind in {"global.rename", "global.type.set", "address.comment.set"}:
        address = _target_address(target)
        for iterator in (idautils.CodeRefsTo(address, False), idautils.DataRefsTo(address)):
            for xref in iterator:
                consumer = _function_start(int(xref))
                if consumer is not None:
                    starts.add(consumer)
    return sorted(starts)[:256]


def _semantic_dependency_artifacts(operation):
    """Measure native IDA neighbors that may inherit a type mutation."""

    kind = operation["kind"]
    target = operation["target"]
    functions = set()
    globals_ = set()
    edges = []
    scan_state = {"items": 0, "truncated": False}

    def add_global(address, *, source_address, relation):
        try:
            item = int(ida_bytes.get_item_head(int(address)))
        except Exception:
            item = int(address)
        if item == idc.BADADDR or _function_start(item) is not None:
            return
        globals_.add(item)
        if len(edges) < 1024:
            edges.append({
                "from": hex(int(source_address)),
                "to": hex(item),
                "kind": relation,
            })

    def add_function(address, *, source_address, relation):
        owner = _function_start(int(address))
        if owner is None:
            add_global(
                address,
                source_address=source_address,
                relation=relation,
            )
            return
        functions.add(owner)
        if len(edges) < 1024:
            edges.append({
                "from": hex(int(source_address)),
                "to": hex(owner),
                "kind": relation,
            })

    def add_function_data_dependencies(function_start):
        """Add one bounded native data-reference hop from an affected caller."""

        for item_ea in idautils.FuncItems(function_start):
            scan_state["items"] += 1
            if scan_state["items"] > 100000:
                scan_state["truncated"] = True
                return
            for data_ref in idautils.DataRefsFrom(int(item_ea)):
                add_global(
                    data_ref,
                    source_address=item_ea,
                    relation="affected_function_data_reference",
                )
                if len(globals_) >= 512:
                    return

    if kind == "function.prototype.set":
        primary = _function_start(_target_address(target))
        if primary is not None:
            for iterator in (
                idautils.CodeRefsTo(primary, False),
                idautils.DataRefsTo(primary),
            ):
                for xref in iterator:
                    add_function(
                        xref,
                        source_address=primary,
                        relation="prototype_target_reference",
                    )
            functions.discard(primary)
            for function_start in sorted(functions)[:256]:
                add_function_data_dependencies(function_start)
                if scan_state["truncated"]:
                    break
    elif kind in {"global.type.set", "global.rename"}:
        address = _target_address(target)
        for iterator in (
            idautils.CodeRefsTo(address, False),
            idautils.DataRefsTo(address),
        ):
            for xref in iterator:
                add_function(
                    xref,
                    source_address=address,
                    relation="global_target_reference",
                )
    return {
        "source": "ida_native_bounded_dependency_graph",
        "function_addresses": [hex(ea) for ea in sorted(functions)[:256]],
        "global_addresses": [hex(ea) for ea in sorted(globals_)[:512]],
        "edges": edges,
        "scan": {
            "function_item_count": scan_state["items"],
            "truncated": scan_state["truncated"],
        },
    }


def _read_folder_fallback(ea):
    start = _function_start(ea)
    if start is None:
        return ""
    comment = "\n".join(
        value
        for value in (
            idc.get_func_cmt(start, 1) or "",
            idc.get_func_cmt(start, 0) or "",
        )
        if value
    )
    matches = re.findall(r"^\[verified-folder\]\s*(.+?)\s*$", comment, flags=re.MULTILINE)
    return matches[-1].strip().strip("/") if matches else ""


def _append_function_line(ea, line):
    start = _function_start(ea)
    if start is None:
        return False
    existing = idc.get_func_cmt(start, 1) or ""
    if line in existing.splitlines():
        return True
    value = (existing.rstrip() + "\n" + line).strip() if existing else line
    return bool(idc.set_func_cmt(start, value, 1))


def _upsert_function_line(ea, prefix, line):
    """Replace one durable summary line instead of accumulating stale versions."""

    start = _function_start(ea)
    if start is None:
        return False
    existing = idc.get_func_cmt(start, 1) or ""
    return bool(idc.set_func_cmt(start, upsert_prefixed_line(existing, prefix, line), 1))


def _upsert_address_line(ea, prefix, line):
    existing = idc.get_cmt(ea, 1) or ""
    return bool(idc.set_cmt(ea, upsert_prefixed_line(existing, prefix, line), 1))


RELATIONSHIP_NODE_NAME = "$ verified_ida_relationships"
RELATIONSHIP_BLOB_TAG = ord("R")


def _relationship_id(target, desired):
    return relationship_key(
        target.get("source_address"),
        target.get("destination_address"),
        desired.get("relationship_kind"),
        target.get("callsite_address"),
    )


def _relationship_record(target, desired):
    relationship_id = _relationship_id(target, desired)
    return {
        "relationship_id": relationship_id,
        "source_address": hex(_parse_address(target.get("source_address"))),
        "callsite_address": (
            hex(_parse_address(target.get("callsite_address")))
            if target.get("callsite_address") not in (None, "") else None
        ),
        "destination_address": hex(_parse_address(target.get("destination_address"))),
        "relationship_kind": str(desired.get("relationship_kind") or "").strip(),
        "description": desired.get("description"),
        "flow": desired.get("flow"),
        "ownership": desired.get("ownership"),
    }


def _legacy_relationship_node(*, create=False):
    if not create:
        try:
            return ida_netnode.netnode(RELATIONSHIP_NODE_NAME)
        except Exception:
            return None
    node = ida_netnode.netnode()
    if not node.create(RELATIONSHIP_NODE_NAME):
        node = ida_netnode.netnode(RELATIONSHIP_NODE_NAME)
    return node


def _relationship_source_node(source, *, create=False):
    """Return size-safe structured storage dedicated to one source function."""

    name = "%s:%x" % (RELATIONSHIP_NODE_NAME, int(source))
    if not create:
        try:
            return ida_netnode.netnode(name)
        except Exception:
            return None
    node = ida_netnode.netnode()
    if not node.create(name):
        node = ida_netnode.netnode(name)
    return node


def _decode_relationship_records(raw):
    if not raw:
        return {}
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    try:
        value = json.loads(raw)
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _relationship_records(source):
    source = int(source)
    source_node = _relationship_source_node(source)
    if source_node is not None:
        records = _decode_relationship_records(
            source_node.getblob(0, RELATIONSHIP_BLOB_TAG)
        )
        if records:
            return records

    # Preserve databases created before per-source blob storage. The first
    # subsequent update migrates this source function into the new node.
    legacy_node = _legacy_relationship_node()
    if legacy_node is None:
        return {}
    return _decode_relationship_records(legacy_node.supstr(source))


def _store_relationship(target, desired):
    source = _parse_address(target.get("source_address"))
    record = _relationship_record(target, desired)
    records = _relationship_records(source)
    records[record["relationship_id"]] = record
    payload = json.dumps(
        records, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return bool(
        _relationship_source_node(source, create=True).setblob(
            payload, 0, RELATIONSHIP_BLOB_TAG
        )
    )


def _relationship_line(target, desired):
    relationship_id = _relationship_id(target, desired)
    destination = target.get("destination_address")
    kind = desired.get("relationship_kind")
    description = canonical_text(desired.get("description")).replace("\n", " ")
    if len(description) > 240:
        description = description[:237] + "..."
    return "[relationship:%s] %s @ %s -> %s (%s): %s" % (
        relationship_id,
        target.get("source_address"),
        target.get("callsite_address") or "legacy",
        destination,
        kind,
        description,
    )


def _relationship_visible_summary(target, relationship_id):
    prefix = "[relationship:%s]" % relationship_id
    callsite = target.get("callsite_address")
    if callsite not in (None, ""):
        ea = _parse_address(callsite)
        for comment in (idc.get_cmt(ea, 1) or "", idc.get_cmt(ea, 0) or ""):
            for line in comment.splitlines():
                if line.startswith(prefix):
                    return line
    source = _parse_address(target.get("source_address"))
    start = _function_start(source)
    if start is None:
        return ""
    for comment in (
        idc.get_func_cmt(start, 1) or "",
        idc.get_func_cmt(start, 0) or "",
    ):
        for line in comment.splitlines():
            if line.startswith(prefix):
                return line
    return ""


def _read_relationship(target, desired):
    source = _parse_address(target.get("source_address"))
    relationship_id = _relationship_id(target, desired)
    record = _relationship_records(source).get(relationship_id)
    if isinstance(record, dict):
        return {
            "description": record.get("description"),
            "relationship_kind": record.get("relationship_kind"),
            "relationship_id": relationship_id,
            "record": record,
            "storage": "ida_netnode",
            "visible_summary": _relationship_visible_summary(
                target, relationship_id
            ),
        }
    # Read legacy databases produced before structured netnode storage.
    start = _function_start(source)
    if start is None:
        return {"description": "", "relationship_id": relationship_id}
    prefix = "[verified-relationship:%s] " % relationship_id
    for comment in (
        idc.get_func_cmt(start, 1) or "",
        idc.get_func_cmt(start, 0) or "",
    ):
        for comment_line in comment.splitlines():
            if not comment_line.startswith(prefix):
                continue
            try:
                record = json.loads(comment_line[len(prefix):])
                return {
                    "description": record.get("description"),
                    "relationship_kind": record.get("relationship_kind"),
                    "relationship_id": relationship_id,
                    "record": record,
                }
            except Exception:
                break
    return {"description": "", "relationship_id": relationship_id}


def _set_function_behavior_comment(start, comment, repeatable):
    selected_slot = 1 if repeatable else 0
    existing = idc.get_func_cmt(start, selected_slot) or ""
    durable = [
        line
        for line in existing.splitlines()
        if line.startswith("[verified-folder] ")
        or line.startswith("[verified-relationship:")
        or line.startswith("[relationship:")
    ]
    value = canonical_text(comment)
    if durable:
        value = (value + "\n" + "\n".join(durable)).strip()
    validate_function_comment(value, function_comment_limits(idaapi.get_kernel_version(), ida_pro.MAXSTR))
    return bool(idc.set_func_cmt(start, value, selected_slot))


def _set_address_behavior_comment(ea, comment, repeatable):
    selected_slot = 1 if repeatable else 0
    existing = idc.get_cmt(ea, selected_slot) or ""
    durable = [
        line for line in existing.splitlines()
        if line.startswith("[relationship:")
        or line.startswith("[verified-relationship:")
    ]
    value = canonical_text(comment)
    if durable:
        value = (value + "\n" + "\n".join(durable)).strip()
    return bool(idc.set_cmt(ea, value, selected_slot))


def _print_named_type(name):
    tif = ida_typeinf.tinfo_t()
    loaded = False
    for til in (None, getattr(ida_typeinf, "get_idati", lambda: None)()):
        try:
            if tif.get_named_type(til, name):
                loaded = True
                break
        except Exception:
            continue
    if not loaded:
        return ""
    flags = 0
    for flag_name in ("PRTYPE_MULTI", "PRTYPE_TYPE", "PRTYPE_SEMI"):
        flags |= int(getattr(ida_typeinf, flag_name, 0) or 0)
    printer = getattr(ida_typeinf, "print_tinfo", None)
    if callable(printer):
        for args in (("", 0, 0, flags, tif, name, ""), ("", 0, 0, flags, tif, name)):
            try:
                rendered = printer(*args)
                if rendered:
                    return str(rendered)
            except Exception:
                continue
    try:
        return str(tif.dstr())
    except Exception:
        return name


def _parse_declaration_tinfo(declaration):
    text = str(declaration or "").strip()
    if not text:
        return None
    candidates = [text]
    open_paren = text.find("(")
    if open_paren > 0:
        prefix = text[:open_paren]
        match = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*$", prefix)
        reserved = {
            "void", "char", "short", "int", "long", "float", "double",
            "signed", "unsigned", "const", "volatile", "struct", "union", "enum",
            "__cdecl", "__stdcall", "__fastcall", "__thiscall", "__usercall",
        }
        if match and match.group(1) not in reserved:
            candidates.append(text[:match.start(1)] + text[match.end(1):])
        elif match:
            candidates.append(text[:open_paren].rstrip() + " __vida_proto" + text[open_paren:])
    for candidate in candidates:
        for flags in (
            ida_typeinf.PT_SIL,
            ida_typeinf.PT_SIL | int(getattr(ida_typeinf, "PT_TYP", 0) or 0),
            ida_typeinf.PT_SIL | int(getattr(ida_typeinf, "PT_VAR", 0) or 0),
        ):
            tif = ida_typeinf.tinfo_t()
            try:
                if ida_typeinf.parse_decl(tif, None, candidate, flags) and not tif.empty():
                    return tif
            except Exception:
                continue
        try:
            parsed = idc.parse_decl(candidate, idc.PT_SIL)
            if parsed is not None:
                _name, type_bytes, field_bytes = parsed
                tif = ida_typeinf.tinfo_t()
                if tif.deserialize(None, type_bytes, field_bytes) and not tif.empty():
                    return tif
        except Exception:
            pass
    try:
        parsed = type_adapter._parse_lvar_type_tinfo(text)
        if parsed is not None and not parsed.empty():
            return parsed
    except Exception:
        pass
    return None


def _tinfo_signature(tif):
    if tif is None:
        return None
    try:
        size = int(tif.get_size())
    except Exception:
        size = None
    try:
        if tif.is_udt():
            details = ida_typeinf.udt_type_data_t()
            if tif.get_udt_details(details):
                return {
                    "kind": "udt",
                    "udt_kind": "union" if bool(getattr(tif, "is_union", lambda: False)()) else "struct",
                    "size": size,
                    "members": [
                        {
                            "name": str(getattr(member, "name", "") or ""),
                            "offset_bits": int(getattr(member, "offset", 0) or 0),
                            "size_bits": int(getattr(member, "size", 0) or 0),
                            "type": type_adapter._normalize_type_text(member.type.dstr()),
                        }
                        for member in list(details)
                    ],
                }
    except Exception:
        pass
    try:
        if tif.is_enum():
            details = ida_typeinf.enum_type_data_t()
            if tif.get_enum_details(details):
                return {
                    "kind": "enum",
                    "size": size,
                    "members": [
                        {
                            "name": str(getattr(member, "name", "") or ""),
                            "value": int(getattr(member, "value", 0) or 0),
                        }
                        for member in list(details)
                    ],
                }
    except Exception:
        pass
    try:
        if tif.is_array():
            element = None
            count = None
            try:
                element = tif.get_array_element()
                count = int(tif.get_array_nelems())
            except Exception:
                details = ida_typeinf.array_type_data_t()
                if tif.get_array_details(details):
                    element = details.elem_type
                    count = int(details.nelems)
            return {
                "kind": "array",
                "size": size,
                "count": count,
                "element": _tinfo_signature(element),
            }
    except Exception:
        pass
    try:
        if tif.is_bool():
            return {"kind": "scalar", "category": "bool", "size": size}
    except Exception:
        pass
    try:
        if tif.is_integral():
            signed = None
            try:
                signed = bool(tif.is_signed())
            except Exception:
                try:
                    signed = not bool(tif.is_unsigned())
                except Exception:
                    pass
            return {"kind": "scalar", "category": "integer", "size": size, "signed": signed}
    except Exception:
        pass
    try:
        if tif.is_floating():
            return {"kind": "scalar", "category": "floating", "size": size}
    except Exception:
        pass
    try:
        if tif.is_ptr():
            pointed = None
            try:
                pointed = tif.get_pointed_object()
            except Exception:
                candidate = ida_typeinf.tinfo_t()
                try:
                    if tif.get_pointed_object(candidate):
                        pointed = candidate
                except Exception:
                    pass
            return {"kind": "pointer", "size": size, "pointed_to": _tinfo_signature(pointed)}
    except Exception:
        pass
    try:
        rendered = type_adapter._normalize_type_text(tif.dstr())
    except Exception:
        rendered = ""
    return {"kind": "type", "size": size, "declaration": rendered}


def _named_type_tinfo(name):
    tif = ida_typeinf.tinfo_t()
    for til in (None, getattr(ida_typeinf, "get_idati", lambda: None)()):
        try:
            if tif.get_named_type(til, name):
                return tif
        except Exception:
            continue
    return None


def _compare_operation(operation, observed):
    kind = operation["kind"]
    desired = operation["desired"]
    if kind in {"function.comment.set", "address.comment.set"}:
        filtered = dict(observed)
        filtered["comment"] = "\n".join(
            line
            for line in canonical_text(observed.get("comment")).splitlines()
            if not line.startswith("[verified-folder] ")
            and not line.startswith("[verified-relationship:")
            and not line.startswith("[relationship:")
        ).strip()
        return compare_desired(kind, desired, filtered)
    if kind == "relationship.annotate":
        keys = ["relationship_kind", "description"]
        keys.extend(key for key in ("flow", "ownership") if key in desired)
        expected = {key: desired.get(key) for key in keys}
        record = observed.get("record") or {}
        actual = {key: record.get(key) for key in keys}
        expected["description"] = canonical_text(expected.get("description"))
        actual["description"] = canonical_text(actual.get("description"))
        visible_summary = canonical_text(observed.get("visible_summary"))
        expected_summary = canonical_text(
            _relationship_line(operation["target"], desired)
        )
        visible_summary_matches = visible_summary == expected_summary
        return expected == actual and visible_summary_matches, {
            "mode": "structured_relationship",
            "expected": expected,
            "actual": actual,
            "visible_summary": {
                "expected": expected_summary,
                "actual": visible_summary,
                "matches": visible_summary_matches,
            },
        }
    if kind == "named_type.create_or_update":
        desired_tif = _parse_declaration_tinfo(desired.get("declaration"))
        expected = _tinfo_signature(desired_tif)
        actual = observed.get("signature")
        if expected is not None and actual is not None:
            return expected == actual, {"mode": "ida_tinfo_structure", "expected": expected, "actual": actual}
    if kind in {"function.prototype.set", "local.type.set", "global.type.set"}:
        desired_tif = _parse_declaration_tinfo(desired.get("declaration"))
        observed_tif = _parse_declaration_tinfo(observed.get("declaration"))
        expected = _tinfo_signature(desired_tif)
        actual = _tinfo_signature(observed_tif)
        if expected is not None and actual is not None:
            return expected == actual, {"mode": "ida_tinfo", "expected": expected, "actual": actual}
    return compare_desired(kind, desired, observed)


def _local_item(operation):
    target = operation["target"]
    desired = operation["desired"]
    return {
        "variable": target.get("current_name"),
        "address": target.get("function_address"),
        "parameter": target.get("current_name") if target.get("is_parameter") else None,
        "target": target.get("current_name"),
        "lvar_index": target.get("lvar_index"),
        "is_parameter": target.get("is_parameter"),
        "location": target.get("location") or {},
        "current_type": target.get("current_type"),
        "use_site": target.get("use_site"),
        "proposed_name": desired.get("name"),
        "proposed_type": desired.get("declaration"),
    }


def _read_local(operation):
    item = _local_item(operation)
    ea = _parse_address(item["address"])
    if _function_start(ea) is None:
        return {"error": "not_a_function"}
    try:
        cfunc = ida_hexrays.decompile(ea)
        lvar, reason = type_adapter._find_lvar(cfunc, item, check_current_type=False)
        if lvar is None:
            return {"error": reason}
        return {
            "name": str(getattr(lvar, "name", "") or ""),
            "declaration": type_adapter._lvar_type_text(lvar),
            "is_parameter": bool(type_adapter._call_or_value(lvar, "is_arg_var", False)),
            "location_kind": type_adapter._lvar_location_kind(lvar),
            "stack_offset": type_adapter._lvar_stack_offset(lvar),
        }
    except Exception as exc:
        return {"error": str(exc)}


def read_state(operation):
    kind = operation["kind"]
    target = operation["target"]
    desired = operation["desired"]
    if kind == "function.rename":
        ea = _target_address(target)
        start = _function_start(ea)
        return {"name": idc.get_func_name(start) if start is not None else ""}
    if kind == "function.comment.set":
        ea = _target_address(target)
        start = _function_start(ea)
        repeatable = 1 if desired.get("repeatable", True) else 0
        nonrepeatable = (
            idc.get_func_cmt(start, 0) if start is not None else ""
        ) or ""
        repeatable_comment = (
            idc.get_func_cmt(start, 1) if start is not None else ""
        ) or ""
        return {
            "name": idc.get_func_name(start) if start is not None else "",
            "comment": (
                repeatable_comment if repeatable else nonrepeatable
            ),
            "repeatable": bool(repeatable),
            "comments": {
                "nonrepeatable": nonrepeatable,
                "repeatable": repeatable_comment,
            },
        }
    if kind == "address.comment.set":
        ea = _target_address(target)
        repeatable = 1 if desired.get("repeatable") else 0
        nonrepeatable = idc.get_cmt(ea, 0) or ""
        repeatable_comment = idc.get_cmt(ea, 1) or ""
        return {
            "comment": repeatable_comment if repeatable else nonrepeatable,
            "repeatable": bool(repeatable),
            "comments": {
                "nonrepeatable": nonrepeatable,
                "repeatable": repeatable_comment,
            },
        }
    if kind == "function.folder.set":
        ea = _target_address(target)
        start = _function_start(ea)
        return {
            "name": idc.get_func_name(start) if start is not None else "",
            "folder": _read_folder_fallback(ea),
            "source": "verified_folder_annotation",
        }
    if kind == "function.prototype.set":
        ea = _target_address(target)
        start = _function_start(ea)
        return {
            "name": idc.get_func_name(start) if start is not None else "",
            "declaration": "" if start is None else (idc.get_type(start) or ""),
        }
    if kind in {"local.rename", "local.type.set"}:
        return _read_local(operation)
    if kind == "global.rename":
        ea = _target_address(target)
        return {"name": idc.get_name(ea) or ""}
    if kind == "global.type.set":
        ea = _target_address(target)
        return {"name": idc.get_name(ea) or "", "declaration": idc.get_type(ea) or ""}
    if kind == "named_type.create_or_update":
        name = str(target.get("name") or "")
        tif = _named_type_tinfo(name)
        return {"name": name, "declaration": _print_named_type(name), "signature": _tinfo_signature(tif)}
    if kind == "relationship.annotate":
        return _read_relationship(target, desired)
    return {"error": "unsupported_operation"}


def _preconditions_match(operation, before):
    preconditions = dict(operation.get("preconditions") or {})
    target = operation.get("target") or {}
    if target.get("current_name") not in (None, "") and not ({"name", "current_name"} & set(preconditions)):
        preconditions["current_name"] = target["current_name"]
    if (
        target.get("current_type") not in (None, "")
        and ("type" in before or "declaration" in before)
        and not ({"type", "declaration", "current_type"} & set(preconditions))
    ):
        preconditions["current_type"] = target["current_type"]
    if target.get("declaration_digest") not in (None, "") and "declaration_digest" not in preconditions:
        preconditions["declaration_digest"] = target["declaration_digest"]
    mismatches = []
    for field, expected in preconditions.items():
        if field == "database_revision":
            continue
        observed_field = {
            "current_name": "name",
            "current_type": "type" if "type" in before else "declaration",
        }.get(field, field)
        actual = before.get(observed_field)
        if field == "comment_digest":
            actual = hashlib.sha256(canonical_text(before.get("comment")).encode("utf-8")).hexdigest()
        elif field == "declaration_digest":
            actual = hashlib.sha256(canonical_declaration(before.get("declaration")).encode("utf-8")).hexdigest()
        actual_text = "" if actual is None else str(actual)
        expected_text = "" if expected is None else str(expected)
        if actual_text != expected_text:
            mismatches.append({"field": field, "expected": expected, "actual": actual})
    return not mismatches, mismatches


def _live_target_error(operation):
    target = operation["target"]
    target_kind = target["kind"]
    if target_kind in {"function", "folder_entry"}:
        ea = _target_address(target)
        start = _function_start(ea)
        if start is None:
            return "target address is not inside a function"
        if start != ea:
            return "target address is not the function start (resolved %s)" % hex(start)
    elif target_kind == "local_variable":
        ea = _parse_address(target.get("function_address"))
        start = _function_start(ea)
        if start is None or start != ea:
            return "local target function_address must be an exact function start"
    elif target_kind == "relationship":
        for field in ("source_address", "destination_address"):
            ea = _parse_address(target.get(field))
            start = _function_start(ea)
            if start is None or start != ea:
                return "%s must be an exact function start" % field
    elif target_kind in {"address", "global"}:
        ea = _target_address(target)
        try:
            if idaapi.getseg(ea) is None:
                return "target address is not loaded"
        except Exception:
            pass
    expected_byte_hash = target.get("function_byte_hash")
    if expected_byte_hash not in (None, ""):
        target_ea = (
            target.get("function_address")
            if target.get("function_address") not in (None, "")
            else target.get("address")
        )
        if target_ea in (None, ""):
            return "function_byte_hash requires a function address"
        observed_byte_hash = _function_byte_hash(_parse_address(target_ea))
        if observed_byte_hash is None:
            return "function_byte_hash target is not inside a function"
        if observed_byte_hash.lower() != str(expected_byte_hash).lower():
            return "function bytes changed (expected %s, observed %s)" % (
                expected_byte_hash,
                observed_byte_hash,
            )
    return None


def apply_operation(operation, *, replace_existing_named_types=False):
    kind = operation["kind"]
    target = operation["target"]
    desired = operation["desired"]
    ea = _target_address(target)
    try:
        if kind == "function.rename":
            start = _function_start(ea)
            success = start is not None and bool(idc.set_name(start, desired["name"], getattr(idc, "SN_CHECK", 0)))
        elif kind == "function.comment.set":
            start = _function_start(ea)
            success = start is not None and _set_function_behavior_comment(
                start,
                desired["comment"],
                bool(desired.get("repeatable", True)),
            )
        elif kind == "address.comment.set":
            success = _set_address_behavior_comment(
                ea, desired["comment"], bool(desired.get("repeatable"))
            )
        elif kind == "function.folder.set":
            moved = annotation_adapter._move_to_ida_folder(ea, desired["folder"])
            tagged = _append_function_line(ea, "[verified-folder] %s" % str(desired["folder"]).strip().strip("/"))
            success = bool(moved or tagged)
            return {"success": success, "api_result": {"moved": bool(moved), "fallback_annotation": bool(tagged)}}
        elif kind == "function.prototype.set":
            start = _function_start(ea)
            success = start is not None and bool(idc.SetType(start, desired["declaration"]))
        elif kind == "local.rename":
            status, reason = type_adapter._apply_local_name_update(_local_item(operation))
            return {"success": status in {"applied", "confirmed_existing"}, "api_result": status, "reason": reason}
        elif kind == "local.type.set":
            status, reason = type_adapter._apply_local_type_update(_local_item(operation))
            return {"success": status in {"applied", "confirmed_existing"}, "api_result": status, "reason": reason}
        elif kind == "global.rename":
            success = bool(idc.set_name(ea, desired["name"], getattr(idc, "SN_CHECK", 0)))
        elif kind == "global.type.set":
            success = bool(idc.SetType(ea, desired["declaration"]))
        elif kind == "named_type.create_or_update":
            legacy_item = {"name": desired["name"], "declaration": desired["declaration"]}
            if desired["type_kind"] in {"struct", "union"}:
                status, reason = type_adapter._apply_structure_type_update(legacy_item, replace_existing=replace_existing_named_types)
            elif desired["type_kind"] == "enum":
                status, reason = type_adapter._apply_enum_type_update(legacy_item, replace_existing=replace_existing_named_types)
            elif desired["type_kind"] == "typedef":
                status, reason = type_adapter._apply_typedef_type_update(legacy_item, replace_existing=replace_existing_named_types)
            else:
                return {"success": False, "api_result": "rejected", "reason": "Unsupported named type kind"}
            return {"success": status in {"applied", "refined", "confirmed_existing"}, "api_result": status, "reason": reason}
        elif kind == "relationship.annotate":
            line = _relationship_line(target, desired)
            relationship_id = _relationship_id(target, desired)
            success = _store_relationship(target, desired)
            if success:
                callsite = target.get("callsite_address")
                success = (
                    _upsert_address_line(
                        _parse_address(callsite),
                        "[relationship:%s]" % relationship_id,
                        line,
                    )
                    if callsite not in (None, "")
                    else _upsert_function_line(
                        _parse_address(target.get("source_address")),
                        "[relationship:%s]" % relationship_id,
                        line,
                    )
                )
        else:
            return {"success": False, "api_result": "unsupported", "reason": "Unsupported operation"}
        return {"success": bool(success), "api_result": bool(success)}
    except Exception as exc:
        return {"success": False, "api_result": "exception", "reason": str(exc)}


def _remember_registry_receipt(registry, operation, receipt):
    entry = registry.get(operation["operation_id"])
    if isinstance(entry, dict):
        entry.update({"status": receipt["status"], "receipt_id": receipt["receipt_id"]})


def execute_batch(raw_operations, expected_artifact, *, replace_existing_named_types=False, operation_registry=None):
    receipts = []
    status_by_operation = {}
    registry = operation_registry if isinstance(operation_registry, dict) else {}
    for raw in raw_operations:
        try:
            operation = validate_operation(raw)
        except ContractError as exc:
            placeholder = dict(raw) if isinstance(raw, Mapping) else {}
            placeholder.setdefault("operation_id", "invalid_%d" % len(receipts))
            placeholder.setdefault("kind", "invalid")
            placeholder.setdefault("artifact", dict(expected_artifact))
            placeholder.setdefault("target", {})
            placeholder.setdefault("desired", {})
            receipt = build_receipt(
                placeholder,
                "rejected",
                "validation",
                errors=[exc.as_dict()],
                recovery="Repair the request using the operation schema.",
            )
            receipts.append(receipt)
            status_by_operation[placeholder["operation_id"]] = receipt["status"]
            continue

        digest = operation_digest(operation)
        prior_entry = registry.get(operation["operation_id"])
        if isinstance(prior_entry, str):
            prior_entry = {"digest": prior_entry, "status": None}
            registry[operation["operation_id"]] = prior_entry
        if prior_entry and prior_entry.get("digest") != digest:
            receipt = build_receipt(
                operation,
                "conflict",
                "validation",
                errors=[{"code": "operation_id_reused", "message": "operation_id was already used for different content"}],
                recovery="Use a new operation identifier after re-inspecting live state.",
            )
            receipts.append(receipt)
            status_by_operation[operation["operation_id"]] = receipt["status"]
            continue
        registry.setdefault(operation["operation_id"], {"digest": digest, "status": None})
        idempotent_retry = bool(
            prior_entry and prior_entry.get("status") in {"verified", "verified_existing"}
        )

        try:
            operation = validate_operation(
                operation,
                expected_artifact=expected_artifact,
                # A successful save changes the database revision. Only an
                # exact logical retry of an already verified operation may
                # cross that revision boundary; binary and database identity
                # must still match.
                rebind_database_revision=idempotent_retry,
            )
        except ContractError as exc:
            receipt = build_receipt(
                operation,
                "rejected",
                "validation",
                errors=[exc.as_dict()],
                recovery=(
                    "Re-inspect the live artifact for a fresh reference. "
                    "Only exact retries of previously verified operations "
                    "may use an earlier database revision."
                ),
            )
            receipts.append(receipt)
            status_by_operation[operation["operation_id"]] = receipt["status"]
            continue
        live_target_error = _live_target_error(operation)
        if live_target_error:
            receipt = build_receipt(
                operation,
                "rejected",
                "validation",
                errors=[{"code": "invalid_live_target", "message": live_target_error}],
                recovery="Re-inspect the live database and submit an exact target.",
            )
            receipts.append(receipt)
            status_by_operation[operation["operation_id"]] = receipt["status"]
            _remember_registry_receipt(registry, operation, receipt)
            continue

        blocked = []
        for item in operation["depends_on"]:
            dependency_status = status_by_operation.get(item)
            if dependency_status is None and isinstance(registry.get(item), dict):
                dependency_status = registry[item].get("status")
            if dependency_status not in {"verified", "verified_existing"}:
                blocked.append(item)
        if blocked:
            receipt = build_receipt(
                operation,
                "blocked",
                "validation",
                errors=[{"code": "dependency_not_verified", "message": "Dependencies not verified: %s" % ", ".join(blocked)}],
                recovery="Verify prerequisite operations before retrying.",
            )
            receipts.append(receipt)
            status_by_operation[operation["operation_id"]] = receipt["status"]
            _remember_registry_receipt(registry, operation, receipt)
            continue

        before = read_state(operation)
        already_matches, initial_normalization = _compare_operation(operation, before)
        if idempotent_retry and already_matches:
            receipt = build_receipt(
                operation,
                "verified_existing",
                "readback",
                before=before,
                observed=before,
                normalization=initial_normalization,
                persistence="pending",
            )
            receipts.append(receipt)
            status_by_operation[operation["operation_id"]] = receipt["status"]
            _remember_registry_receipt(registry, operation, receipt)
            continue
        preconditions_ok, mismatches = _preconditions_match(operation, before)
        if not preconditions_ok:
            receipt = build_receipt(
                operation,
                "conflict",
                "validation",
                before=before,
                observed=before,
                errors=[{"code": "precondition_failed", "message": "Live state did not match preconditions", "mismatches": mismatches}],
                recovery="Re-inspect the live artifact and submit a newly anchored operation.",
            )
            receipts.append(receipt)
            status_by_operation[operation["operation_id"]] = receipt["status"]
            _remember_registry_receipt(registry, operation, receipt)
            continue

        if already_matches:
            receipt = build_receipt(
                operation,
                "verified_existing",
                "readback",
                before=before,
                observed=before,
                normalization=initial_normalization,
                persistence="pending",
            )
            receipts.append(receipt)
            status_by_operation[operation["operation_id"]] = receipt["status"]
            _remember_registry_receipt(registry, operation, receipt)
            continue

        affected_functions = _affected_function_addresses(operation)
        dependency_artifacts = _semantic_dependency_artifacts(operation)
        execution = apply_operation(operation, replace_existing_named_types=replace_existing_named_types)
        observed = read_state(operation)
        matches, normalization = _compare_operation(operation, observed)
        effects = {
            "decompiler_functions": [],
            "decompiler_changed": None,
            "refresh_count": None,
            "measurement": "not_run_in_durable_mutation_worker",
            "affected_function_addresses": [
                hex(ea) for ea in affected_functions
            ],
            "semantic_dependency_artifacts": dependency_artifacts,
            "measurement_reason": (
                "Hex-Rays rendering is intentionally excluded from the durable "
                "mutation transaction because decompilation can infer and write "
                "types unrelated to the requested operation. Reinspect code "
                "through the analytical session after readback when needed."
            ),
        }
        if not execution.get("success"):
            status = "failed"
            recovery = "Inspect the IDA rejection or exception and retry after correcting the request."
        elif matches:
            status = "verified"
            recovery = None
        elif observed.get("error"):
            status = "unverified"
            recovery = "Repair readback or re-anchor the live artifact before relying on this mutation."
        else:
            status = "ineffective"
            recovery = "Re-inspect the observed state and submit a corrected operation."
        errors = []
        if status != "verified":
            errors.append({"code": status, "message": execution.get("reason") or "Desired state did not verify"})
        receipt = build_receipt(
            operation,
            status,
            "readback" if execution.get("success") else "execution",
            before=before,
            observed=observed,
            execution=execution,
            normalization=normalization,
            effects=effects,
            persistence="pending" if status in {"verified", "verified_existing"} else "not_checked",
            errors=errors,
            recovery=recovery,
        )
        receipts.append(receipt)
        status_by_operation[operation["operation_id"]] = receipt["status"]
        _remember_registry_receipt(registry, operation, receipt)
    return {"schema": "verified_ida.batch_result.v1", "summary": summarize_receipts(receipts), "receipts": receipts}


def main(argv):
    args = parse_args(argv)
    load_binary(args.input)
    payload = _load_json(args.operations)
    raw_operations = payload if isinstance(payload, list) else payload.get("operations") or []
    artifact = _load_json(args.artifact)
    registry_document = _load_json(args.registry) if args.registry and os.path.isfile(args.registry) else {}
    operation_registry = (
        registry_document.get("operations")
        if isinstance(registry_document, Mapping) and isinstance(registry_document.get("operations"), Mapping)
        else registry_document
    )
    if not isinstance(operation_registry, dict):
        operation_registry = {}
    result = execute_batch(
        raw_operations,
        artifact,
        replace_existing_named_types=args.replace_existing_named_types,
        operation_registry=operation_registry,
    )
    save_database(args.save_as)
    if args.registry:
        _write_json(
            args.registry,
            {
                "schema": "verified_ida.operation_registry.v1",
                "operations": operation_registry,
            },
        )
    _write_json(args.receipts, result)
    print(json.dumps(result, indent=2, sort_keys=True))
    print("Saved verified database to: %s" % args.save_as)
    return 0 if result["summary"]["status"] in {"verified", "empty"} else 2


if __name__ == "__main__":
    main(sys.argv[1:])
