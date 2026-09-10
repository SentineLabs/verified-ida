"""Versioned, deterministic semantic state for Verified IDA checkpoints.

This module runs inside IDA.  It intentionally excludes file paths, timestamps,
raw IDB bytes, and decompiler rendering so a no-op reopen/save does not change
the digest.  Selected local-variable state is exported only for functions the
Verified IDA journal says were edited through a local operation.
"""

from __future__ import annotations

import ida_bytes
import ida_funcs
import ida_nalt
import ida_typeinf
import idautils
import idc

try:
    import ida_hexrays
except Exception:
    ida_hexrays = None

from apply_verified_ida_operations import _relationship_records
from verified_ida_annotations_export_ida import export_enums, export_structs
from verified_ida.canonical import canonical_declaration, canonical_name, canonical_text
from verified_ida.semantic_delta import (
    DERIVED_SEMANTIC_FIELDS,
    semantic_state_digest,
)


EXPORT_SCHEMA = "verified_ida.semantic_state.v2"
EXPORT_VERSION = 5


def _type_dependencies(tif, failures=None):
    """Return named type references by walking IDA's tinfo_t tree."""

    names = set()
    failures = failures if failures is not None else []

    class Visitor(ida_typeinf.tinfo_visitor_t):
        def __init__(self):
            ida_typeinf.tinfo_visitor_t.__init__(self)

        def visit_type(self, _out, current, _name, _comment):
            try:
                name = canonical_name(current.get_type_name())
            except Exception:
                name = ""
            if name and not name.startswith("#"):
                names.add(name)
            return 0

    try:
        Visitor().apply_to(tif)
    except Exception:
        pass
    # Follow resolved wrappers explicitly. IDA's generic visitor stops at
    # some named typedef references; for example FARPROC is a pointer to a
    # function returning INT_PTR, and the visitor reports FARPROC without
    # descending to that return type.
    seen = set()

    def walk(current, depth=0):
        if current is None:
            return
        if depth > 64:
            failures.append("native_type_depth_limit")
            return
        try:
            signature = canonical_declaration(current.dstr())
        except Exception:
            signature = ""
        try:
            realtype = int(current.get_realtype(True))
        except Exception:
            realtype = -1
        key = (signature, realtype)
        if key in seen:
            return
        seen.add(key)
        try:
            name = canonical_name(current.get_type_name())
        except Exception:
            name = ""
        if name and not name.startswith("#"):
            names.add(name)
        try:
            if current.is_ptr():
                walk(current.get_pointed_object(), depth + 1)
                return
            if current.is_array():
                walk(current.get_array_element(), depth + 1)
                return
            if current.is_func():
                walk(current.get_rettype(), depth + 1)
                for index in range(int(current.get_nargs() or 0)):
                    walk(current.get_nth_arg(index), depth + 1)
            if current.is_udt():
                details = ida_typeinf.udt_type_data_t()
                if not current.get_udt_details(details):
                    failures.append("udt_details_unavailable")
                else:
                    for member in details:
                        walk(member.type, depth + 1)
        except Exception as exc:
            failures.append("native_walk:%s" % type(exc).__name__)
            return

    try:
        walk(tif)
    except Exception as exc:
        failures.append("native_walk:%s" % type(exc).__name__)
    # IDA's visitor can treat a named typedef as a terminal reference. Record
    # the native typedef-chain names explicitly so dependency-aware mutation
    # verification can distinguish FARPROC -> INT_PTR materialization from an
    # unrelated local-type change.
    for accessor in ("get_next_type_name", "get_final_type_name"):
        try:
            value = getattr(tif, accessor)()
        except Exception:
            value = ""
        if isinstance(value, str):
            name = canonical_name(value)
            if name and not name.startswith("#"):
                names.add(name)
    return sorted(names, key=lambda value: (value.lower(), value))


def _dependency_fields(tif, exclude_name=None):
    failures = []
    names = _type_dependencies(tif, failures) if tif is not None else []
    if tif is None:
        failures.append("native_type_unavailable")
    return {
        "type_dependencies": [name for name in names if name != exclude_name],
        "type_dependency_scan": {"complete": not failures, "reasons": sorted(set(failures))},
    }


def _address_tinfo(ea):
    tif = ida_typeinf.tinfo_t()
    try:
        if ida_nalt.get_tinfo(tif, ea):
            return tif
    except Exception:
        pass
    return None


def _user_name(probe):
    try:
        return bool(probe() if callable(probe) else probe) if probe is not None else None
    except Exception:
        return None


def _function_rows(selected_local_functions):
    selected = {int(str(value), 0) for value in (selected_local_functions or [])}
    rows = []
    for ea in idautils.Functions():
        start = int(ea)
        tif = _address_tinfo(start)
        argument_names = {"available": False, "names": []}
        callback_parameters = []
        if tif is not None:
            try:
                details = ida_typeinf.func_type_data_t()
                if tif.get_func_details(details):
                    argument_names = {"available": True, "names": [str(arg.name) for arg in details if arg.name]}
                    callback_parameters = [
                        {"index": index, "name": str(arg.name)}
                        for index, arg in enumerate(details)
                        if arg.type.is_funcptr()
                    ]
            except Exception:
                pass
        row = {
            "address": hex(start),
            "name": canonical_name(idc.get_func_name(start)),
            "comment": canonical_text(idc.get_func_cmt(start, 0)),
            "repeatable_comment": canonical_text(idc.get_func_cmt(start, 1)),
            "prototype": canonical_declaration(idc.get_type(start)),
            "native_argument_names": argument_names,
            "native_callback_parameters": callback_parameters,
            "native_has_user_name": _user_name(
                lambda: ida_bytes.has_user_name(ida_bytes.get_flags(start))),
            **_dependency_fields(tif),
        }
        if start in selected:
            row["locals"] = _local_rows(start)
        rows.append(row)
    return rows


def _native_call_arguments(cfunc):
    """Measure exact direct call arguments, never guess indirect targets."""
    rows = []

    def function_object(expr):
        for _ in range(8):
            if expr.op in (ida_hexrays.cot_cast, ida_hexrays.cot_ref):
                expr = expr.x
            else:
                break
        if expr.op != ida_hexrays.cot_obj:
            return None
        address = int(expr.obj_ea)
        function = ida_funcs.get_func(address)
        return hex(address) if function and int(function.start_ea) == address else None

    class Visitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, expr):
            if len(rows) >= 4096:
                return 1
            if expr.op == ida_hexrays.cot_call:
                callee = function_object(expr.x)
                if callee and int(expr.ea) != idc.BADADDR:
                    for index, arg in enumerate(expr.a):
                        callback = function_object(arg)
                        if callback:
                            rows.append({"callee": callee, "callsite": hex(int(expr.ea)),
                                         "argument_index": index, "function": callback})
            return 0

    Visitor().apply_to(cfunc.body, None)
    return rows


def _local_rows(ea):
    if ida_hexrays is None:
        return {"available": False, "items": []}
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return {"available": False, "items": []}
        cfunc = ida_hexrays.decompile(ea)
        saved_locals = ida_hexrays.lvar_uservec_t()
        try:
            saved_available = bool(ida_hexrays.restore_user_lvar_settings(saved_locals, ea))
        except Exception:
            saved_available = False
        items = []
        for index, lvar in enumerate(list(cfunc.lvars)):
            try:
                declaration = canonical_declaration(lvar.type().dstr())
            except Exception:
                declaration = ""
            is_argument = False
            try:
                is_argument = bool(_user_name(getattr(lvar, "is_arg_var", None)))
            except Exception:
                pass
            saved_name = None
            if saved_available:
                try:
                    info = saved_locals.find_info(lvar)
                    saved_name = bool(info is not None and info.name)
                except Exception:
                    pass
            items.append({
                "index": index,
                "name": canonical_name(getattr(lvar, "name", "")),
                "declaration": declaration,
                "is_argument": is_argument,
                "native_has_user_name": _user_name(lvar.has_user_name),
                "native_saved_user_name": saved_name,
                **_dependency_fields(lvar.type()),
            })
        try:
            bindings = _native_call_arguments(cfunc)
        except Exception:
            bindings = []  # Missing evidence never grants callback permission.
        return {"available": True, "items": items, "native_call_arguments": bindings}
    except Exception as exc:
        return {"available": False, "error": type(exc).__name__,
                "message": str(exc)[:512], "items": []}


def _global_rows(selected_global_addresses=None):
    selected = {
        int(str(value), 0) for value in (selected_global_addresses or [])
    }
    addresses = {int(ea) for ea, _name in idautils.Names()}
    addresses.update(selected)
    rows = []
    for address in sorted(addresses):
        if ida_funcs.get_func(address) is not None:
            continue
        flags = ida_bytes.get_flags(address)
        if (
            address not in selected
            and not ida_bytes.has_user_name(flags)
            and not idc.get_type(address)
        ):
            continue
        tif = _address_tinfo(address)
        rows.append({
            "address": hex(address),
            "name": canonical_name(idc.get_name(address)),
            "native_has_user_name": _user_name(lambda: ida_bytes.has_user_name(flags)),
            "declaration": canonical_declaration(idc.get_type(address)),
            "comment": canonical_text(idc.get_cmt(address, 0)),
            "repeatable_comment": canonical_text(idc.get_cmt(address, 1)),
            **_dependency_fields(tif),
        })
    return sorted(rows, key=lambda row: int(row["address"], 0))


def _named_type_rows():
    rows = []
    til = ida_typeinf.get_idati()
    limit = int(ida_typeinf.get_ordinal_limit(til) or 0)
    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        try:
            if not tif.get_numbered_type(til, ordinal):
                continue
        except Exception:
            continue
        name = canonical_name(ida_typeinf.get_numbered_type_name(til, ordinal))
        if not name:
            continue
        kind = "type"
        try:
            if tif.is_udt():
                kind = "struct_or_union"
            elif tif.is_enum():
                kind = "enum"
            elif tif.is_typedef():
                kind = "typedef"
        except Exception:
            pass
        try:
            declaration = canonical_declaration(tif.dstr())
        except Exception:
            declaration = ""
        try:
            size = int(tif.get_size())
        except Exception:
            size = 0
        dependency_tif = ida_typeinf.tinfo_t()
        try:
            loaded = dependency_tif.get_numbered_type(
                til,
                ordinal,
                ida_typeinf.BTF_TYPEDEF,
                False,
            )
            if not loaded:
                dependency_tif = tif
        except Exception:
            dependency_tif = tif
        rows.append({
            "name": name,
            "kind": kind,
            "declaration": declaration,
            "size": size,
            **_dependency_fields(dependency_tif, name),
        })
    return sorted(rows, key=lambda row: (row["name"].lower(), row["kind"]))


def _struct_dependency_rows(rows):
    """Attach native, digest-excluded member dependencies to struct rows."""

    til = ida_typeinf.get_idati()
    enriched = []
    for raw in rows:
        row = dict(raw)
        members = [dict(member) for member in row.get("members") or []]
        dependencies = set()
        tif = ida_typeinf.tinfo_t()
        try:
            loaded = bool(tif.get_named_type(til, str(row.get("name") or "")))
        except Exception:
            loaded = False
        details = ida_typeinf.udt_type_data_t()
        if loaded:
            try:
                loaded = bool(tif.get_udt_details(details))
            except Exception:
                loaded = False
        if loaded:
            native_members = list(details)
            for index, member in enumerate(members):
                if index >= len(native_members):
                    break
                names = [
                    value for value in _type_dependencies(native_members[index].type)
                    if value != row.get("name")
                ]
                member["type_dependencies"] = names
                dependencies.update(names)
        row["members"] = members
        row["type_dependencies"] = sorted(
            dependencies,
            key=lambda value: (value.lower(), value),
        )
        enriched.append(row)
    return enriched


def _relationship_rows(functions):
    rows = []
    for function in functions:
        source = int(function["address"], 0)
        records = _relationship_records(source)
        for relationship_id, record in records.items():
            if not isinstance(record, dict):
                continue
            rows.append({
                "relationship_id": str(relationship_id),
                "source_address": hex(int(str(record.get("source_address")), 0)),
                "destination_address": hex(int(str(record.get("destination_address")), 0)),
                "relationship_kind": canonical_name(record.get("relationship_kind")),
                "description": canonical_text(record.get("description")),
                "flow": record.get("flow"),
                "ownership": record.get("ownership"),
            })
    return sorted(
        rows,
        key=lambda row: (
            int(row["source_address"], 0),
            int(row["destination_address"], 0),
            row["relationship_kind"],
        ),
    )


def _canonical_type_items(value):
    rows = []
    for row in ((value or {}).get("items") or []):
        item = dict(row)
        item.pop("id", None)
        item.pop("ordinal", None)
        item.pop("source", None)
        rows.append(item)
    return rows


def export_semantic_state(
    selected_local_functions=None,
    selected_global_addresses=None,
):
    # Capture durable named-type state before advisory tinfo dependency walking.
    # Some IDA SDK type traversals lazily materialize standard-library or SDK
    # type details in memory; that must not perturb the semantic oracle emitted
    # later in the same read-only process.
    structs = _canonical_type_items(export_structs())
    enums = _canonical_type_items(export_enums())
    # Snapshot the durable named-type inventory before any later dependency
    # walk can lazily materialize SDK typedef details in this process.
    named_types = _named_type_rows()
    structs = _struct_dependency_rows(structs)
    functions = _function_rows(selected_local_functions)
    state = {
        "schema": EXPORT_SCHEMA,
        "export_version": EXPORT_VERSION,
        "functions": functions,
        "globals": _global_rows(selected_global_addresses),
        "named_types": named_types,
        "structs": structs,
        "enums": enums,
        "relationships": _relationship_rows(functions),
    }
    return {
        "schema": EXPORT_SCHEMA,
        "export_version": EXPORT_VERSION,
        "semantic_digest": semantic_state_digest(state),
        "digest_policy": {
            "derived_fields_excluded": sorted(DERIVED_SEMANTIC_FIELDS),
            "reason": (
                "Native type dependencies are advisory measurements and do not "
                "represent an independent durable IDB mutation."
            ),
        },
        "counts": {
            "functions": len(state["functions"]),
            "globals": len(state["globals"]),
            "named_types": len(state["named_types"]),
            "structs": len(state["structs"]),
            "enums": len(state["enums"]),
            "relationships": len(state["relationships"]),
            "selected_local_functions": len(selected_local_functions or []),
            "selected_global_addresses": len(selected_global_addresses or []),
        },
        "state": state,
    }
