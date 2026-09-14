#!/usr/bin/env python3
"""
Export standard IDA-visible annotations for inspection and comparison.

This script runs inside IDA/idat through scripts/run_ida_script_no_network.sh.
It intentionally exports IDA-visible annotations only: names, comments, types,
function prototypes, local variables, data names, structs, and enums. Harness
metadata is not required to read the annotation export.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import ida_bytes
import ida_dirtree
import ida_funcs
import ida_ida
import ida_lines
import ida_nalt
import ida_segment
import idaapi
import idautils
import idc

try:
    import ida_hexrays
    HAS_HEXRAYS = True
except Exception:
    ida_hexrays = None
    HAS_HEXRAYS = False

try:
    import ida_struct
except Exception:
    ida_struct = None

try:
    import ida_enum
except Exception:
    ida_enum = None

try:
    import ida_typeinf
except Exception:
    ida_typeinf = None

from ida_backend import save_database
from ida_reader import load_binary


SCHEMA = "ida_harness.annotations.v2"


def folder_disposition_from_comments(comments):
    """Read the legacy visible folder tag without importing campaign state."""

    text = "\n".join(
        str(comments.get(key) or "")
        for key in ("nonrepeatable", "repeatable")
    )
    match = re.search(r"\[folder:\s*([^\]]+)\]", text, re.IGNORECASE)
    if not match:
        return {"folder": "", "folder_source": "unreported"}
    return {
        "folder": match.group(1).strip().strip("/"),
        "folder_source": "comment_tag_fallback_or_receipt",
    }


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Export standard IDA annotations.")
    parser.add_argument("input", help="Binary, IDB, or I64 loaded by IDA.")
    parser.add_argument("--output", required=True, help="Output annotation JSON path.")
    parser.add_argument(
        "--save-as",
        default=None,
        help="Optional path to save the currently loaded database before exit.",
    )
    return parser.parse_args(argv)


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def write_json(path, value):
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def safe_call(default, func, *args):
    try:
        value = func(*args)
    except Exception:
        return default
    if value is None:
        return default
    return value


def clean_text(value):
    if value is None:
        return ""
    try:
        value = ida_lines.tag_remove(str(value))
    except Exception:
        value = str(value)
    return value.strip()


def comments_at(ea):
    return {
        "nonrepeatable": clean_text(safe_call("", idc.get_cmt, ea, 0)),
        "repeatable": clean_text(safe_call("", idc.get_cmt, ea, 1)),
    }


def function_comments(ea):
    return {
        "nonrepeatable": clean_text(safe_call("", idc.get_func_cmt, ea, 0)),
        "repeatable": clean_text(safe_call("", idc.get_func_cmt, ea, 1)),
    }


def type_string(ea):
    return clean_text(safe_call("", idc.get_type, ea))


def function_flags(func):
    flags = []
    raw = int(getattr(func, "flags", 0) or 0)
    pairs = [
        ("library", getattr(idaapi, "FUNC_LIB", 0)),
        ("thunk", getattr(idaapi, "FUNC_THUNK", 0)),
        ("static", getattr(idaapi, "FUNC_STATICDEF", 0)),
        ("hidden", getattr(idaapi, "FUNC_HIDDEN", 0)),
    ]
    for name, mask in pairs:
        if mask and raw & mask:
            flags.append(name)
    return flags


def input_hashes():
    sha256 = safe_call(b"", ida_nalt.retrieve_input_file_sha256)
    md5 = safe_call(b"", ida_nalt.retrieve_input_file_md5)
    return {
        "sha256": sha256.hex() if isinstance(sha256, bytes) else clean_text(sha256),
        "md5": md5.hex() if isinstance(md5, bytes) else clean_text(md5),
    }


def import_export_addresses():
    imports = set()

    def import_callback(ea, _name, _ordinal):
        if ea != idaapi.BADADDR:
            imports.add(int(ea))
        return True

    for index in range(int(safe_call(0, ida_nalt.get_import_module_qty) or 0)):
        safe_call(False, ida_nalt.enum_import_names, index, import_callback)

    exports = set()
    for entry in idautils.Entries():
        if len(entry) >= 3 and entry[2] != idaapi.BADADDR:
            exports.add(int(entry[2]))
    return imports, exports


def name_provenance(ea, flags, *, is_import=False, is_export=False, function_flags_=None):
    function_flags_ = set(function_flags_ or [])
    if is_import:
        source = "pe_import"
    elif is_export:
        source = "pe_export"
    elif "library" in function_flags_:
        source = "flirt:unattributed_signature"
    elif safe_call(False, ida_bytes.has_dummy_name, flags):
        source = "ida_dummy"
    elif safe_call(False, ida_bytes.has_auto_name, flags):
        source = "ida_auto"
    elif safe_call(False, ida_bytes.has_user_name, flags):
        source = "stored_user_name"
    else:
        source = "unclassified"
    return {
        "source": source,
        "is_user_name": bool(safe_call(False, ida_bytes.has_user_name, flags)),
        "is_auto_name": bool(safe_call(False, ida_bytes.has_auto_name, flags)),
        "is_dummy_name": bool(safe_call(False, ida_bytes.has_dummy_name, flags)),
        "is_import": bool(is_import),
        "is_export": bool(is_export),
        "training_eligible_source": source not in {
            "pe_import",
            "ida_dummy",
            "ida_auto",
            "flirt:unattributed_signature",
            "unclassified",
        },
    }


def function_identity(func):
    chunks = []
    combined = hashlib.sha256()
    instruction_addresses = []
    call_targets = set()
    string_refs = set()
    try:
        ranges = list(idautils.Chunks(func.start_ea))
    except Exception:
        ranges = [(func.start_ea, func.end_ea)]
    for start, end in ranges:
        size = max(0, int(end) - int(start))
        data = safe_call(b"", ida_bytes.get_bytes, start, size)
        if not isinstance(data, bytes):
            data = bytes(data or b"")
        combined.update(int(start).to_bytes(8, "little", signed=False))
        combined.update(int(end).to_bytes(8, "little", signed=False))
        combined.update(data)
        chunks.append({
            "start": hex(start),
            "end": hex(end),
            "size": size,
            "bytes_sha256": hashlib.sha256(data).hexdigest(),
        })
    try:
        instruction_addresses = [hex(int(ea)) for ea in idautils.FuncItems(func.start_ea)]
    except Exception:
        instruction_addresses = []
    for item_text in instruction_addresses:
        item_ea = int(item_text, 16)
        for target in idautils.CodeRefsFrom(item_ea, False):
            callee = ida_funcs.get_func(target)
            if callee is not None and callee.start_ea != func.start_ea:
                call_targets.add(hex(callee.start_ea))
        for target in idautils.DataRefsFrom(item_ea):
            raw = safe_call(None, idc.get_strlit_contents, target)
            if raw is None:
                continue
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", errors="replace")
            value = clean_text(raw)
            if value:
                string_refs.add(value[:240])
    first_block = b""
    try:
        flow = idaapi.FlowChart(func)
        block = next(iter(flow), None)
        if block is not None:
            first_block = safe_call(
                b"",
                ida_bytes.get_bytes,
                block.start_ea,
                max(0, block.end_ea - block.start_ea),
            )
    except Exception:
        first_block = b""
    if not isinstance(first_block, bytes):
        first_block = bytes(first_block or b"")
    return {
        "entry": hex(func.start_ea),
        "end": hex(func.end_ea),
        "region_sha256": combined.hexdigest(),
        "first_block_sha256": hashlib.sha256(first_block).hexdigest(),
        "chunks": chunks,
        "instruction_addresses": instruction_addresses,
        "call_targets": sorted(call_targets),
        "string_refs": sorted(string_refs),
    }


def native_function_folder(ea):
    try:
        tree = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
        entry = ida_dirtree.direntry_t(int(ea), False)
        cursor = tree.find_entry(entry)
        path = clean_text(tree.get_abspath(cursor))
        if path:
            folder = os.path.dirname(path).replace("\\", "/")
            if folder in {"", ".", "/"}:
                folder = ""
            return {
                "folder": folder,
                "folder_source": "native_ida_dirtree",
                "native_path": path,
            }
    except Exception:
        pass
    return None


def applied_signatures():
    rows = []
    quantity = int(safe_call(0, ida_funcs.get_idasgn_qty) or 0)
    for index in range(quantity):
        description = safe_call(None, ida_funcs.get_idasgn_desc_with_matches, index)
        if isinstance(description, (tuple, list)):
            name = clean_text(description[0] if description else "")
            details = clean_text(description[1] if len(description) > 2 else "")
            matches = description[-1] if len(description) > 1 else None
        else:
            name = clean_text(description)
            details = ""
            matches = None
        try:
            matches = int(matches) if matches is not None else None
        except Exception:
            matches = clean_text(matches)
        rows.append({
            "index": index,
            "name": name,
            "description": details,
            "matches": matches,
        })
    return rows


def lvar_type_string(lvar):
    candidates = []
    for attr in ("tif",):
        if hasattr(lvar, attr):
            candidates.append(getattr(lvar, attr))
    for method in ("type", "get_type"):
        if hasattr(lvar, method):
            try:
                candidates.append(getattr(lvar, method)())
            except Exception:
                pass
    for candidate in candidates:
        if candidate is None:
            continue
        for method in ("dstr", "_print"):
            if hasattr(candidate, method):
                try:
                    text = getattr(candidate, method)()
                    if text:
                        return clean_text(text)
                except Exception:
                    pass
        text = clean_text(candidate)
        if text:
            return text
    return ""


def lvar_comment(lvar):
    for attr in ("cmt", "comment"):
        if hasattr(lvar, attr):
            text = clean_text(getattr(lvar, attr))
            if text:
                return text
    return ""


def lvar_is_argument(lvar):
    value = getattr(lvar, "is_arg_var", None)
    if callable(value):
        try:
            return bool(value())
        except Exception:
            return False
    if value is not None:
        return bool(value)
    value = getattr(lvar, "is_arg", None)
    if callable(value):
        try:
            return bool(value())
        except Exception:
            return False
    return bool(value) if value is not None else False


def function_lvars(ea):
    if not HAS_HEXRAYS:
        return {"available": False, "error": "hexrays_unavailable", "parameters": [], "locals": []}
    try:
        cfunc = ida_hexrays.decompile(ea)
    except Exception as exc:
        return {"available": False, "error": str(exc), "parameters": [], "locals": []}
    if cfunc is None:
        return {"available": False, "error": "decompile_failed", "parameters": [], "locals": []}

    params = []
    locals_ = []
    try:
        lvars = list(cfunc.lvars)
    except Exception:
        lvars = []
    for index, lvar in enumerate(lvars):
        item = {
            "index": index,
            "name": clean_text(getattr(lvar, "name", "")),
            "type": lvar_type_string(lvar),
            "comment": lvar_comment(lvar),
            "is_argument": lvar_is_argument(lvar),
        }
        if item["is_argument"]:
            params.append(item)
        else:
            locals_.append(item)
    return {"available": True, "parameters": params, "locals": locals_}


def instruction_comments(func):
    rows = []
    for head in idautils.FuncItems(func.start_ea):
        comments = comments_at(head)
        if comments["nonrepeatable"] or comments["repeatable"]:
            rows.append({
                "address": hex(head),
                "comments": comments,
            })
    return rows


def export_functions(imports=None, exports=None):
    imports = set(imports or [])
    exports = set(exports or [])
    rows = []
    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        if not func:
            continue
        name = clean_text(idc.get_func_name(func.start_ea) or "")
        lvars = function_lvars(func.start_ea)
        comments = function_comments(func.start_ea)
        flags = int(safe_call(0, ida_bytes.get_flags, func.start_ea) or 0)
        func_flags = function_flags(func)
        folder = native_function_folder(func.start_ea)
        if folder is None:
            folder = folder_disposition_from_comments(comments)
        rows.append({
            "address": hex(func.start_ea),
            "end": hex(func.end_ea),
            "name": name,
            "size": int(func.end_ea - func.start_ea),
            "flags": func_flags,
            "name_provenance": name_provenance(
                func.start_ea,
                flags,
                is_import=func.start_ea in imports,
                is_export=func.start_ea in exports,
                function_flags_=func_flags,
            ),
            "identity": function_identity(func),
            "prototype": type_string(func.start_ea),
            "comments": comments,
            **folder,
            "instruction_comments": instruction_comments(func),
            "parameters": lvars.get("parameters", []),
            "locals": lvars.get("locals", []),
            "local_variable_export": {
                "available": bool(lvars.get("available")),
                "error": lvars.get("error"),
            },
        })
    return rows


def is_code_ea(ea):
    seg = ida_segment.getseg(ea)
    if not seg:
        return False
    return bool(seg.perm & ida_segment.SEGPERM_EXEC) or seg.type == ida_segment.SEG_CODE


def export_data(imports=None, exports=None):
    imports = set(imports or [])
    exports = set(exports or [])
    rows = []
    seen = set()
    for ea, name in idautils.Names():
        if ea in seen:
            continue
        if ida_funcs.get_func(ea) is not None:
            continue
        seen.add(ea)
        comments = comments_at(ea)
        row_type = type_string(ea)
        name = clean_text(name)
        if not (name or row_type or comments["nonrepeatable"] or comments["repeatable"]):
            continue
        flags = safe_call(0, ida_bytes.get_flags, ea)
        rows.append({
            "address": hex(ea),
            "name": name,
            "type": row_type,
            "comments": comments,
            "size": int(safe_call(0, ida_bytes.get_item_size, ea) or 0),
            "segment": clean_text(safe_call("", idc.get_segm_name, ea)),
            "is_code_segment": is_code_ea(ea),
            "is_data": bool(safe_call(False, ida_bytes.is_data, flags)),
            "name_provenance": name_provenance(
                ea,
                flags,
                is_import=ea in imports,
                is_export=ea in exports,
            ),
        })
    rows.sort(key=lambda item: int(item["address"], 16))
    return rows


def struct_member_type(member):
    if ida_struct is None:
        return ""
    try:
        tinfo_cls = getattr(ida_typeinf, "tinfo_t", None) if ida_typeinf else None
        if tinfo_cls is None:
            tinfo_cls = getattr(idaapi, "tinfo_t", None)
        if tinfo_cls is None:
            return ""
        tif = tinfo_cls()
        if ida_struct.get_member_tinfo(tif, member):
            return clean_text(tif.dstr())
    except Exception:
        pass
    return ""


def local_type_name(tif, ordinal=None):
    if ida_typeinf is None:
        return ""
    til = safe_call(None, ida_typeinf.get_idati)
    if ordinal is not None:
        name = clean_text(safe_call("", ida_typeinf.get_numbered_type_name, til, ordinal))
        if name:
            return name
    for method_name in ("get_type_name", "get_nice_type_name"):
        method = getattr(tif, method_name, None)
        if callable(method):
            try:
                name = clean_text(method())
                if name and not name.startswith("#"):
                    return name
            except Exception:
                pass
    dstr = clean_text(safe_call("", tif.dstr))
    match = re.search(r"\b(?:struct|enum)\s+([A-Za-z_][A-Za-z0-9_]*)", dstr)
    return clean_text(match.group(1)) if match else ""


def bits_to_bytes(value):
    try:
        bits = int(value or 0)
    except Exception:
        return 0
    if bits <= 0:
        return 0
    return (bits + 7) // 8


def export_local_named_types():
    if ida_typeinf is None:
        return {"available": False, "structs": [], "enums": []}
    til = safe_call(None, ida_typeinf.get_idati)
    if til is None:
        return {"available": False, "structs": [], "enums": []}
    limit = int(safe_call(0, ida_typeinf.get_ordinal_limit, til) or 0)
    structs = []
    enums = []
    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        try:
            if not tif.get_numbered_type(til, ordinal):
                continue
        except Exception:
            continue
        name = local_type_name(tif, ordinal)
        if not name or name.startswith("#"):
            continue
        if safe_call(False, tif.is_udt):
            udt = ida_typeinf.udt_type_data_t()
            if not safe_call(False, tif.get_udt_details, udt):
                continue
            members = []
            for member in list(udt):
                member_type = ""
                try:
                    member_type = clean_text(member.type.dstr())
                except Exception:
                    pass
                offset = bits_to_bytes(getattr(member, "offset", 0))
                size = bits_to_bytes(getattr(member, "size", 0))
                members.append({
                    "name": clean_text(getattr(member, "name", "")),
                    "offset": offset,
                    "end_offset": offset + size,
                    "size": size,
                    "type": member_type,
                    "comment": clean_text(getattr(member, "cmt", "")),
                    "repeatable_comment": "",
                })
            structs.append({
                "ordinal": ordinal,
                "id": ordinal,
                "name": name,
                "size": int(safe_call(0, tif.get_size) or getattr(udt, "total_size", 0) or 0),
                "members": members,
                "source": "local_types",
                "declaration": clean_text(safe_call("", tif.dstr)),
            })
            continue
        if safe_call(False, tif.is_enum):
            enum_data = ida_typeinf.enum_type_data_t()
            if not safe_call(False, tif.get_enum_details, enum_data):
                continue
            members = []
            for member in list(enum_data):
                members.append({
                    "name": clean_text(getattr(member, "name", "")),
                    "value": int(getattr(member, "value", 0) or 0),
                    "comment": clean_text(getattr(member, "cmt", "")),
                    "repeatable_comment": "",
                })
            enums.append({
                "ordinal": ordinal,
                "id": ordinal,
                "name": name,
                "members": members,
                "source": "local_types",
                "declaration": clean_text(safe_call("", tif.dstr)),
            })
    return {"available": True, "structs": structs, "enums": enums}


def export_struct_database_items():
    if ida_struct is None:
        return []
    items = []
    try:
        count = ida_struct.get_struc_qty()
    except Exception:
        return []
    for ordinal in range(count):
        try:
            sid = ida_struct.get_struc_by_idx(ordinal)
            sptr = ida_struct.get_struc(sid)
        except Exception:
            continue
        if not sptr:
            continue
        members = []
        try:
            member_count = ida_struct.get_member_qty(sptr)
        except Exception:
            member_count = 0
        for member_index in range(member_count):
            member = None
            get_by_idx = getattr(ida_struct, "get_member_by_idx", None)
            if get_by_idx:
                try:
                    member = get_by_idx(sptr, member_index)
                except Exception:
                    member = None
            if member is None:
                try:
                    member = ida_struct.get_member(sptr, member_index)
                except Exception:
                    member = None
            if not member:
                continue
            members.append({
                "name": clean_text(ida_struct.get_member_name(member.id)),
                "offset": int(getattr(member, "soff", 0) or 0),
                "end_offset": int(getattr(member, "eoff", 0) or 0),
                "size": int(safe_call(0, ida_struct.get_member_size, member) or 0),
                "type": struct_member_type(member),
                "comment": clean_text(safe_call("", ida_struct.get_member_cmt, member.id, False)),
                "repeatable_comment": clean_text(safe_call("", ida_struct.get_member_cmt, member.id, True)),
            })
        items.append({
            "ordinal": ordinal,
            "id": int(sid),
            "name": clean_text(ida_struct.get_struc_name(sid)),
            "size": int(safe_call(0, ida_struct.get_struc_size, sptr) or 0),
            "members": members,
            "source": "struct_database",
        })
    return items


def export_structs():
    local_types = export_local_named_types()
    by_name = {}
    struct_db_items = export_struct_database_items()
    for item in struct_db_items + (local_types.get("structs") or []):
        name = clean_text(item.get("name"))
        if name:
            by_name.setdefault(name, item)
    return {
        "available": ida_struct is not None or local_types.get("available"),
        "items": sorted(by_name.values(), key=lambda item: clean_text(item.get("name")).lower()),
        "struct_database_count": len(struct_db_items),
        "local_type_count": len(local_types.get("structs") or []),
    }


def export_enum_database_items():
    if ida_enum is None:
        return []
    items = []
    try:
        count = ida_enum.get_enum_qty()
    except Exception:
        return []
    for ordinal in range(count):
        try:
            enum_id = ida_enum.getn_enum(ordinal)
        except Exception:
            continue
        members = []
        try:
            member_id = ida_enum.get_first_enum_member(enum_id)
        except Exception:
            member_id = idaapi.BADADDR
        guard = 0
        while member_id != idaapi.BADADDR and guard < 100000:
            guard += 1
            try:
                value = ida_enum.get_enum_member_value(member_id)
                serial = ida_enum.get_enum_member_serial(member_id)
                name = ida_enum.get_enum_member_name(member_id)
                comment = ida_enum.get_enum_member_cmt(member_id, False)
                repeatable = ida_enum.get_enum_member_cmt(member_id, True)
                next_member = ida_enum.get_next_enum_member(enum_id, value, serial)
            except Exception:
                break
            members.append({
                "name": clean_text(name),
                "value": int(value),
                "serial": int(serial),
                "comment": clean_text(comment),
                "repeatable_comment": clean_text(repeatable),
            })
            member_id = next_member
        items.append({
            "ordinal": ordinal,
            "id": int(enum_id),
            "name": clean_text(ida_enum.get_enum_name(enum_id)),
            "members": members,
            "source": "enum_database",
        })
    return items


def export_enums():
    local_types = export_local_named_types()
    by_name = {}
    enum_db_items = export_enum_database_items()
    for item in enum_db_items + (local_types.get("enums") or []):
        name = clean_text(item.get("name"))
        if name:
            by_name.setdefault(name, item)
    return {
        "available": ida_enum is not None or local_types.get("available"),
        "items": sorted(by_name.values(), key=lambda item: clean_text(item.get("name")).lower()),
        "enum_database_count": len(enum_db_items),
        "local_type_count": len(local_types.get("enums") or []),
    }


def export_database(input_path):
    image_base = safe_call(0, idaapi.get_imagebase)
    start_ea = safe_call(idaapi.BADADDR, ida_ida.inf_get_start_ea)
    imports, exports = import_export_addresses()
    hashes = input_hashes()
    hexrays_version = ""
    if HAS_HEXRAYS:
        hexrays_version = clean_text(
            safe_call("", getattr(ida_hexrays, "get_hexrays_version", lambda: ""))
        )
    return {
        "schema": SCHEMA,
        "version": 1,
        "generated_at": utc_now_iso(),
        "input": os.path.abspath(input_path),
        "database": {
            "idb_path": clean_text(safe_call("", idc.get_idb_path)),
            "input_file_path": clean_text(safe_call("", idc.get_input_file_path)),
            "image_base": hex(image_base) if image_base else None,
            "entry_point": hex(start_ea) if start_ea != idaapi.BADADDR else None,
            "ida_version": clean_text(safe_call("", idaapi.get_kernel_version)),
            "hexrays_version": hexrays_version,
            "processor": clean_text(safe_call("", ida_ida.inf_get_procname)),
            "is_64bit": bool(safe_call(False, ida_ida.inf_is_64bit)),
            "input_sha256": hashes.get("sha256"),
            "input_md5": hashes.get("md5"),
        },
        "analysis_environment": {
            "network_policy": os.environ.get(
                "IDA_HARNESS_NETWORK_POLICY", "unreported"
            ),
            "lumina_policy": os.environ.get(
                "IDA_HARNESS_LUMINA_POLICY", "unreported"
            ),
            "user_state_policy": os.environ.get(
                "IDA_HARNESS_USER_STATE_POLICY", "unreported"
            ),
            "user_state_seed": os.environ.get(
                "IDA_HARNESS_USER_STATE_SEED", "unreported"
            ),
            "idausr": os.environ.get("IDAUSR", ""),
            "applied_signatures": applied_signatures(),
            "name_provenance_available": True,
            "function_identity_available": True,
        },
        "functions": export_functions(imports, exports),
        "data": export_data(imports, exports),
        "structs": export_structs(),
        "enums": export_enums(),
    }


def main(argv):
    args = parse_args(argv)
    load_binary(args.input)
    result = export_database(args.input)
    write_json(args.output, result)
    if args.save_as:
        save_database(args.save_as)
    print(json.dumps({
        "schema": SCHEMA,
        "output": args.output,
        "functions": len(result.get("functions") or []),
        "data": len(result.get("data") or []),
        "structs": len((result.get("structs") or {}).get("items") or []),
        "enums": len((result.get("enums") or {}).get("items") or []),
        "saved_as": args.save_as,
    }, indent=2))
    return 0


if __name__ == "__main__":
    exit_code = main(sys.argv[1:])
    if exit_code:
        raise SystemExit(exit_code)
