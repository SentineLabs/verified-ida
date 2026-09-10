"""
Apply host-approved program-model type-stabilization updates to an IDA database.

This script runs inside IDA/idat under the no-network sandbox. It intentionally
does not call a model and does not decide what is safe. The host launcher writes
an update file containing only validated actions.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_segment
import ida_typeinf
import idaapi
import idc

from ida_backend import save_database
from ida_reader import load_binary


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Apply program-model IDA type updates.")
    parser.add_argument("input", help="IDB or I64 to update.")
    parser.add_argument("--updates", required=True, help="Host-approved type update JSON path.")
    parser.add_argument("--save-as", required=True, help="Output IDB/I64 path.")
    parser.add_argument("--summary", required=False, help="Write application summary JSON to this path.")
    parser.add_argument(
        "--replace-existing-named-types",
        action="store_true",
        help="Allow structure/enum declarations to replace existing named local types.",
    )
    return parser.parse_args(argv)


def _load_updates(path):
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, list):
        return _normalize_update_bundle({"updates": data})
    return _normalize_update_bundle(data)


def _parse_addr(value):
    try:
        if isinstance(value, str):
            return int(value, 16)
        return int(value)
    except Exception:
        return None


def _target_address_alias(item):
    target = item.get("target")
    if isinstance(target, str) and re.match(r"^0x[0-9a-fA-F]+$", target.strip()):
        return target
    if isinstance(target, int):
        return target
    return None


def _normalize_update_bundle(data):
    if not isinstance(data, dict):
        return {"updates": []}
    rows = []
    for item in data.get("updates") or []:
        if not isinstance(item, dict):
            continue
        row = dict(item)
        kind = row.get("kind")
        if kind == "prototype":
            row["kind"] = "prototype_update"
        if row.get("kind") == "prototype_update":
            if "address" not in row or row.get("address") in (None, ""):
                address = row.get("ea") or row.get("function_ea") or row.get("func_ea") or _target_address_alias(row)
                if address not in (None, ""):
                    row["address"] = address
            if "proposed" not in row and row.get("prototype"):
                row["proposed"] = row.get("prototype")
            if "proposed" not in row and row.get("declaration"):
                row["proposed"] = row.get("declaration")
        elif row.get("kind") in {"global_type_update", "local_type_update", "local_name_update"}:
            if "address" not in row or row.get("address") in (None, ""):
                address = row.get("ea") or row.get("function_ea") or row.get("func_ea")
                if row.get("kind") == "global_type_update":
                    address = address or _target_address_alias(row)
                if address not in (None, ""):
                    row["address"] = address
        rows.append(row)
    out = dict(data)
    out["updates"] = rows
    return out


def _is_code(ea):
    seg = ida_segment.getseg(ea)
    if not seg:
        return False
    return bool(seg.perm & ida_segment.SEGPERM_EXEC) or seg.type == ida_segment.SEG_CODE


def _is_valid_data_address(ea):
    if ea is None or ida_funcs.get_func(ea) is not None:
        return False
    seg = ida_segment.getseg(ea)
    if not seg:
        return False
    # Zero-initialized storage may be a dedicated BSS segment or the unloaded
    # virtual tail of a writable PE data segment.
    try:
        loaded = ida_bytes.is_loaded(ea)
    except Exception:
        loaded = True
    if not loaded:
        segment_type = getattr(seg, "type", None)
        is_bss = segment_type == getattr(
            ida_segment, "SEG_BSS", object()
        )
        is_writable_data = (
            segment_type == getattr(ida_segment, "SEG_DATA", object())
            and bool(
                getattr(seg, "perm", 0)
                & getattr(ida_segment, "SEGPERM_WRITE", 0)
            )
        )
        if not (is_bss or is_writable_data):
            return False
    try:
        return not ida_bytes.is_code(ida_bytes.get_flags(ea))
    except Exception:
        return True


def _set_type(ea, type_string):
    if not type_string:
        return False
    try:
        return bool(idc.SetType(ea, type_string))
    except Exception:
        return False


def _split_tail_item_if_requested(ea, item):
    if not item.get("split_tail"):
        return False
    try:
        flags = ida_bytes.get_flags(ea)
        if not ida_bytes.is_tail(flags):
            return False
        head = ida_bytes.get_item_head(ea)
        size = ida_bytes.get_item_size(head)
        if head in (None, idaapi.BADADDR) or size <= 0:
            return False
        return bool(ida_bytes.del_items(head, ida_bytes.DELIT_SIMPLE, size))
    except Exception:
        return False


def _global_type_declaration(item):
    text = str(item.get("proposed_type") or item.get("proposed") or item.get("type") or "").strip()
    if not text:
        return ""
    text = text.rstrip(";").strip()
    address_name = str(item.get("name") or item.get("proposed_name") or item.get("new_name") or "").strip()
    if address_name and text.endswith(" " + address_name):
        return text[: -len(address_name)].strip()
    match = re.match(r"^(?P<type>.+?)\s+[_A-Za-z?$@.][_0-9A-Za-z?$@.]*$", text)
    if match:
        return match.group("type").strip()
    return text


_PROTOTYPE_DECLARATION_KEYS = ("proposed", "proposed_type", "prototype", "new_prototype", "declaration", "type")


def _prototype_declaration(item):
    for key in _PROTOTYPE_DECLARATION_KEYS:
        value = item.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _named_type_exists(name):
    if not name:
        return False
    try:
        tif = ida_typeinf.tinfo_t()
        if tif.get_named_type(None, name):
            return True
    except Exception:
        pass
    try:
        tif = ida_typeinf.tinfo_t()
        if tif.get_named_type(ida_typeinf.get_idati(), name):
            return True
    except Exception:
        pass
    try:
        return idc.get_struc_id(name) != idc.BADADDR
    except Exception:
        return False


COMMON_EXTERNAL_TYPE_TOKENS = {
    "BOOL",
    "BOOLEAN",
    "BYTE",
    "CHAR",
    "CRITICAL_SECTION",
    "DWORD",
    "DWORD64",
    "HANDLE",
    "HRESULT",
    "HWND",
    "LPCSTR",
    "LPCWSTR",
    "LPSTR",
    "LPVOID",
    "LPWSTR",
    "NTSTATUS",
    "PDRIVER_OBJECT",
    "PIRP",
    "PUNICODE_STRING",
    "SIZE_T",
    "SSIZE_T",
    "UCHAR",
    "UINT",
    "ULONG",
    "ULONG_PTR",
    "UNICODE_STRING",
    "USHORT",
    "WCHAR",
    "_CONTEXT",
    "_DISPATCHER_CONTEXT",
    "_EXCEPTION_RECORD",
}


def _prototype_missing_type_hints(prototype):
    text = _normalize_declaration_text(prototype)
    if not text:
        return []
    tokens = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", text))
    missing = []
    for token in sorted(tokens):
        if token not in COMMON_EXTERNAL_TYPE_TOKENS:
            continue
        base = token[1:] if token.startswith("P") and len(token) > 2 and token[1].isupper() else token
        if _named_type_exists(token) or _named_type_exists(base):
            continue
        missing.append(token)
    return missing


def _type_replace_flag():
    return int(getattr(ida_typeinf, "PT_REPLACE", getattr(idc, "PT_REPLACE", 0)) or 0)


def _normalize_declaration_text(declaration):
    value = str(declaration or "")
    if "\\n" in value or "\\t" in value or "\\r" in value:
        value = value.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\t", "\t").replace("\\r", "\r")
    return value


def _split_c_declaration_block(declaration):
    value = _normalize_declaration_text(declaration).strip()
    if not value:
        return []
    parts = []
    start = 0
    brace_depth = 0
    for index, ch in enumerate(value):
        if ch == "{":
            brace_depth += 1
        elif ch == "}":
            brace_depth = max(0, brace_depth - 1)
        elif ch == ";" and brace_depth == 0:
            part = value[start:index + 1].strip()
            if part:
                parts.append(part)
            start = index + 1
    tail = value[start:].strip()
    if tail:
        parts.append(tail)
    return parts or [value]


def _parse_declaration_once(declaration, flags):
    til = None
    try:
        til = ida_typeinf.get_idati()
    except Exception:
        til = None

    attempts = []
    parser = getattr(ida_typeinf, "idc_parse_types", None)
    if callable(parser):
        attempts.append(lambda: parser(declaration, flags))
    parser = getattr(ida_typeinf, "parse_decls", None)
    if callable(parser):
        attempts.append(lambda: parser(til, declaration, None, flags))
        attempts.append(lambda: parser(til, declaration, flags))
    parser = getattr(idc, "parse_decls", None)
    if callable(parser):
        attempts.append(lambda: parser(declaration, flags))

    for attempt in attempts:
        try:
            result = attempt()
            if result is True or result == 0:
                return True
        except Exception:
            continue
    return False


def _parse_type_declaration(declaration, replace_existing=False):
    declaration = _normalize_declaration_text(declaration)
    if not declaration:
        return False
    flags = getattr(ida_typeinf, "PT_SIL", getattr(idc, "PT_SIL", 0))
    if replace_existing:
        flags |= _type_replace_flag()
    if _parse_declaration_once(declaration, flags):
        return True
    parts = _split_c_declaration_block(declaration)
    if len(parts) <= 1:
        return False
    return all(_parse_declaration_once(part, flags) for part in parts)


def _declaration_defines_type_body(declaration):
    return "{" in _normalize_declaration_text(declaration) and "}" in _normalize_declaration_text(declaration)


def _update_apply_priority(item):
    kind = item.get("kind")
    if kind == "typedef_type_update":
        return 10
    if kind == "enum_type_update":
        return 20
    if kind == "structure_type_update":
        return 30
    if kind == "global_type_update":
        return 40
    if kind == "prototype_update":
        return 50
    if kind == "local_type_update":
        return 60
    if kind == "local_name_update":
        return 65
    return 100


def _update_type_name(item):
    if item.get("kind") in {"typedef_type_update", "enum_type_update", "structure_type_update"}:
        return str(item.get("name") or "").strip()
    return ""


def _declaration_references_type(declaration, name):
    if not declaration or not name:
        return False
    return re.search(r"\b%s\b" % re.escape(name), _normalize_declaration_text(declaration)) is not None


def _order_priority_group(indexed_rows):
    rows_by_index = {index: item for index, item in indexed_rows}
    names_by_index = {index: _update_type_name(item) for index, item in indexed_rows}
    known_names = {name for name in names_by_index.values() if name}
    dependencies = {}
    for index, item in indexed_rows:
        own_name = names_by_index.get(index)
        declaration = item.get("declaration")
        dependencies[index] = {
            dep_index
            for dep_index, dep_name in names_by_index.items()
            if dep_index != index
            and dep_name
            and dep_name in known_names
            and dep_name != own_name
            and _declaration_references_type(declaration, dep_name)
        }

    ordered = []
    pending = set(rows_by_index)
    while pending:
        ready = sorted(index for index in pending if not (dependencies[index] & pending))
        if not ready:
            ready = [min(pending)]
        for index in ready:
            ordered.append((index, rows_by_index[index]))
            pending.remove(index)
    return ordered


def _ordered_updates(update_bundle):
    rows = list(update_bundle.get("updates") or [])
    ordered = []
    indexed = sorted(enumerate(rows), key=lambda pair: (_update_apply_priority(pair[1]), pair[0]))
    group = []
    group_priority = None
    for pair in indexed:
        priority = _update_apply_priority(pair[1])
        if group and priority != group_priority:
            ordered.extend(_order_priority_group(group))
            group = []
        group.append(pair)
        group_priority = priority
    if group:
        ordered.extend(_order_priority_group(group))
    return ordered


def _apply_structure_type_update(item, replace_existing=False):
    name = str(item.get("name") or "").strip()
    declaration = item.get("declaration")
    if not name or not declaration:
        return "failed", "Missing structure name or declaration"
    exists = _named_type_exists(name)
    if exists and not replace_existing:
        if _declaration_defines_type_body(declaration) and _parse_type_declaration(declaration, replace_existing=False):
            return "refined", ""
        return "confirmed_existing", ""
    if exists and replace_existing and not _type_replace_flag():
        if _declaration_defines_type_body(declaration) and _parse_type_declaration(declaration, replace_existing=False):
            return "refined", ""
        return "confirmed_existing", "IDA named type replacement flag is unavailable"
    if not _parse_type_declaration(declaration, replace_existing=bool(exists and replace_existing)):
        return "failed", "IDA rejected structure declaration for %s" % name
    if not _named_type_exists(name):
        return "failed", "Structure declaration parsed but named type was not visible: %s" % name
    if exists:
        return "refined", ""
    return "applied", ""


def _apply_enum_type_update(item, replace_existing=False):
    name = str(item.get("name") or "").strip()
    declaration = item.get("declaration")
    if not name or not declaration:
        return "failed", "Missing enum name or declaration"
    exists = _named_type_exists(name)
    if exists and not replace_existing:
        return "confirmed_existing", ""
    if exists and replace_existing and not _type_replace_flag():
        return "confirmed_existing", "IDA named type replacement flag is unavailable"
    if not _parse_type_declaration(declaration, replace_existing=bool(exists and replace_existing)):
        return "failed", "IDA rejected enum declaration for %s" % name
    if not _named_type_exists(name):
        return "failed", "Enum declaration parsed but named type was not visible: %s" % name
    if exists:
        return "refined", ""
    return "applied", ""


def _apply_typedef_type_update(item, replace_existing=False):
    name = str(item.get("name") or "").strip()
    declaration = item.get("declaration")
    if not name or not declaration:
        return "failed", "Missing typedef name or declaration"
    exists = _named_type_exists(name)
    if exists and not replace_existing:
        return "confirmed_existing", ""
    if exists and replace_existing and not _type_replace_flag():
        return "confirmed_existing", "IDA named type replacement flag is unavailable"
    if not _parse_type_declaration(declaration, replace_existing=bool(exists and replace_existing)):
        return "failed", "IDA rejected typedef declaration for %s" % name
    if not _named_type_exists(name):
        return "failed", "Typedef declaration parsed but named type was not visible: %s" % name
    if exists:
        return "refined", ""
    return "applied", ""


def _normalize_type_text(value):
    text = " ".join(str(value or "").replace("*", " * ").split())
    replacements = {
        "unsigned __int8": "unsigned char",
        "signed __int8": "signed char",
        "__int8": "char",
        "_BYTE": "unsigned char",
        "_DWORD": "unsigned int",
        "struct lua_State": "lua_State",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


def _lvar_type_text(lvar):
    try:
        return lvar.type().dstr()
    except Exception:
        return ""


def _tinfo_type_text(tif):
    try:
        return tif.dstr()
    except Exception:
        return ""


def _call_or_value(obj, name, default=None):
    try:
        attr = getattr(obj, name)
        return attr() if callable(attr) else attr
    except Exception:
        return default


def _lvar_location_kind(lvar):
    location = getattr(lvar, "location", None)
    for source, predicates in (
        (
            lvar,
            (
                ("is_stk_var", "stack"),
                ("is_reg_var", "register"),
                ("is_scattered", "scattered"),
            ),
        ),
        (
            location,
            (
                ("is_stkoff", "stack"),
                ("is_reg", "register"),
                ("is_reg1", "register"),
                ("is_scattered", "scattered"),
                ("is_empty", "empty"),
            ),
        ),
    ):
        if source is None:
            continue
        for predicate, kind in predicates:
            if _call_or_value(source, predicate, False):
                return kind
    if _lvar_stack_offset(lvar) is not None:
        return "stack"
    return "unknown"


def _lvar_stack_offset(lvar):
    location = getattr(lvar, "location", None)
    for source in (lvar, location):
        if source is None:
            continue
        for method in ("get_stkoff", "stkoff"):
            value = _call_or_value(source, method)
            if isinstance(value, int) and value >= 0:
                return value
    return None


def _parse_int(value):
    try:
        if value is None or value == "":
            return None
        return int(value)
    except Exception:
        return None


def _array_decl_for_type(type_string, name):
    match = re.match(r"^(?P<base>.+?)(?P<suffix>(?:\s*\[[^\]]*\])+)$", type_string)
    if not match:
        return None
    return "%s %s%s;" % (match.group("base").strip(), name, match.group("suffix").replace(" ", ""))


def _windows_typedef_expansions(type_string):
    replacements = {
        "LPCSTR": "const char *",
        "PCSTR": "const char *",
        "LPSTR": "char *",
        "PSTR": "char *",
        "LPCWSTR": "const wchar_t *",
        "PCWSTR": "const wchar_t *",
        "LPWSTR": "wchar_t *",
        "PWSTR": "wchar_t *",
        "LPBYTE": "unsigned char *",
        "PBYTE": "unsigned char *",
        "BYTE": "unsigned char",
        "DWORD": "unsigned int",
        "BOOL": "int",
    }
    values = [type_string]
    for old, new in replacements.items():
        pattern = r"\b%s\b" % re.escape(old)
        if re.search(pattern, type_string):
            expanded = re.sub(pattern, new, type_string)
            if expanded not in values:
                values.append(expanded)
    return values


def _parse_lvar_type(type_string, target_name=None):
    type_string = str(type_string or "").strip().rstrip(";")
    if not type_string:
        return None
    name = "__ida_harness_lvar"
    declarations = []
    for candidate in _windows_typedef_expansions(type_string):
        if target_name and re.search(r"\b%s\b" % re.escape(str(target_name)), candidate):
            declarations.append((candidate + ";", ida_typeinf.PT_VAR))
            declarations.append((
                re.sub(r"\b%s\b" % re.escape(str(target_name)), name, candidate, count=1) + ";",
                ida_typeinf.PT_VAR,
            ))
        array_decl = _array_decl_for_type(candidate, name)
        if array_decl:
            declarations.append((array_decl, ida_typeinf.PT_VAR))
        declarations.extend([
            ("%s %s;" % (candidate, name), ida_typeinf.PT_VAR),
            ("%s;" % candidate, ida_typeinf.PT_TYP),
        ])

    seen = set()
    for decl, parse_kind in declarations:
        if decl in seen:
            continue
        seen.add(decl)
        tif = ida_typeinf.tinfo_t()
        flags = ida_typeinf.PT_SIL | parse_kind
        try:
            if ida_typeinf.parse_decl(tif, None, decl, flags) and not tif.empty():
                return tif
        except Exception:
            pass
        try:
            parsed = idc.parse_decl(decl, idc.PT_SIL)
            if parsed is not None:
                _name, type_bytes, field_bytes = parsed
                if tif.deserialize(None, type_bytes, field_bytes) and not tif.empty():
                    return tif
        except Exception:
            pass
    return None


def _safe_lvar_name(value):
    name = str(value or "").strip()
    if not name:
        return ""
    if len(name) > 80:
        return ""
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
        return ""
    if name in {"if", "for", "while", "switch", "return", "sizeof"}:
        return ""
    return name


def _proposed_lvar_name(item):
    for key in ("proposed_name", "new_name", "proposed_variable", "proposed_parameter"):
        name = _safe_lvar_name(item.get(key))
        if name:
            return name
    return ""


def _locators_match(lvar, item):
    requested_kind = str((item.get("location") or {}).get("kind") or item.get("location_kind") or "")
    requested_stack_offset = _parse_int((item.get("location") or {}).get("stack_offset"))
    if requested_stack_offset is None:
        requested_stack_offset = _parse_int(item.get("stack_offset"))
    live_stack_offset = _lvar_stack_offset(lvar)
    if requested_kind and _lvar_location_kind(lvar) != requested_kind:
        if not (requested_kind == "stack" and requested_stack_offset is not None and live_stack_offset == requested_stack_offset):
            return False
    if requested_stack_offset is not None and live_stack_offset != requested_stack_offset:
        return False
    return True


def _role_matches(lvar, item):
    if "is_arg" not in item and "is_parameter" not in item:
        return True
    expected = bool(item.get("is_arg") or item.get("is_parameter"))
    return expected == bool(_call_or_value(lvar, "is_arg_var", False))


def _current_type_matches(lvar, item):
    current_type = item.get("current_type")
    if not current_type:
        return True
    return _normalize_type_text(current_type) == _normalize_type_text(_lvar_type_text(lvar))


def _live_type_matches_proposed(lvar, proposed_type, parsed_type):
    return _normalize_type_text(_lvar_type_text(lvar)) in {
        _normalize_type_text(proposed_type),
        _normalize_type_text(parsed_type),
    }


def _compatible_lvar_anchor(lvar, item, *, check_current_type=True):
    if not _locators_match(lvar, item) or not _role_matches(lvar, item):
        return False
    if check_current_type and not _current_type_matches(lvar, item):
        return False
    return True


def _find_lvar(cfunc, item, *, check_current_type=True):
    expected_name = str(item.get("variable") or item.get("parameter") or item.get("target") or "")
    proposed_name = _proposed_lvar_name(item)
    acceptable_names = {name for name in (expected_name, proposed_name) if name}
    requested_index = _parse_int(item.get("lvar_index"))
    lvars = list(cfunc.lvars)

    if requested_index is not None and 0 <= requested_index < len(lvars):
        lvar = lvars[requested_index]
        live_name = str(getattr(lvar, "name", "") or "")
        if (
            (not acceptable_names or live_name in acceptable_names)
            and _compatible_lvar_anchor(lvar, item, check_current_type=check_current_type)
        ):
            return lvar, ""
        if acceptable_names and _compatible_lvar_anchor(lvar, item, check_current_type=check_current_type):
            return lvar, "lvar_index matched after Hex-Rays renamed the local"

    matches = [
        lvar
        for lvar in lvars
        if str(getattr(lvar, "name", "") or "") in acceptable_names
    ]
    matches = [
        lvar
        for lvar in matches
        if _compatible_lvar_anchor(lvar, item, check_current_type=check_current_type)
    ]
    if not matches:
        locator_matches = [
            lvar
            for lvar in lvars
            if _compatible_lvar_anchor(lvar, item, check_current_type=check_current_type)
        ]
        if len(locator_matches) == 1 and (
            requested_index is not None
            or (item.get("location") or {}).get("stack_offset") is not None
            or item.get("stack_offset") is not None
            or "is_arg" in item
            or "is_parameter" in item
        ):
            return locator_matches[0], "unique live lvar matched by compatibility anchors"
        if requested_index is not None:
            return None, "lvar_index became stale and no matching name/location lvar was found"
        return None, "No matching lvar found in decompiled function"
    if len(matches) > 1:
        return None, "Multiple lvars matched; lvar_index is required"
    return matches[0], ""


def _apply_lvar_name(func_ea, lvar, new_name):
    old_name = str(getattr(lvar, "name", "") or "")
    new_name = _safe_lvar_name(new_name)
    if not new_name or old_name == new_name:
        return "unchanged", ""
    try:
        rename = getattr(ida_hexrays, "rename_lvar", None)
        if callable(rename) and rename(func_ea, old_name, new_name):
            return "applied", ""
    except Exception:
        pass
    try:
        info = ida_hexrays.lvar_saved_info_t()
        info.ll = lvar
        info.name = new_name
        if ida_hexrays.modify_user_lvar_info(func_ea, ida_hexrays.MLI_NAME, info):
            return "applied", ""
    except Exception as exc:
        return "failed", "Failed to persist lvar name update: %s" % exc
    return "failed", "Hex-Rays rejected the lvar name update"


def _apply_local_type_update(item):
    func_ea = _parse_addr(item.get("address"))
    if func_ea is None or ida_funcs.get_func(func_ea) is None:
        return "failed", "Invalid function address for local type update: %r" % (item.get("address"),)
    if not ida_hexrays.init_hexrays_plugin():
        return "failed", "Hex-Rays decompiler is unavailable"

    proposed_type = item.get("proposed_type")
    tif = _parse_lvar_type(proposed_type, item.get("variable") or item.get("parameter") or item.get("target"))
    if tif is None:
        return "failed", "IDA could not parse local type %r" % (proposed_type,)

    try:
        cfunc = ida_hexrays.decompile(func_ea)
    except Exception as exc:
        return "failed", "Hex-Rays failed to decompile %s: %s" % (hex(func_ea), exc)
    if cfunc is None:
        return "failed", "Hex-Rays returned no cfunc for %s" % hex(func_ea)

    parsed_type = _tinfo_type_text(tif)
    lvar, reason = _find_lvar(cfunc, item)
    if lvar is None:
        loose_lvar, _loose_reason = _find_lvar(cfunc, item, check_current_type=False)
        if loose_lvar is not None and _live_type_matches_proposed(loose_lvar, proposed_type, parsed_type):
            proposed_name = _proposed_lvar_name(item)
            if proposed_name:
                name_status, name_reason = _apply_lvar_name(func_ea, loose_lvar, proposed_name)
                if name_status == "failed":
                    return "confirmed_existing", "Live Hex-Rays local type matched proposed type; %s" % name_reason
                if name_status == "applied":
                    return "applied", "Hex-Rays local type was already proposed and local name was applied"
            return "confirmed_existing", "Live Hex-Rays local type already matched proposed type"
        if loose_lvar is not None:
            return "deferred", "lvar current type changed before type application"
        return "deferred", reason

    proposed_name = _proposed_lvar_name(item)
    if ("is_arg" in item or "is_parameter" in item) and not _role_matches(lvar, item):
        return "deferred", "lvar argument/local role changed before type application"
    current_type = item.get("current_type")
    live_type = _lvar_type_text(lvar)
    if _live_type_matches_proposed(lvar, proposed_type, parsed_type):
        if proposed_name:
            name_status, name_reason = _apply_lvar_name(func_ea, lvar, proposed_name)
            if name_status == "failed":
                return "confirmed_existing", "Live Hex-Rays local type matched proposed type; %s" % name_reason
            try:
                ida_hexrays.mark_cfunc_dirty(func_ea, True)
                ida_hexrays.clear_cached_cfuncs()
                refreshed = ida_hexrays.decompile(func_ea)
                renamed_lvar, rename_reason = _find_lvar(refreshed, item, check_current_type=False)
                if renamed_lvar is None:
                    return "deferred", "Could not confirm persisted lvar name after rerender: %s" % rename_reason
                if str(getattr(renamed_lvar, "name", "") or "") != proposed_name:
                    return "failed", "Persisted lvar name did not reread as proposed"
            except Exception as exc:
                return "failed", "Could not confirm persisted lvar name: %s" % exc
            if name_status == "applied":
                return "applied", "Hex-Rays accepted and reread the local name"
        return "confirmed_existing", ""
    if current_type and _normalize_type_text(current_type) != _normalize_type_text(live_type):
        return "deferred", "lvar current type changed before type application"
    try:
        if not lvar.accepts_type(tif, False):
            return "failed", "Hex-Rays rejected the proposed lvar type for this variable"
    except Exception:
        pass

    info = ida_hexrays.lvar_saved_info_t()
    try:
        info.ll = lvar
        info.type = tif
        try:
            info.size = tif.get_size()
        except Exception:
            pass
        if not ida_hexrays.modify_user_lvar_info(func_ea, ida_hexrays.MLI_TYPE, info):
            return "failed", "modify_user_lvar_info rejected the lvar type update"
    except Exception as exc:
        return "failed", "Failed to persist lvar type update: %s" % exc

    if proposed_name:
        name_status, name_reason = _apply_lvar_name(func_ea, lvar, proposed_name)
        if name_status == "failed":
            proposed_name = ""

    try:
        ida_hexrays.mark_cfunc_dirty(func_ea, True)
        ida_hexrays.clear_cached_cfuncs()
        ida_auto.auto_wait()
        refreshed = ida_hexrays.decompile(func_ea)
        refreshed_lvar, reason = _find_lvar(refreshed, item, check_current_type=False)
        if refreshed_lvar is None:
            return "deferred", "Could not confirm persisted lvar type after rerender: %s" % reason
        if _normalize_type_text(_lvar_type_text(refreshed_lvar)) not in {
            _normalize_type_text(proposed_type),
            _normalize_type_text(parsed_type),
        }:
            return "failed", "Persisted lvar type did not reread as proposed"
        if proposed_name and str(getattr(refreshed_lvar, "name", "") or "") != proposed_name:
            return "failed", "Persisted lvar name did not reread as proposed"
    except Exception as exc:
        return "failed", "Could not confirm persisted lvar type: %s" % exc

    if proposed_name:
        return "applied", "Hex-Rays accepted and reread the local type/name"
    return "applied", ""


def _apply_local_name_update(item):
    func_ea = _parse_addr(item.get("address"))
    if func_ea is None or ida_funcs.get_func(func_ea) is None:
        return "failed", "Invalid function address for local name update: %r" % (item.get("address"),)
    proposed_name = _proposed_lvar_name(item)
    if not proposed_name:
        return "failed", "Missing or invalid proposed local name"
    if not ida_hexrays.init_hexrays_plugin():
        return "failed", "Hex-Rays decompiler is unavailable"
    try:
        cfunc = ida_hexrays.decompile(func_ea)
    except Exception as exc:
        return "failed", "Hex-Rays failed to decompile %s: %s" % (hex(func_ea), exc)
    if cfunc is None:
        return "failed", "Hex-Rays returned no cfunc for %s" % hex(func_ea)
    lvar, reason = _find_lvar(cfunc, item, check_current_type=False)
    if lvar is None:
        return "deferred", reason
    status, reason = _apply_lvar_name(func_ea, lvar, proposed_name)
    if status == "unchanged":
        return "confirmed_existing", "Live Hex-Rays local name already matched proposed name"
    if status == "failed":
        return "failed", reason
    try:
        ida_hexrays.mark_cfunc_dirty(func_ea, True)
        ida_hexrays.clear_cached_cfuncs()
        ida_auto.auto_wait()
        refreshed = ida_hexrays.decompile(func_ea)
        renamed_lvar, rename_reason = _find_lvar(refreshed, item, check_current_type=False)
        if renamed_lvar is None:
            return "deferred", "Could not confirm persisted lvar name after rerender: %s" % rename_reason
        if str(getattr(renamed_lvar, "name", "") or "") != proposed_name:
            return "failed", "Persisted lvar name did not reread as proposed"
    except Exception as exc:
        return "failed", "Could not confirm persisted lvar name: %s" % exc
    return "applied", "Hex-Rays accepted and reread the local name"


def apply_updates(update_bundle, *, replace_existing_named_types=False):
    summary = {
        "prototype_applied": False,
        "local_variable_types_applied": 0,
        "local_variable_names_applied": 0,
        "local_variable_types_confirmed_existing": 0,
        "local_variable_names_confirmed_existing": 0,
        "local_variable_types_deferred": 0,
        "local_variable_names_deferred": 0,
        "global_types_applied": 0,
        "structures_created": 0,
        "structures_refined": 0,
        "structures_confirmed_existing": 0,
        "enums_created": 0,
        "enums_refined": 0,
        "enums_confirmed_existing": 0,
        "typedefs_created": 0,
        "typedefs_refined": 0,
        "typedefs_confirmed_existing": 0,
        "applied_total": 0,
        "attempted_total": 0,
        "failed": 0,
        "errors": [],
        "deferred": [],
        "records": [],
    }

    for _, item in _ordered_updates(update_bundle):
        kind = item.get("kind")
        if kind == "prototype_update":
            proposed_type = _prototype_declaration(item)
        elif kind == "global_type_update":
            proposed_type = _global_type_declaration(item)
        else:
            proposed_type = item.get("proposed_type") or item.get("proposed")
        summary["attempted_total"] += 1
        record = {
            "kind": kind,
            "address": item.get("address"),
            "target": item.get("variable") or item.get("parameter") or item.get("address") or item.get("name"),
            "proposed_type": proposed_type,
            "proposed_name": item.get("proposed_name") or item.get("new_name"),
            "current_type": item.get("current_type") or item.get("current"),
            "lvar_index": item.get("lvar_index"),
            "is_parameter": item.get("is_parameter"),
            "is_arg": item.get("is_arg"),
            "location": item.get("location") or {},
            "status": "pending",
            "reason": "",
            "retry_strategy": "",
        }
        if kind == "prototype_update":
            ea = _parse_addr(item.get("address"))
            if ea is None or ida_funcs.get_func(ea) is None:
                summary["failed"] += 1
                reason = "Invalid function address for prototype update: %r" % (item.get("address"),)
                summary["errors"].append(reason)
                record.update({"status": "failed", "reason": reason})
                summary["records"].append(record)
                continue
            if not proposed_type:
                summary["failed"] += 1
                reason = (
                    "Missing prototype declaration for prototype update at %s; "
                    "expected one of: %s"
                ) % (item.get("address"), ", ".join(_PROTOTYPE_DECLARATION_KEYS))
                summary["errors"].append(reason)
                record.update({"status": "failed", "reason": reason})
            elif _set_type(ea, proposed_type):
                summary["prototype_applied"] = True
                summary["applied_total"] += 1
                record.update({"status": "applied", "reason": "IDA accepted function prototype update"})
            else:
                summary["failed"] += 1
                missing_types = _prototype_missing_type_hints(proposed_type)
                reason = "IDA rejected prototype update at %s" % item.get("address")
                if missing_types:
                    reason += "; probable missing named/platform types: %s" % ", ".join(missing_types)
                summary["errors"].append(reason)
                record.update({"status": "failed", "reason": reason})
            summary["records"].append(record)
            continue

        if kind == "local_type_update":
            status, reason = _apply_local_type_update(item)
            if status == "applied":
                summary["local_variable_types_applied"] += 1
                summary["applied_total"] += 1
                record.update({"status": "applied", "reason": "Hex-Rays accepted and reread the local type"})
            elif status == "confirmed_existing":
                summary["local_variable_types_confirmed_existing"] += 1
                record.update({"status": "confirmed_existing", "reason": "Live Hex-Rays local type already matched proposed type"})
            elif status == "deferred":
                summary["local_variable_types_deferred"] += 1
                deferred_record = {
                    "kind": "local_type_update",
                    "target": item.get("variable") or item.get("parameter") or item.get("target"),
                    "address": item.get("address"),
                    "proposed_type": item.get("proposed_type"),
                    "proposed_name": item.get("proposed_name") or item.get("new_name"),
                    "current_type": item.get("current_type"),
                    "lvar_index": item.get("lvar_index"),
                    "is_parameter": item.get("is_parameter"),
                    "is_arg": item.get("is_arg"),
                    "location": item.get("location") or {},
                    "reason": reason,
                    "retry_strategy": "re-export function, re-anchor by name/location/use-site, and retry only if a unique live lvar matches",
                }
                summary["deferred"].append(deferred_record)
                record.update({
                    "status": "deferred",
                    "reason": reason,
                    "retry_strategy": deferred_record["retry_strategy"],
                })
            else:
                summary["failed"] += 1
                summary["errors"].append(reason)
                record.update({"status": "failed", "reason": reason})
            summary["records"].append(record)
            continue

        if kind == "local_name_update":
            status, reason = _apply_local_name_update(item)
            if status == "applied":
                summary["local_variable_names_applied"] += 1
                summary["applied_total"] += 1
                record.update({"status": "applied", "reason": reason or "Hex-Rays accepted and reread the local name"})
            elif status == "confirmed_existing":
                summary["local_variable_names_confirmed_existing"] += 1
                record.update({"status": "confirmed_existing", "reason": reason or "Live Hex-Rays local name already matched proposed name"})
            elif status == "deferred":
                summary["local_variable_names_deferred"] += 1
                deferred_record = {
                    "kind": "local_name_update",
                    "target": item.get("variable") or item.get("parameter") or item.get("target"),
                    "address": item.get("address"),
                    "proposed_name": item.get("proposed_name") or item.get("new_name"),
                    "lvar_index": item.get("lvar_index"),
                    "is_parameter": item.get("is_parameter"),
                    "is_arg": item.get("is_arg"),
                    "location": item.get("location") or {},
                    "reason": reason,
                    "retry_strategy": "re-export function, re-anchor by name/location/use-site, and retry only if a unique live lvar matches",
                }
                summary["deferred"].append(deferred_record)
                record.update({
                    "status": "deferred",
                    "reason": reason,
                    "retry_strategy": deferred_record["retry_strategy"],
                })
            else:
                summary["failed"] += 1
                summary["errors"].append(reason)
                record.update({"status": "failed", "reason": reason})
            summary["records"].append(record)
            continue

        if kind == "global_type_update":
            ea = _parse_addr(item.get("address"))
            if ea is None or not _is_valid_data_address(ea):
                summary["failed"] += 1
                reason = "Invalid data address for global type update: %r" % (item.get("address"),)
                summary["errors"].append(reason)
                record.update({"status": "failed", "reason": reason})
                summary["records"].append(record)
                continue
            split_tail = _split_tail_item_if_requested(ea, item)
            if _set_type(ea, proposed_type):
                comment = item.get("reason") or ""
                if comment:
                    idc.set_cmt(ea, comment, 0)
                summary["global_types_applied"] += 1
                summary["applied_total"] += 1
                reason = "IDA accepted global data type update"
                if split_tail:
                    reason += " after splitting stale containing item"
                record.update({"status": "applied", "reason": reason})
            else:
                summary["failed"] += 1
                reason = "IDA rejected global type update at %s" % item.get("address")
                summary["errors"].append(reason)
                record.update({"status": "failed", "reason": reason})
            summary["records"].append(record)
            continue

        if kind == "structure_type_update":
            status, reason = _apply_structure_type_update(
                item,
                replace_existing=replace_existing_named_types,
            )
            if status == "applied":
                summary["structures_created"] += 1
                summary["applied_total"] += 1
                record.update({"status": "applied", "reason": "IDA accepted structure type declaration"})
            elif status == "refined":
                summary["structures_refined"] += 1
                summary["applied_total"] += 1
                record.update({"status": "refined", "reason": "IDA replaced existing structure type declaration"})
            elif status == "confirmed_existing":
                summary["structures_confirmed_existing"] += 1
                record.update({"status": "confirmed_existing", "reason": reason or "IDA already had the named structure type"})
            else:
                summary["failed"] += 1
                summary["errors"].append(reason)
                record.update({"status": "failed", "reason": reason})
            summary["records"].append(record)
            continue

        if kind == "enum_type_update":
            status, reason = _apply_enum_type_update(
                item,
                replace_existing=replace_existing_named_types,
            )
            if status == "applied":
                summary["enums_created"] += 1
                summary["applied_total"] += 1
                record.update({"status": "applied", "reason": "IDA accepted enum type declaration"})
            elif status == "refined":
                summary["enums_refined"] += 1
                summary["applied_total"] += 1
                record.update({"status": "refined", "reason": "IDA replaced existing enum type declaration"})
            elif status == "confirmed_existing":
                summary["enums_confirmed_existing"] += 1
                record.update({"status": "confirmed_existing", "reason": reason or "IDA already had the named enum type"})
            else:
                summary["failed"] += 1
                summary["errors"].append(reason)
                record.update({"status": "failed", "reason": reason})
            summary["records"].append(record)
            continue

        if kind == "typedef_type_update":
            status, reason = _apply_typedef_type_update(
                item,
                replace_existing=replace_existing_named_types,
            )
            if status == "applied":
                summary["typedefs_created"] += 1
                summary["applied_total"] += 1
                record.update({"status": "applied", "reason": "IDA accepted typedef declaration"})
            elif status == "refined":
                summary["typedefs_refined"] += 1
                summary["applied_total"] += 1
                record.update({"status": "refined", "reason": "IDA replaced existing typedef declaration"})
            elif status == "confirmed_existing":
                summary["typedefs_confirmed_existing"] += 1
                record.update({"status": "confirmed_existing", "reason": reason or "IDA already had the named typedef"})
            else:
                summary["failed"] += 1
                summary["errors"].append(reason)
                record.update({"status": "failed", "reason": reason})
            summary["records"].append(record)
            continue

        summary["failed"] += 1
        reason = "Unsupported type update kind: %r" % (kind,)
        summary["errors"].append(reason)
        record.update({"status": "failed", "reason": reason})
        summary["records"].append(record)

    if summary["applied_total"]:
        try:
            idaapi.auto_wait()
        except Exception:
            pass

    return summary


def main(argv):
    args = parse_args(argv)
    load_binary(args.input)
    update_bundle = _load_updates(args.updates)
    summary = apply_updates(
        update_bundle,
        replace_existing_named_types=args.replace_existing_named_types,
    )
    save_database(args.save_as)
    if args.summary:
        os.makedirs(os.path.dirname(os.path.abspath(args.summary)), exist_ok=True)
        with open(args.summary, "w") as f:
            json.dump(summary, f, indent=2)
    print(json.dumps(summary, indent=2))
    print("Saved typed database to: %s" % args.save_as)
    return 0


if __name__ == "__main__":
    main(sys.argv[1:])
