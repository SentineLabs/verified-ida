"""
Execute bounded structural queries inside IDA.

This script runs under `scripts/run_ida_script_no_network.sh`; it must stay
deterministic and network-free. The host runner owns orchestration and model
calls, if any.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from collections import deque

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import ida_bytes
import ida_funcs
import ida_loader
import ida_lines
import ida_name
import ida_nalt
import ida_segment
import idautils
import idc
try:
    import idaapi
except ImportError:
    idaapi = None
try:
    import ida_hexrays
except ImportError:
    ida_hexrays = None
try:
    import ida_idp
    import ida_ua
except ImportError:
    ida_idp = None
    ida_ua = None

from ida_reader import load_binary
from ida_ctree_summary import summarize_ctree
from ida_analyst_api import normalize_capability_name
from pe_inventory import build_pe_inventory, build_pe_inventory_bytes


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Run IDA structural query tasks.")
    parser.add_argument("input", help="IDB/I64 loaded by IDA.")
    parser.add_argument("--tasks", required=True, help="JSON task list.")
    parser.add_argument("--output", required=True, help="Output JSON path.")
    return parser.parse_args(argv)


def _hex(value):
    if value is None or value == idc.BADADDR:
        return None
    return hex(int(value))


def _parse_int(value):
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 16 if text.lower().startswith("0x") else 10)
    except ValueError:
        return None


def _file_offset(ea):
    try:
        off = ida_loader.get_fileregion_offset(ea)
        if off is None or off < 0:
            return None
        return off
    except Exception:
        return None


def _segment(ea):
    seg = ida_segment.getseg(ea)
    if not seg:
        return None
    return {
        "name": idc.get_segm_name(ea),
        "start": _hex(seg.start_ea),
        "end": _hex(seg.end_ea),
        "perm": int(seg.perm),
        "type": int(seg.type),
    }


def _segment_name(ea):
    seg = ida_segment.getseg(ea)
    if not seg:
        return None
    return idc.get_segm_name(ea)


def _func_at(ea):
    func = ida_funcs.get_func(ea)
    if not func:
        return None
    return {
        "address": _hex(func.start_ea),
        "name": idc.get_func_name(func.start_ea) or "sub_%x" % func.start_ea,
    }


def _safe_name(ea):
    try:
        return ida_name.get_name(ea) or ""
    except Exception:
        return ""


def _safe_comment(ea, repeatable=False):
    try:
        return ida_bytes.get_cmt(ea, 1 if repeatable else 0) or ""
    except Exception:
        return ""


def _safe_dword(ea):
    try:
        value = ida_bytes.get_dword(ea)
    except Exception:
        return None
    if value is None or value == idc.BADADDR:
        return None
    return int(value)


def _pointer_size():
    try:
        if idaapi is not None and hasattr(idaapi, "inf_is_64bit"):
            return 8 if idaapi.inf_is_64bit() else 4
        if idaapi is not None and hasattr(idaapi, "get_inf_structure"):
            return 8 if idaapi.get_inf_structure().is_64bit() else 4
    except Exception:
        pass
    return 4


def _safe_pointer(ea):
    try:
        value = (
            ida_bytes.get_qword(ea)
            if _pointer_size() == 8 and hasattr(ida_bytes, "get_qword")
            else ida_bytes.get_dword(ea)
        )
    except Exception:
        return None
    if value is None or value == idc.BADADDR:
        return None
    return int(value)


def render_vtable_entries(address, max_entries=64):
    ea = _parse_int(address)
    if ea is None:
        return {"ok": False, "error": "missing address", "entries": []}
    stride = _pointer_size()
    entries = []
    boundary_reason = ""
    boundary_address = None
    for index in range(max(1, min(int(max_entries or 64), 256))):
        slot_ea = ea + (index * stride)
        slot_name = _safe_name(slot_ea)
        if index and slot_name:
            boundary_reason = "named_item_boundary"
            boundary_address = slot_ea
            break
        target_ea = _safe_pointer(slot_ea)
        if target_ea is None:
            boundary_reason = "unreadable_pointer"
            boundary_address = slot_ea
            break
        function = _func_at(target_ea)
        if not function:
            boundary_reason = (
                "first_slot_not_function"
                if index == 0
                else "non_function_pointer"
            )
            boundary_address = slot_ea
            break
        entries.append(
            {
                "index": index,
                "slot_address": _hex(slot_ea),
                "slot_name": slot_name,
                "target": _hex(target_ea),
                "target_name": _safe_name(target_ea)
                or function.get("name")
                or "",
                "target_type": _safe_type(target_ea),
                "function": function,
            }
        )
    return {
        "ok": True,
        "address": _hex(ea),
        "pointer_size": stride,
        "entry_count": len(entries),
        "entries": entries,
        "boundary_reason": boundary_reason or "maximum_entries",
        "boundary_address": _hex(boundary_address),
    }


def _safe_disassembly(ea):
    try:
        return _clean_line(idc.generate_disasm_line(ea, 0) or "")
    except Exception:
        return ""


def _safe_type(ea):
    getter = getattr(idc, "get_type", None)
    if not callable(getter):
        return ""
    try:
        return getter(ea) or ""
    except Exception:
        return ""


def _clean_line(text):
    try:
        return ida_lines.tag_remove(text or "")
    except Exception:
        return text or ""


def _function(address):
    ea = _parse_int(address)
    if ea is None:
        return None, None
    func = ida_funcs.get_func(ea)
    return ea, func


def _ida_name_provenance(ea):
    """Return IDA's native name flags without inferring provenance from spelling."""

    try:
        flags = ida_bytes.get_flags(ea)
        has_user_name = bool(ida_bytes.has_user_name(flags))
        has_auto_name = bool(ida_bytes.has_auto_name(flags))
        has_dummy_name = bool(ida_bytes.has_dummy_name(flags))
        return {
            "has_user_name": has_user_name,
            "has_auto_name": has_auto_name,
            "has_dummy_name": has_dummy_name,
            "name_provenance": (
                "user"
                if has_user_name
                else "dummy"
                if has_dummy_name
                else "auto"
                if has_auto_name
                else "not_user_supplied"
            ),
        }
    except Exception:
        return {
            "has_user_name": None,
            "has_auto_name": None,
            "has_dummy_name": None,
            "name_provenance": "unknown",
        }


def _function_bounds(func):
    if not func:
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
    nonrepeatable = idc.get_func_cmt(func.start_ea, 0) or ""
    repeatable = idc.get_func_cmt(func.start_ea, 1) or ""
    return {
        "start": _hex(func.start_ea),
        "end": _hex(func.end_ea),
        "size": size,
        "name": idc.get_func_name(func.start_ea) or "",
        "prototype": idc.get_type(func.start_ea) or "",
        "comment": repeatable or nonrepeatable,
        "comments": {
            "nonrepeatable": nonrepeatable,
            "repeatable": repeatable,
        },
        "function_byte_hash": digest.hexdigest(),
        **_ida_name_provenance(func.start_ea),
    }


def _function_summary(ea):
    func = ida_funcs.get_func(ea)
    if not func:
        return None
    name = idc.get_func_name(func.start_ea) or "sub_%x" % func.start_ea
    flags = 0
    try:
        flags = int(idc.get_func_attr(func.start_ea, getattr(idc, "FUNCATTR_FLAGS", 8)) or 0)
    except Exception:
        flags = 0
    nonrepeatable = idc.get_func_cmt(func.start_ea, 0) or ""
    repeatable = idc.get_func_cmt(func.start_ea, 1) or ""
    comment = repeatable or nonrepeatable
    provenance = _ida_name_provenance(func.start_ea)
    anonymous = bool(provenance.get("has_dummy_name"))
    if provenance.get("has_dummy_name") is None:
        anonymous = bool(
            re.match(r"^(sub|loc|unknown|function)_[0-9a-f]+$", name, re.I)
        )
    return {
        "address": _hex(func.start_ea),
        "end": _hex(func.end_ea),
        "name": name,
        "size": int(func.end_ea - func.start_ea),
        "segment": _segment_name(func.start_ea),
        "flags": flags,
        "prototype": _safe_type(func.start_ea),
        "comment": comment,
        "comments": {
            "nonrepeatable": nonrepeatable,
            "repeatable": repeatable,
        },
        "name_class": "anonymous" if anonymous else "named",
        **provenance,
    }


def _perm_text(perm):
    chars = []
    if perm & ida_segment.SEGPERM_READ:
        chars.append("r")
    if perm & ida_segment.SEGPERM_WRITE:
        chars.append("w")
    if perm & ida_segment.SEGPERM_EXEC:
        chars.append("x")
    return "".join(chars) or "-"


def _magic(data):
    if data.startswith(b"MZ"):
        return "PE executable"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP archive"
    if data.startswith(b"\x1bLua"):
        return "Lua bytecode"
    if data.startswith(b"\x7fELF"):
        return "ELF executable"
    if data.startswith(b"{") or data.startswith(b"["):
        return "JSON-like text"
    return None


def _registered_input_path(input_file_path=None):
    """Resolve only the host-bound input when one was supplied.

    An IDB retains the path of the machine on which it was first created.
    That historical path is useful provenance but is not a safe source for
    current-file reads after the project has moved to another host.
    """

    if input_file_path is not None:
        candidate = os.path.abspath(str(input_file_path))
        return candidate if os.path.isfile(candidate) else None
    historical = idc.get_input_file_path()
    return historical if historical and os.path.isfile(historical) else None


def _bounded_file_read(file_offset, size, *, input_file_path=None):
    path = _registered_input_path(input_file_path)
    if not path:
        return b""
    try:
        with open(path, "rb") as handle:
            handle.seek(max(0, int(file_offset)))
            return handle.read(max(0, int(size)))
    except Exception:
        return b""


def _bounded_file_sha256(
    file_offset,
    size,
    max_hash_bytes=67108864,
    *,
    input_file_path=None,
):
    path = _registered_input_path(input_file_path)
    if not path:
        return None
    digest = hashlib.sha256()
    remaining = min(max(0, int(size or 0)), max(0, int(max_hash_bytes or 0)))
    try:
        with open(path, "rb") as handle:
            handle.seek(max(0, int(file_offset or 0)))
            while remaining:
                chunk = handle.read(min(1048576, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
    except Exception:
        return None
    return digest.hexdigest()


def _string_at(ea, max_length=160):
    data = ida_bytes.get_strlit_contents(ea, -1, 0)
    if data is None:
        data = ida_bytes.get_strlit_contents(ea, -1, 1)
    if data is None:
        return None
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = repr(data)
    return text[:max_length]


def query_xrefs(address, limit=80):
    ea = _parse_int(address)
    if ea is None:
        return {"ok": False, "error": "missing address"}
    refs_to = []
    refs_from = []
    for xref in list(idautils.XrefsTo(ea, 0))[:limit]:
        refs_to.append({
            "from": _hex(xref.frm),
            "to": _hex(xref.to),
            "type": int(xref.type),
            "function": _func_at(xref.frm),
        })
    func = ida_funcs.get_func(ea)
    heads = list(idautils.FuncItems(func.start_ea)) if func else [ea]
    for head in heads[:2000]:
        for target in idautils.CodeRefsFrom(head, 0):
            refs_from.append({
                "from": _hex(head),
                "to": _hex(target),
                "function": _func_at(target),
            })
            if len(refs_from) >= limit:
                break
        if len(refs_from) >= limit:
            break
    return {
        "ok": True,
        "address": _hex(ea),
        "refs_to": refs_to,
        "refs_from": refs_from,
        "count_to": len(refs_to),
        "count_from": len(refs_from),
    }


def retrieve_disassembly(address, limit=120, offset=0):
    ea, func = _function(address)
    if ea is None:
        return {"ok": False, "error": "missing address"}
    if not func:
        return {"ok": False, "error": "no function at address", "address": _hex(ea)}
    page_size = max(1, min(int(limit or 120), 800))
    page_offset = max(0, int(offset or 0))
    heads = list(idautils.FuncItems(func.start_ea))
    lines = []
    for head in heads[page_offset:page_offset + page_size]:
        lines.append({
            "address": _hex(head),
            "disassembly": _clean_line(idc.generate_disasm_line(head, 0) or ""),
            "mnemonic": idc.print_insn_mnem(head) or "",
        })
    return {
        "ok": True,
        "address": _hex(ea),
        "function": _function_bounds(func),
        "line_count": len(lines),
        "total_line_count": len(heads),
        "offset": page_offset,
        "next_offset": page_offset + len(lines),
        "has_more": page_offset + len(lines) < len(heads),
        "lines": lines,
    }


def retrieve_pseudocode(address, limit=240, offset=0):
    ea, func = _function(address)
    if ea is None:
        return {"ok": False, "error": "missing address"}
    if not func:
        return {"ok": False, "error": "no function at address", "address": _hex(ea)}
    try:
        import ida_hexrays
    except Exception as exc:
        return {"ok": False, "error": "Hex-Rays module unavailable: %s" % exc, "address": _hex(ea)}
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return {"ok": False, "error": "Hex-Rays plugin is not initialized", "address": _hex(ea)}
        cfunc = ida_hexrays.decompile(func.start_ea)
        if not cfunc:
            return {"ok": False, "error": "Hex-Rays decompile returned no cfunc", "address": _hex(ea)}
        page_size = max(1, min(int(limit or 240), 1000))
        page_offset = max(0, int(offset or 0))
        source_lines = list(cfunc.get_pseudocode())
        pseudocode = []
        for line in source_lines[page_offset:page_offset + page_size]:
            pseudocode.append(_clean_line(line.line))
        return {
            "ok": True,
            "address": _hex(ea),
            "function": _function_bounds(func),
            "line_count": len(pseudocode),
            "total_line_count": len(source_lines),
            "offset": page_offset,
            "next_offset": page_offset + len(pseudocode),
            "has_more": page_offset + len(pseudocode) < len(source_lines),
            "pseudocode": pseudocode,
        }
    except Exception as exc:
        return {"ok": False, "error": "decompile failed: %s" % exc, "address": _hex(ea), "function": _function_bounds(func)}


def query_callers_callees(address, limit=120):
    ea, func = _function(address)
    if ea is None:
        return {"ok": False, "error": "missing address"}
    if not func:
        return {"ok": False, "error": "no function at address", "address": _hex(ea)}
    callers = []
    for ref in list(idautils.CodeRefsTo(func.start_ea, 0))[:limit]:
        caller_func = ida_funcs.get_func(ref)
        if caller_func and int(caller_func.start_ea) == int(func.start_ea):
            continue
        callers.append({
            "from": _hex(ref),
            "caller": _func_at(ref),
        })
    seen = set()
    callees = []
    for head in idautils.FuncItems(func.start_ea):
        for target in idautils.CodeRefsFrom(head, 0):
            callee = _func_at(target)
            if not callee:
                continue
            if int(callee["address"], 0) == int(func.start_ea):
                continue
            key = callee["address"]
            if key in seen:
                continue
            seen.add(key)
            callees.append({"from": _hex(head), "to": _hex(target), "callee": callee})
            if len(callees) >= limit:
                break
        if len(callees) >= limit:
            break
    return {
        "ok": True,
        "address": _hex(ea),
        "function": _function_bounds(func),
        "callers": callers,
        "callees": callees,
        "caller_count": len(callers),
        "callee_count": len(callees),
    }


def _instruction_feature(ea, feature_name):
    """Return an IDA-native instruction feature decision when available."""

    if ida_idp is None or ida_ua is None:
        return None
    try:
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) <= 0:
            return None
        feature = int(insn.get_canon_feature())
        mask = getattr(ida_idp, feature_name, None)
        if mask is None:
            return None
        return bool(feature & int(mask))
    except Exception:
        return None


def _instruction_kind(ea):
    is_call = _instruction_feature(ea, "CF_CALL")
    if is_call is True:
        return "call", "ida_instruction_feature"
    is_jump = _instruction_feature(ea, "CF_JUMP")
    if is_jump is True:
        return "jump", "ida_instruction_feature"
    # This fallback is presentation-only provenance. The claim-flow runtime
    # admits blocking edges only when IDA's decoded instruction features prove
    # the instruction class.
    mnemonic = str(idc.print_insn_mnem(ea) or "").strip().lower()
    if mnemonic in {"call", "callq", "bl", "blx", "jal", "jalr", "bctrl"}:
        return "call", "mnemonic_fallback"
    if mnemonic.startswith("j") or mnemonic in {"b", "br", "bx"}:
        return "jump", "mnemonic_fallback"
    return "other", "unknown"


def _import_addresses():
    values = set()
    try:
        count = int(ida_nalt.get_import_module_qty() or 0)
    except Exception:
        return values
    for index in range(count):
        def callback(ea, _name, _ordinal):
            values.add(int(ea))
            return True
        try:
            ida_nalt.enum_import_names(index, callback)
        except Exception:
            continue
    return values


def _function_native_flags(func):
    flags = 0
    if func is None:
        return {
            "flags": flags,
            "is_library": False,
            "is_thunk": False,
        }
    try:
        flags = int(getattr(func, "flags", 0) or 0)
    except Exception:
        flags = 0
    if not flags:
        try:
            flags = int(idc.get_func_attr(
                func.start_ea, getattr(idc, "FUNCATTR_FLAGS", 8)
            ) or 0)
        except Exception:
            flags = 0
    library_flag = int(
        getattr(ida_funcs, "FUNC_LIB", getattr(idaapi, "FUNC_LIB", 0)) or 0
    )
    thunk_flag = int(
        getattr(ida_funcs, "FUNC_THUNK", getattr(idaapi, "FUNC_THUNK", 0)) or 0
    )
    return {
        "flags": flags,
        "is_library": bool(library_flag and flags & library_flag),
        "is_thunk": bool(thunk_flag and flags & thunk_flag),
    }


def inspect_direct_call_edges(address, limit=4096):
    """Inventory decoded direct calls without treating all code refs as calls."""

    ea, func = _function(address)
    if ea is None:
        return {"ok": False, "error": "missing address"}
    if not func:
        return {"ok": False, "error": "no function at address", "address": _hex(ea)}
    maximum = max(1, min(int(limit or 4096), 4096))
    imports = _import_addresses()
    edges = []
    all_edge_count = 0
    for head in idautils.FuncItems(func.start_ea):
        instruction_kind, classification_source = _instruction_kind(head)
        if instruction_kind not in {"call", "jump"}:
            continue
        targets = list(idautils.CodeRefsFrom(head, 0))
        if not targets and instruction_kind == "call":
            all_edge_count += 1
            if len(edges) < maximum:
                edges.append({
                    "source": _hex(func.start_ea),
                    "callsite": _hex(head),
                    "destination": None,
                    "destination_function": None,
                    "edge_kind": "unresolved_indirect",
                    "classification_source": classification_source,
                    "instruction": _safe_disassembly(head),
                })
            continue
        for target in targets:
            callee = ida_funcs.get_func(target)
            callee_start = int(callee.start_ea) if callee else int(target)
            if callee and callee_start == int(func.start_ea):
                continue
            flags = _function_native_flags(callee)
            if instruction_kind == "jump":
                edge_kind = "tail_call"
            elif int(target) in imports or callee_start in imports:
                edge_kind = "direct_import"
            elif flags["is_thunk"]:
                edge_kind = "direct_thunk"
            elif flags["is_library"]:
                edge_kind = "direct_library"
            elif callee:
                edge_kind = "direct_internal"
            else:
                edge_kind = "unresolved_direct"
            all_edge_count += 1
            if len(edges) >= maximum:
                continue
            destination_function = _function_bounds(callee) if callee else None
            if destination_function is not None:
                destination_function.update(flags)
            edges.append({
                "source": _hex(func.start_ea),
                "callsite": _hex(head),
                "destination": _hex(callee_start),
                "destination_function": destination_function,
                "edge_kind": edge_kind,
                "classification_source": classification_source,
                "instruction": _safe_disassembly(head),
            })
    canonical_edges = [{
        key: row.get(key)
        for key in (
            "source", "callsite", "destination", "edge_kind",
            "classification_source",
        )
    } for row in edges]
    digest = hashlib.sha256(json.dumps(
        canonical_edges,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    counts = {}
    for row in edges:
        kind = row["edge_kind"]
        counts[kind] = counts.get(kind, 0) + 1
    return {
        "ok": True,
        "schema": "verified_ida.direct_call_inventory.v1",
        "address": _hex(func.start_ea),
        "function": _function_bounds(func),
        "edges": edges,
        "edge_count": all_edge_count,
        "returned_edge_count": len(edges),
        "counts_by_kind": dict(sorted(counts.items())),
        "complete": all_edge_count <= len(edges),
        "truncated": all_edge_count > len(edges),
        "edge_set_digest": digest,
        "blocking_edge_policy": (
            "only direct_internal edges classified by ida_instruction_feature"
        ),
    }


def query_data_refs(address, limit=80):
    ea = _parse_int(address)
    if ea is None:
        return {"ok": False, "error": "missing address"}
    refs_to = []
    refs_from = []
    for frm in list(idautils.DataRefsTo(ea))[:limit]:
        refs_to.append({
            "from": _hex(frm),
            "to": _hex(ea),
            "function": _func_at(frm),
            "segment": _segment(frm),
        })
    for to in list(idautils.DataRefsFrom(ea))[:limit]:
        refs_from.append({
            "from": _hex(ea),
            "to": _hex(to),
            "function": _func_at(to),
            "segment": _segment(to),
        })
    return {
        "ok": True,
        "address": _hex(ea),
        "refs_to": refs_to,
        "refs_from": refs_from,
        "count_to": len(refs_to),
        "count_from": len(refs_from),
    }


def inspect_bytes(address, size=256):
    ea = _parse_int(address)
    if ea is None:
        return {"ok": False, "error": "missing address"}
    size = max(1, min(int(size or 256), 4096))
    data = ida_bytes.get_bytes(ea, size) or b""
    printable = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:160])
    return {
        "ok": True,
        "address": _hex(ea),
        "requested_size": size,
        "size": len(data),
        "file_offset": _hex(_file_offset(ea)),
        "segment": _segment(ea),
        "hex": data.hex(),
        "hex_prefix": data[:128].hex(),
        "ascii_preview": printable,
        "all_zero": bool(data) and all(b == 0 for b in data),
    }


def linear_disassemble(address, size=256, limit=120, force=False):
    ea = _parse_int(address)
    if ea is None:
        return {"ok": False, "error": "missing address"}
    size = max(1, min(int(size or 256), 8192))
    limit = max(1, min(int(limit or 120), 1000))
    end = ea + size
    cursor = ea
    lines = []
    while cursor < end and len(lines) < limit:
        if force:
            try:
                idc.create_insn(cursor)
            except Exception:
                pass
        flags = ida_bytes.get_flags(cursor)
        text = _clean_line(idc.generate_disasm_line(cursor, 0) or "")
        item_size = ida_bytes.get_item_size(cursor)
        if item_size <= 0:
            item_size = 1
        lines.append({
            "address": _hex(cursor),
            "file_offset": _hex(_file_offset(cursor)),
            "is_code": bool(ida_bytes.is_code(flags)),
            "item_size": int(item_size),
            "mnemonic": idc.print_insn_mnem(cursor) or "",
            "disassembly": text,
        })
        cursor += item_size
    return {
        "ok": True,
        "address": _hex(ea),
        "requested_size": size,
        "segment": _segment(ea),
        "line_count": len(lines),
        "lines": lines,
    }


def render_cfg(address, limit=120):
    ea, func = _function(address)
    if ea is None:
        return {"ok": False, "error": "missing address"}
    if not func:
        return {"ok": False, "error": "no function at address", "address": _hex(ea)}
    try:
        import ida_gdl
    except Exception as exc:
        return {"ok": False, "error": "IDA graph module unavailable: %s" % exc, "address": _hex(ea)}
    limit = max(1, min(int(limit or 120), 1000))
    blocks = []
    edges = []
    try:
        flow = ida_gdl.FlowChart(func)
        block_ids = {}
        for index, block in enumerate(flow):
            if len(blocks) >= limit:
                break
            block_id = "bb_%04d" % index
            block_ids[int(block.start_ea)] = block_id
            heads = list(idautils.Heads(block.start_ea, block.end_ea))
            branch = heads[-1] if heads else block.start_ea
            instructions = []
            for head in heads[:12]:
                instructions.append({
                    "address": _hex(head),
                    "mnemonic": idc.print_insn_mnem(head) or "",
                    "disassembly": _clean_line(idc.generate_disasm_line(head, 0) or ""),
                })
            blocks.append({
                "id": block_id,
                "start": _hex(block.start_ea),
                "end": _hex(block.end_ea),
                "instruction_count": len(heads),
                "branch": {
                    "address": _hex(branch),
                    "mnemonic": idc.print_insn_mnem(branch) or "",
                    "disassembly": _clean_line(idc.generate_disasm_line(branch, 0) or ""),
                },
                "instructions": instructions,
            })
        known = set(block_ids)
        for block in ida_gdl.FlowChart(func):
            if int(block.start_ea) not in known:
                continue
            source_id = block_ids[int(block.start_ea)]
            for succ in block.succs():
                if int(succ.start_ea) not in block_ids:
                    continue
                edges.append({
                    "from": source_id,
                    "to": block_ids[int(succ.start_ea)],
                    "from_address": _hex(block.start_ea),
                    "to_address": _hex(succ.start_ea),
                })
                if len(edges) >= limit * 2:
                    break
            if len(edges) >= limit * 2:
                break
    except Exception as exc:
        return {"ok": False, "error": "CFG render failed: %s" % exc, "address": _hex(ea), "function": _function_bounds(func)}
    return {
        "ok": True,
        "address": _hex(ea),
        "function": _function_bounds(func),
        "block_count": len(blocks),
        "edge_count": len(edges),
        "blocks": blocks,
        "edges": edges,
    }


def render_data_object(address, size=256):
    ea = _parse_int(address)
    if ea is None:
        return {"ok": False, "error": "missing address"}
    size = max(1, min(int(size or 256), 4096))
    flags = ida_bytes.get_flags(ea)
    data = ida_bytes.get_bytes(ea, size) or b""
    refs_to = [{"from": _hex(frm), "function": _func_at(frm)} for frm in list(idautils.DataRefsTo(ea))[:80]]
    refs_from = [{"to": _hex(to), "function": _func_at(to)} for to in list(idautils.DataRefsFrom(ea))[:80]]
    return {
        "ok": True,
        "address": _hex(ea),
        "name": ida_name.get_name(ea) or "",
        "segment": _segment(ea),
        "file_offset": _hex(_file_offset(ea)),
        "item_size": ida_bytes.get_item_size(ea),
        "is_code": bool(ida_bytes.is_code(flags)),
        "is_data": bool(ida_bytes.is_data(flags)),
        "string": _string_at(ea),
        "requested_size": size,
        "size": len(data),
        "hex_prefix": data[:128].hex(),
        "refs_to": refs_to,
        "refs_from": refs_from,
        "count_to": len(refs_to),
        "count_from": len(refs_from),
    }


def render_strings(address=None, limit=80):
    limit = max(1, min(int(limit or 80), 500))
    func = None
    if address:
        _, func = _function(address)
    items = []
    strings = list(idautils.Strings())
    for string in strings:
        ea = int(string.ea)
        if func:
            refs = list(idautils.DataRefsTo(ea))
            if not any(func.start_ea <= ref < func.end_ea for ref in refs):
                continue
        text = str(string)
        items.append({
            "address": _hex(ea),
            "length": int(getattr(string, "length", len(text)) or len(text)),
            "type": int(getattr(string, "strtype", 0) or 0),
            "segment": _segment(ea),
            "text": text[:240],
            "refs_to": [{"from": _hex(ref), "function": _func_at(ref)} for ref in list(idautils.DataRefsTo(ea))[:20]],
        })
        if len(items) >= limit:
            break
    return {
        "ok": True,
        "address": _hex(_parse_int(address)) if address else None,
        "function": _function_bounds(func) if func else None,
        "strings": items,
        "count": len(items),
    }


def render_imports(address=None, limit=160):
    limit = max(1, min(int(limit or 160), 1000))
    imports = []

    def callback(ea, name, ordinal):
        if len(imports) >= limit:
            return False
        imports.append({
            "address": _hex(ea),
            "name": name or "",
            "ordinal": int(ordinal or 0),
            "refs_to": [{"from": _hex(ref), "function": _func_at(ref)} for ref in list(idautils.DataRefsTo(ea))[:20]],
        })
        return True

    for index in range(ida_nalt.get_import_module_qty()):
        module_name = ida_nalt.get_import_module_name(index) or ""
        before = len(imports)
        ida_nalt.enum_import_names(index, callback)
        for item in imports[before:]:
            item["module"] = module_name
        if len(imports) >= limit:
            break

    if address:
        _, func = _function(address)
        if func:
            imports = [
                item for item in imports
                if any(
                    (ref.get("function") or {}).get("address") == _hex(func.start_ea)
                    for ref in item.get("refs_to") or []
                )
            ][:limit]
    return {"ok": True, "imports": imports, "count": len(imports)}


def render_idb_meta(limit=80):
    functions = list(getattr(idautils, "Functions", lambda: [])())
    names = list(getattr(idautils, "Names", lambda: [])())
    start_ea = None
    try:
        import ida_ida

        start_ea = ida_ida.inf_get_start_ea()
    except Exception:
        start_ea = None
    image_base = None
    try:
        image_base = ida_nalt.get_imagebase()
    except Exception:
        image_base = None
    try:
        ida_version = idaapi.get_kernel_version() if idaapi is not None else None
    except Exception:
        ida_version = None
    try:
        hexrays_version = (
            ida_hexrays.get_hexrays_version()
            if ida_hexrays is not None
            else None
        )
    except Exception:
        hexrays_version = None
    return {
        "ok": True,
        "input_file_path": idc.get_input_file_path(),
        "image_base": _hex(image_base),
        "start_ea": _hex(start_ea),
        "processor": getattr(idc, "get_inf_attr", lambda _attr: None)(getattr(idc, "INF_PROCNAME", 0)),
        "counts": {
            "functions": len(functions),
            "names": len(names),
            "entrypoints": len(_entry_rows(include_primary=True, limit=limit)),
            "exports": len(_entry_rows(include_primary=False, limit=limit)),
        },
        "analysis": {
            "status": "available",
            "auto_wait_completed": True,
        },
        "runtime": {
            "ida_version": ida_version,
            "hexrays_version": hexrays_version,
            "python_version": sys.version.split()[0],
        },
    }


def _segment_rows():
    rows = []
    for ea in getattr(idautils, "Segments", lambda: [])():
        seg = ida_segment.getseg(ea)
        if not seg:
            continue
        rows.append({
            "name": idc.get_segm_name(ea) or "",
            "start": _hex(seg.start_ea),
            "end": _hex(seg.end_ea),
            "size": max(0, int(seg.end_ea - seg.start_ea)),
            "permissions": _perm_text(int(seg.perm)),
            "type": int(seg.type),
        })
    return rows


def _all_import_rows(include_refs=False):
    rows = []
    for index in range(ida_nalt.get_import_module_qty()):
        module_name = ida_nalt.get_import_module_name(index) or ""

        def callback(ea, name, ordinal):
            row = {
                "address": _hex(ea),
                "name": name or "",
                "ordinal": int(ordinal or 0),
                "module": module_name,
                "segment": _segment_name(ea),
            }
            if include_refs:
                refs = list(idautils.DataRefsTo(ea))
                row["refs_to_count"] = len(refs)
                row["sample_refs_to"] = [
                    {"from": _hex(ref), "function": _func_at(ref)}
                    for ref in refs[:8]
                ]
            rows.append(row)
            return True

        ida_nalt.enum_import_names(index, callback)
    return rows


def _all_string_rows():
    rows = []
    strings = idautils.Strings()
    try:
        strings.setup(strtypes=[0, 1, 2, 3, 4, 5, 6, 7])
    except Exception:
        pass
    for item in strings:
        text = str(item)
        refs = list(idautils.DataRefsTo(item.ea))
        rows.append({
            "address": _hex(item.ea),
            "length": int(getattr(item, "length", len(text)) or len(text)),
            "type": int(getattr(item, "strtype", 0) or 0),
            "segment": _segment_name(item.ea),
            "text": text[:512],
            "refs_to_count": len(refs),
            "sample_refs_to": [
                {"from": _hex(ref), "function": _func_at(ref)}
                for ref in refs[:8]
            ],
        })
    return rows


def _processor_metadata():
    try:
        import ida_ida

        processor = ida_ida.inf_get_procname()
        bitness = 64 if ida_ida.inf_is_64bit() else 32
    except Exception:
        processor = None
        bitness = _pointer_size() * 8
    try:
        file_format = ida_loader.get_file_type_name()
    except Exception:
        file_format = None
    return {
        "format": file_format,
        "processor": processor,
        "bitness": bitness,
        "architecture": "%s-%d" % (processor or "unknown", bitness),
    }


def describe_query_runtime():
    import ida_pro
    from verified_ida.backend_limits import function_comment_limits
    decompiler_available = False
    try:
        decompiler_available = bool(
            ida_hexrays is not None and ida_hexrays.init_hexrays_plugin()
        )
    except Exception:
        decompiler_available = False
    return {
        "ok": True,
        "binary": _processor_metadata(),
        "analysis": {"decompiler_available": decompiler_available},
        "function_comment_limits": function_comment_limits(idaapi.get_kernel_version(), ida_pro.MAXSTR),
        "runtime": render_idb_meta().get("runtime") or {},
    }


def survey_idb():
    functions = [
        row for row in (
            _function_summary(ea)
            for ea in getattr(idautils, "Functions", lambda: [])()
        )
        if row
    ]
    names = list(getattr(idautils, "Names", lambda: [])())
    imports = _all_import_rows()
    strings = _all_string_rows()
    segments = _segment_rows()
    globals_used = _all_global_rows()
    entries = _entry_rows(include_primary=True, limit=None)
    exports = _entry_rows(include_primary=False, limit=None)
    local_types = _local_type_inventory(limit=None)
    modules = {}
    for row in imports:
        module = row.get("module") or ""
        modules[module] = modules.get(module, 0) + 1
    decompiler_available = False
    try:
        decompiler_available = bool(
            ida_hexrays is not None and ida_hexrays.init_hexrays_plugin()
        )
    except Exception:
        decompiler_available = False
    return {
        "ok": True,
        "binary": {
            **_processor_metadata(),
            "input_file_path": idc.get_input_file_path(),
            "image_base": _hex(ida_nalt.get_imagebase()),
        },
        "inventory": {
            "functions": len(functions),
            "anonymous_functions": sum(
                1 for row in functions if row.get("name_class") == "anonymous"
            ),
            "named_functions": sum(
                1 for row in functions if row.get("name_class") == "named"
            ),
            "commented_functions": sum(1 for row in functions if row.get("comment")),
            "prototyped_functions": sum(1 for row in functions if row.get("prototype")),
            "names": len(names),
            "imports": len(imports),
            "exports": len(exports),
            "entrypoints": len(entries),
            "strings": len(strings),
            "globals": len(globals_used),
            "segments": len(segments),
            "local_types": len(local_types.get("items") or []),
            "local_types_total_relation": (
                "exact" if local_types.get("scan_complete") else "lower_bound"
            ),
        },
        "segments": segments,
        "imports_by_module": dict(sorted(modules.items())),
        "analysis": {
            "autoanalysis_complete": True,
            "decompiler_available": decompiler_available,
            "decompilation_failures": {
                "value": None,
                "scan": "not_run",
                "reason": "Survey does not bulk-decompile the database.",
            },
            "potential_problem_indicators": {
                "anonymous_functions": sum(
                    1 for row in functions if row.get("name_class") == "anonymous"
                ),
                "functions_without_comments": sum(
                    1 for row in functions if not row.get("comment")
                ),
                "functions_without_prototypes": sum(
                    1 for row in functions if not row.get("prototype")
                ),
                "interpretation": "navigation facets, not semantic defects",
            },
        },
        "runtime": render_idb_meta().get("runtime") or {},
    }


def _page(items, *, entity, filters, order, limit, offset):
    page_limit = max(1, min(int(limit or 100), 500))
    page_offset = max(0, int(offset or 0))
    page_items = items[page_offset:page_offset + page_limit]
    next_offset = page_offset + len(page_items)
    return {
        "ok": True,
        "query": {
            "entity": entity,
            "filters": dict(filters or {}),
            "order": order,
        },
        "page": {
            "offset": page_offset,
            "returned": len(page_items),
            "limit": page_limit,
            "total": len(items),
            "total_relation": "exact",
            "has_more": next_offset < len(items),
            "next_offset": next_offset if next_offset < len(items) else None,
        },
        "scan": {"complete": True},
        "items": page_items,
    }


def query_functions_collection(filters=None, order="address", limit=100, offset=0):
    filters = dict(filters or {})
    rows = [
        row for row in (
            _function_summary(ea)
            for ea in getattr(idautils, "Functions", lambda: [])()
        )
        if row
    ]
    for row in rows:
        start = int(row["address"], 0)
        caller_starts = set()
        for ref in idautils.CodeRefsTo(start, False):
            caller = ida_funcs.get_func(ref)
            if caller and int(caller.start_ea) != start:
                caller_starts.add(int(caller.start_ea))
        callee_starts = set()
        for head in idautils.FuncItems(start):
            for target in idautils.CodeRefsFrom(head, False):
                callee = ida_funcs.get_func(target)
                if callee and int(callee.start_ea) != start:
                    callee_starts.add(int(callee.start_ea))
        row["caller_count"] = len(caller_starts)
        row["callee_count"] = len(callee_starts)
        row["xref_count"] = len(list(idautils.XrefsTo(start, 0)))
    segment = filters.get("segment")
    name_class = filters.get("name_class")
    prefix = filters.get("name_prefix")
    address_start = _parse_int(filters.get("address_start"))
    address_end = _parse_int(filters.get("address_end"))
    minimum = _parse_int(filters.get("minimum_size"))
    maximum = _parse_int(filters.get("maximum_size"))
    minimum_callers = _parse_int(filters.get("minimum_callers"))
    minimum_callees = _parse_int(filters.get("minimum_callees"))
    minimum_xrefs = _parse_int(filters.get("minimum_xrefs"))
    has_comment = filters.get("has_comment")
    has_prototype = filters.get("has_prototype")
    if segment:
        rows = [row for row in rows if row.get("segment") == segment]
    if name_class in {"anonymous", "named"}:
        rows = [row for row in rows if row.get("name_class") == name_class]
    if prefix:
        rows = [row for row in rows if str(row.get("name") or "").startswith(str(prefix))]
    if address_start is not None:
        rows = [row for row in rows if int(row["address"], 0) >= address_start]
    if address_end is not None:
        rows = [row for row in rows if int(row["address"], 0) < address_end]
    if minimum is not None:
        rows = [row for row in rows if int(row.get("size") or 0) >= minimum]
    if maximum is not None:
        rows = [row for row in rows if int(row.get("size") or 0) <= maximum]
    if minimum_callers is not None:
        rows = [row for row in rows if int(row.get("caller_count") or 0) >= minimum_callers]
    if minimum_callees is not None:
        rows = [row for row in rows if int(row.get("callee_count") or 0) >= minimum_callees]
    if minimum_xrefs is not None:
        rows = [row for row in rows if int(row.get("xref_count") or 0) >= minimum_xrefs]
    if isinstance(has_comment, bool):
        rows = [row for row in rows if bool(row.get("comment")) is has_comment]
    if isinstance(has_prototype, bool):
        rows = [row for row in rows if bool(row.get("prototype")) is has_prototype]
    if order == "name":
        rows.sort(key=lambda row: (str(row.get("name") or "").lower(), int(row["address"], 0)))
    elif order == "size_ascending":
        rows.sort(key=lambda row: (int(row.get("size") or 0), int(row["address"], 0)))
    elif order == "size_descending":
        rows.sort(key=lambda row: (-int(row.get("size") or 0), int(row["address"], 0)))
    else:
        rows.sort(key=lambda row: int(row["address"], 0))
    return _page(rows, entity="functions", filters=filters, order=order, limit=limit, offset=offset)


def query_symbols_collection(filters=None, order="address", limit=100, offset=0):
    filters = dict(filters or {})
    kind = str(filters.get("kind") or "names")
    if kind == "imports":
        rows = _all_import_rows(include_refs=True)
    elif kind == "exports":
        rows = _entry_rows(include_primary=False, limit=None)
    elif kind == "entrypoints":
        rows = _entry_rows(include_primary=True, limit=None)
    elif kind == "globals":
        rows = _all_global_rows()
    else:
        rows = [
            {
                "address": _hex(ea),
                "name": str(name),
                "segment": _segment_name(ea),
                "function": _func_at(ea),
                "type": _safe_type(ea),
            }
            for ea, name in getattr(idautils, "Names", lambda: [])()
        ]
    prefix = filters.get("name_prefix")
    module = filters.get("module")
    segment = filters.get("segment")
    if prefix:
        rows = [row for row in rows if str(row.get("name") or "").startswith(str(prefix))]
    if module:
        rows = [row for row in rows if row.get("module") == module]
    if segment:
        rows = [row for row in rows if row.get("segment") == segment]
    if order == "name":
        rows.sort(key=lambda row: (str(row.get("name") or "").lower(), int(row["address"], 0)))
    else:
        rows.sort(key=lambda row: int(row["address"], 0))
    return _page(rows, entity="symbols", filters=filters, order=order, limit=limit, offset=offset)


def query_strings_collection(filters=None, order="address", limit=100, offset=0):
    filters = dict(filters or {})
    rows = _all_string_rows()
    needle = str(filters.get("needle") or "").lower()
    segment = filters.get("segment")
    minimum = _parse_int(filters.get("minimum_length"))
    referenced = filters.get("referenced")
    if needle:
        rows = [row for row in rows if needle in str(row.get("text") or "").lower()]
    if segment:
        rows = [row for row in rows if row.get("segment") == segment]
    if minimum is not None:
        rows = [row for row in rows if int(row.get("length") or 0) >= minimum]
    if isinstance(referenced, bool):
        rows = [row for row in rows if bool(row.get("refs_to_count")) is referenced]
    if order == "length_descending":
        rows.sort(key=lambda row: (-int(row.get("length") or 0), int(row["address"], 0)))
    elif order == "text":
        rows.sort(key=lambda row: (str(row.get("text") or "").lower(), int(row["address"], 0)))
    else:
        rows.sort(key=lambda row: int(row["address"], 0))
    return _page(rows, entity="strings", filters=filters, order=order, limit=limit, offset=offset)


def query_types_collection(filters=None, order="name", limit=100, offset=0):
    filters = dict(filters or {})
    inventory = _local_type_inventory(limit=None)
    if not inventory.get("available") and inventory.get("error"):
        return {
            "ok": False,
            "error": inventory.get("error"),
            "recovery": "Inspect IDA local-type availability before querying types.",
        }
    rows = list(inventory.get("items") or [])
    kind = str(filters.get("kind") or "all")
    prefix = str(filters.get("name_prefix") or "")
    if kind in {"struct", "enum"}:
        rows = [row for row in rows if row.get("kind") == kind]
    if prefix:
        rows = [row for row in rows if str(row.get("name") or "").startswith(prefix)]
    if order == "kind":
        rows.sort(key=lambda row: (str(row.get("kind") or ""), str(row.get("name") or "").lower()))
    else:
        rows.sort(key=lambda row: str(row.get("name") or "").lower())
    return _page(rows, entity="types", filters=filters, order=order, limit=limit, offset=offset)


def inspect_function_summary(address, sample_limit=12):
    ea, func = _function(address)
    if ea is None:
        return {"ok": False, "error": "missing address"}
    if not func:
        return {"ok": False, "error": "no function at address", "address": _hex(ea)}
    sample_limit = max(1, min(int(sample_limit or 12), 32))
    callers = []
    caller_starts = set()
    for ref in idautils.CodeRefsTo(func.start_ea, False):
        caller = ida_funcs.get_func(ref)
        if caller and int(caller.start_ea) != int(func.start_ea):
            caller_starts.add(int(caller.start_ea))
    callers = [_function_summary(value) for value in sorted(caller_starts)]
    callee_starts = set()
    strings = {}
    globals_used = {}
    imports_by_address = {
        int(row["address"], 0): row for row in _all_import_rows() if row.get("address")
    }
    imports_used = {}
    heads = list(idautils.FuncItems(func.start_ea))
    for head in heads:
        for target in idautils.CodeRefsFrom(head, False):
            callee = ida_funcs.get_func(target)
            if callee and int(callee.start_ea) != int(func.start_ea):
                callee_starts.add(int(callee.start_ea))
            if int(target) in imports_by_address:
                imports_used[int(target)] = imports_by_address[int(target)]
        for target in idautils.DataRefsFrom(head):
            if int(target) in imports_by_address:
                imports_used[int(target)] = imports_by_address[int(target)]
                continue
            text = _string_at(target)
            if text:
                strings[int(target)] = {"address": _hex(target), "text": text}
            elif _safe_name(target):
                globals_used[int(target)] = {
                    "address": _hex(target),
                    "name": _safe_name(target),
                    "type": _safe_type(target),
                }
    callees = [_function_summary(value) for value in sorted(callee_starts)]
    block_count = None
    edge_count = None
    try:
        blocks = list(idaapi.FlowChart(func)) if idaapi is not None else []
        block_count = len(blocks)
        edge_count = sum(len(list(block.succs())) for block in blocks)
    except Exception:
        pass
    return {
        "ok": True,
        "address": _hex(func.start_ea),
        "function": _function_bounds(func),
        "identity": _function_summary(func.start_ea),
        "relationships": {
            "caller_count": len(callers),
            "callee_count": len(callees),
            "sample_callers": callers[:sample_limit],
            "sample_callees": callees[:sample_limit],
        },
        "references": {
            "string_count": len(strings),
            "global_count": len(globals_used),
            "import_count": len(imports_used),
            "sample_strings": list(strings.values())[:sample_limit],
            "sample_globals": list(globals_used.values())[:sample_limit],
            "sample_imports": list(imports_used.values())[:sample_limit],
        },
        "cfg": {"basic_block_count": block_count, "edge_count": edge_count},
        "code": {
            "disassembly": {"available": True, "line_count": len(heads)},
            "pseudocode": {
                "available": bool(ida_hexrays is not None),
                "line_count": None,
                "scan": "not_run",
            },
        },
    }


def list_functions(prefix=None, limit=120, offset=0):
    limit = max(1, min(int(limit or 120), 1000))
    offset = max(0, int(offset or 0))
    prefix_text = str(prefix or "")
    rows = []
    for ea in getattr(idautils, "Functions", lambda: [])():
        summary = _function_summary(ea)
        if not summary:
            continue
        if prefix_text and not str(summary.get("name") or "").startswith(prefix_text):
            continue
        if offset:
            offset -= 1
            continue
        rows.append(summary)
        if len(rows) >= limit:
            break
    return {"ok": True, "functions": rows, "count": len(rows), "prefix": prefix_text or None}


def inspect_addr(address, size=32, limit=80):
    ea = _parse_int(address)
    if ea is None:
        return {"ok": False, "error": "missing address"}
    byte_count = max(1, min(int(size or 32), 256))
    data = ida_bytes.get_bytes(ea, byte_count) or b""
    return {
        "ok": True,
        "address": _hex(ea),
        "name": _safe_name(ea),
        "type": _safe_type(ea),
        "comments": {
            "nonrepeatable": _safe_comment(ea, False),
            "repeatable": _safe_comment(ea, True),
        },
        "segment": _segment(ea),
        "file_offset": _file_offset(ea),
        "function": _func_at(ea),
        "item_size": int(getattr(ida_bytes, "get_item_size", lambda _ea: 0)(ea) or 0),
        "bytes": data.hex(),
        "disassembly": _safe_disassembly(ea),
        "xrefs": query_xrefs(ea, limit),
    }


def _entry_rows(include_primary=False, limit=120):
    bounded_limit = None if limit is None else max(1, min(int(limit or 120), 100000))
    rows = []
    seen = set()
    if include_primary:
        try:
            import ida_ida

            start_ea = ida_ida.inf_get_start_ea()
        except Exception:
            start_ea = None
        if start_ea is not None and start_ea != idc.BADADDR:
            func = ida_funcs.get_func(start_ea)
            ea = func.start_ea if func else start_ea
            rows.append({
                "address": _hex(ea),
                "name": idc.get_func_name(ea) or _safe_name(ea) or "entry",
                "type": "entry_point",
                "ordinal": None,
                "function": _func_at(ea),
            })
            seen.add(ea)
    entries = list(getattr(idautils, "Entries", lambda: [])())
    for entry in entries if bounded_limit is None else entries[:bounded_limit]:
        try:
            _index, ordinal, ea, name = entry
        except Exception:
            continue
        if ea in seen:
            continue
        rows.append({
            "address": _hex(ea),
            "name": name or idc.get_func_name(ea) or _safe_name(ea),
            "type": "export",
            "ordinal": int(ordinal or 0),
            "function": _func_at(ea),
        })
        seen.add(ea)
        if bounded_limit is not None and len(rows) >= bounded_limit:
            break
    return rows


def list_entrypoints(limit=120):
    rows = _entry_rows(include_primary=True, limit=limit)
    return {"ok": True, "entry_points": rows, "count": len(rows)}


def list_exports(limit=120):
    rows = _entry_rows(include_primary=False, limit=limit)
    return {"ok": True, "exports": rows, "count": len(rows)}


def _all_global_rows(prefix=None):
    prefix_text = str(prefix or "")
    rows = []
    for ea, name in getattr(idautils, "Names", lambda: [])():
        if ida_funcs.get_func(ea) is not None:
            continue
        if prefix_text and not str(name).startswith(prefix_text):
            continue
        flags = getattr(ida_bytes, "get_flags", lambda _ea: 0)(ea)
        is_data = False
        try:
            is_data = bool(getattr(ida_bytes, "is_data", lambda _flags: False)(flags))
        except Exception:
            is_data = False
        refs_to = list(idautils.DataRefsTo(ea))
        rows.append({
            "address": _hex(ea),
            "name": str(name),
            "type": _safe_type(ea),
            "segment": _segment_name(ea),
            "size": int(getattr(ida_bytes, "get_item_size", lambda _ea: 0)(ea) or 0),
            "is_data": is_data,
            "comments": {
                "nonrepeatable": _safe_comment(ea, False),
                "repeatable": _safe_comment(ea, True),
            },
            "refs_to_count": len(refs_to),
            "sample_refs_to": [{"from": _hex(ref), "function": _func_at(ref)} for ref in refs_to[:8]],
        })
    return rows


def list_globals(prefix=None, limit=160):
    limit = max(1, min(int(limit or 160), 1000))
    prefix_text = str(prefix or "")
    rows = _all_global_rows(prefix=prefix_text)[:limit]
    return {"ok": True, "globals": rows, "count": len(rows), "prefix": prefix_text or None}


def _local_type_inventory(prefix=None, limit=160):
    prefix_text = str(prefix or "")
    try:
        from verified_ida_annotations_export_ida import export_local_named_types

        local_types = export_local_named_types()
    except Exception as exc:
        return {"available": False, "error": str(exc), "items": []}
    items = []
    bounded_limit = None if limit is None else max(1, min(int(limit or 160), 100000))
    for kind in ("structs", "enums"):
        for item in local_types.get(kind) or []:
            name = str(item.get("name") or "")
            if prefix_text and not name.startswith(prefix_text):
                continue
            row = dict(item)
            row["kind"] = "struct" if kind == "structs" else "enum"
            items.append(row)
            if bounded_limit is not None and len(items) >= bounded_limit:
                return {
                    "available": bool(local_types.get("available")),
                    "items": items,
                    "scan_complete": False,
                }
    return {
        "available": bool(local_types.get("available")),
        "items": items,
        "scan_complete": True,
    }


def list_local_types(prefix=None, limit=160):
    inventory = _local_type_inventory(prefix=prefix, limit=limit)
    return {
        "ok": bool(inventory.get("available", False)) or not inventory.get("error"),
        "available": bool(inventory.get("available", False)),
        "error": inventory.get("error"),
        "local_types": inventory.get("items") or [],
        "count": len(inventory.get("items") or []),
        "prefix": str(prefix or "") or None,
    }


def inspect_struct(name, limit=160):
    target = str(name or "").strip()
    if not target:
        return {"ok": False, "error": "missing struct/type name"}
    inventory = _local_type_inventory(limit=limit)
    target_lower = target.lower()
    matches = [
        item for item in inventory.get("items") or []
        if str(item.get("name") or "").lower() == target_lower
    ]
    if not matches:
        matches = [
            item for item in inventory.get("items") or []
            if target_lower in str(item.get("name") or "").lower()
        ][:8]
    return {
        "ok": bool(matches),
        "query": target,
        "struct": matches[0] if len(matches) == 1 else None,
        "matches": matches,
        "count": len(matches),
        "error": None if matches else "struct/type not found",
    }


def read_struct(name, limit=160):
    result = inspect_struct(name, limit)
    if not result.get("ok"):
        return result
    item = result.get("struct") or ((result.get("matches") or [None])[0])
    members = item.get("members") or [] if isinstance(item, dict) else []
    declaration_lines = ["struct %s {" % (item.get("name") if isinstance(item, dict) else name)]
    for member in members[:max(1, min(int(limit or 160), 1000))]:
        declaration_lines.append("  /* %s */ %s %s;" % (
            member.get("offset"),
            member.get("type") or "unsigned char",
            member.get("name") or ("field_%s" % str(member.get("offset") or "unknown").replace("0x", "")),
        ))
    declaration_lines.append("};")
    out = dict(result)
    out["declaration"] = "\n".join(declaration_lines)
    return out


def xrefs_to_field(name, offset=None, limit=120):
    target = str(name or "").strip()
    offset_value = _parse_int(offset)
    if offset_value is None:
        match = re.search(r"(?:\+|:|@)\s*(0x[0-9a-fA-F]+|[0-9]+)", target)
        if match:
            offset_value = _parse_int(match.group(1))
    if offset_value is None:
        return {"ok": False, "error": "missing field offset", "target": target}
    patterns = {
        "0x%x" % offset_value,
        "%Xh" % offset_value,
        "%xh" % offset_value,
        "+%Xh" % offset_value,
        "+%xh" % offset_value,
        "+%d" % offset_value,
    }
    hits = []
    for func_ea in getattr(idautils, "Functions", lambda: [])():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
        for head in list(idautils.FuncItems(func.start_ea))[:4000]:
            line = _safe_disassembly(head)
            normalized = line.replace(" ", "")
            if any(pattern in normalized for pattern in patterns):
                hits.append({
                    "address": _hex(head),
                    "function": _function_summary(func.start_ea),
                    "disassembly": line,
                })
                if len(hits) >= max(1, min(int(limit or 120), 1000)):
                    return {"ok": True, "target": target, "offset": _hex(offset_value), "hits": hits, "count": len(hits)}
    return {"ok": True, "target": target, "offset": _hex(offset_value), "hits": hits, "count": len(hits)}


def render_switch_table(address, limit=80):
    ea, func = _function(address)
    if ea is None:
        return {"ok": False, "error": "missing address"}
    heads = list(idautils.FuncItems(func.start_ea)) if func else [ea]
    switches = []
    for head in heads[:2000]:
        switch_info = ida_nalt.get_switch_info(head)
        if not switch_info:
            continue
        switches.append({
            "address": _hex(head),
            "cases": int(getattr(switch_info, "ncases", 0) or 0),
            "jumps": _hex(getattr(switch_info, "jumps", None)),
            "lowcase": int(getattr(switch_info, "lowcase", 0) or 0),
            "flags": int(getattr(switch_info, "flags", 0) or 0),
            "disassembly": _clean_line(idc.generate_disasm_line(head, 0) or ""),
        })
        if len(switches) >= limit:
            break
    return {
        "ok": True,
        "address": _hex(ea),
        "function": _function_bounds(func) if func else None,
        "switches": switches,
        "count": len(switches),
    }


def _vector_values(vector):
    values = []
    try:
        iterator = iter(vector)
    except TypeError:
        return values
    for item in iterator:
        try:
            nested = list(item)
        except TypeError:
            nested = None
        if nested is not None:
            for value in nested:
                try:
                    values.append(int(value))
                except (TypeError, ValueError):
                    pass
            continue
        try:
            values.append(int(item))
        except (TypeError, ValueError):
            pass
    return values


def _switch_values(head, switch_info):
    if idaapi is not None:
        try:
            calculated = idaapi.calc_switch_cases(head, switch_info)
            if isinstance(calculated, tuple) and calculated:
                values = _vector_values(calculated[0])
                if values:
                    return sorted(set(values)), "ida_calc_switch_cases"
        except Exception:
            pass
        try:
            cases = idaapi.casevec_t()
            targets = idaapi.eavec_t()
            if idaapi.calc_switch_cases(head, switch_info, cases, targets):
                values = _vector_values(cases)
                if values:
                    return sorted(set(values)), "ida_calc_switch_cases"
        except Exception:
            pass
    count = int(getattr(switch_info, "ncases", 0) or 0)
    lowcase = int(getattr(switch_info, "lowcase", 0) or 0)
    if 2 <= count <= 256:
        return list(range(lowcase, lowcase + count)), "contiguous_lowcase_fallback"
    return [], "unresolved"


def _candidate_id(kind, function_ea, discriminator, values):
    material = "%s|%s|%s|%s" % (
        kind,
        _hex(function_ea),
        discriminator,
        ",".join(str(value) for value in sorted(set(values))),
    )
    return "%s:%s:%s" % (
        kind,
        _hex(function_ea),
        hashlib.sha256(material.encode("utf-8")).hexdigest()[:12],
    )


def _candidate_function(func):
    return {
        "address": _hex(func.start_ea),
        "end": _hex(func.end_ea),
        "name": ida_name.get_name(func.start_ea) or "",
        "size": int(func.end_ea - func.start_ea),
    }


def _normalize_immediate_for_operand(operand, value):
    text = str(operand or "").lower()
    width = None
    if re.search(r"\b(?:al|ah|bl|bh|cl|ch|dl|dh|sil|dil|spl|bpl|r(?:[89]|1[0-5])b)\b", text):
        width = 8
    elif re.search(r"\b(?:ax|bx|cx|dx|si|di|sp|bp|r(?:[89]|1[0-5])w)\b", text):
        width = 16
    elif re.search(r"\b(?:eax|ebx|ecx|edx|esi|edi|esp|ebp|r(?:[89]|1[0-5])d)\b", text):
        width = 32
    elif re.search(r"\b(?:rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|r(?:[89]|1[0-5]))\b", text):
        width = 64
    elif "byte ptr" in text:
        width = 8
    elif "word ptr" in text and "dword ptr" not in text and "qword ptr" not in text:
        width = 16
    elif "dword ptr" in text:
        width = 32
    elif "qword ptr" in text:
        width = 64
    if width is None or width >= 64:
        return int(value)
    return int(value) & ((1 << width) - 1)


def discover_enum_candidates(limit=120, min_compare_values=3):
    """Find blind enum/flags obligations without assigning semantic labels."""
    candidates = []
    skipped_substrate = 0
    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
        flags = int(getattr(func, "flags", 0) or 0)
        if not flags:
            try:
                flags = int(idc.get_func_attr(func.start_ea, idc.FUNCATTR_FLAGS) or 0)
            except Exception:
                flags = 0
        substrate_mask = int(getattr(ida_funcs, "FUNC_LIB", 0)) | int(getattr(ida_funcs, "FUNC_THUNK", 0))
        if substrate_mask and flags & substrate_mask:
            skipped_substrate += 1
            continue

        compare_groups = {}
        mask_groups = {}
        for head in list(idautils.FuncItems(func.start_ea))[:6000]:
            switch_info = ida_nalt.get_switch_info(head)
            if switch_info:
                values, source = _switch_values(head, switch_info)
                if len(values) >= 2:
                    candidates.append({
                        "candidate_id": _candidate_id("enum", func.start_ea, _hex(head), values),
                        "kind": "enum",
                        "confidence": "high" if source == "ida_calc_switch_cases" else "medium",
                        "function": _candidate_function(func),
                        "selector": {
                            "address": _hex(head),
                            "operand": "",
                            "source": source,
                        },
                        "values": values,
                        "evidence_addresses": [_hex(head)],
                        "required_decision": "enum_or_flags_or_scalar_or_unresolved",
                    })
                    if len(candidates) >= limit:
                        break

            mnemonic = str(idc.print_insn_mnem(head) or "").lower()
            if mnemonic not in {"cmp", "test", "and"}:
                continue
            if idc.get_operand_type(head, 1) != getattr(idc, "o_imm", 5):
                continue
            operand = re.sub(r"\s+", "", str(idc.print_operand(head, 0) or "")).lower()
            if not operand:
                continue
            value = _normalize_immediate_for_operand(
                operand,
                int(idc.get_operand_value(head, 1) or 0),
            )
            if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
                continue
            target = compare_groups if mnemonic == "cmp" else mask_groups
            row = target.setdefault(operand, {"values": set(), "addresses": [], "mnemonics": set()})
            row["values"].add(value)
            row["addresses"].append(_hex(head))
            row["mnemonics"].add(mnemonic)

        if len(candidates) >= limit:
            break
        for operand, row in sorted(compare_groups.items()):
            values = sorted(row["values"])
            if len(values) < max(2, int(min_compare_values or 3)):
                continue
            candidates.append({
                "candidate_id": _candidate_id("enum", func.start_ea, operand, values),
                "kind": "enum",
                "confidence": "medium",
                "function": _candidate_function(func),
                "selector": {
                    "address": row["addresses"][0],
                    "operand": operand,
                    "source": "repeated_immediate_comparisons",
                },
                "values": values,
                "evidence_addresses": row["addresses"][:24],
                "required_decision": "enum_or_flags_or_scalar_or_unresolved",
            })
            if len(candidates) >= limit:
                break
        if len(candidates) >= limit:
            break
        for operand, row in sorted(mask_groups.items()):
            values = sorted(value for value in row["values"] if value)
            if len(values) < 2:
                continue
            candidates.append({
                "candidate_id": _candidate_id("flags", func.start_ea, operand, values),
                "kind": "flags",
                "confidence": "medium",
                "function": _candidate_function(func),
                "selector": {
                    "address": row["addresses"][0],
                    "operand": operand,
                    "source": "repeated_immediate_masks",
                },
                "values": values,
                "evidence_addresses": row["addresses"][:24],
                "required_decision": "enum_or_flags_or_scalar_or_unresolved",
            })
            if len(candidates) >= limit:
                break
        if len(candidates) >= limit:
            break

    confidence_counts = {}
    kind_counts = {}
    for row in candidates:
        confidence_counts[row["confidence"]] = confidence_counts.get(row["confidence"], 0) + 1
        kind_counts[row["kind"]] = kind_counts.get(row["kind"], 0) + 1
    return {
        "ok": True,
        "candidate_count": len(candidates),
        "high_confidence_count": confidence_counts.get("high", 0),
        "confidence_counts": confidence_counts,
        "kind_counts": kind_counts,
        "skipped_ida_library_or_thunk_functions": skipped_substrate,
        "candidates": candidates,
    }


def _pointer_table_owner(ref, window=0x40):
    for delta in range(0, max(0, int(window or 0)) + 1):
        ea = ref - delta
        name = _safe_name(ea)
        comment = _safe_comment(ea) or _safe_comment(ea, repeatable=True)
        if not name and not comment:
            continue
        return {
            "address": _hex(ea),
            "offset": ea - ref,
            "name": name,
            "comment": comment,
            "segment": _segment(ea),
            "disassembly": _safe_disassembly(ea),
        }
    return None


def _pointer_table_row(ea, center):
    value = _safe_dword(ea)
    pointed_function = _func_at(value) if value is not None else None
    pointed_name = ""
    if pointed_function:
        pointed_name = pointed_function.get("name") or ""
    elif value is not None:
        pointed_name = _safe_name(value)
    return {
        "address": _hex(ea),
        "offset": ea - center,
        "value": _hex(value),
        "segment": _segment(ea),
        "name": _safe_name(ea),
        "comment": _safe_comment(ea),
        "repeatable_comment": _safe_comment(ea, repeatable=True),
        "points_to_function": pointed_function,
        "points_to_name": pointed_name,
        "disassembly": _safe_disassembly(ea),
    }


def render_pointer_table_neighborhood(ref, radius=0x10, entry_size=4):
    try:
        ref = int(ref)
    except Exception:
        return None
    entry_size = max(1, int(entry_size or 4))
    radius = max(0, int(radius or 0))
    rows = []
    for offset in range(-radius, radius + entry_size, entry_size):
        ea = ref + offset
        if ea < 0:
            continue
        rows.append(_pointer_table_row(ea, ref))
    return {
        "center": _hex(ref),
        "entry_size": entry_size,
        "radius": radius,
        "nearest_named_owner": _pointer_table_owner(ref),
        "rows": rows,
    }


def render_function_pointer_refs(address, limit=120):
    ea = _parse_int(address)
    if ea is None:
        return {"ok": False, "error": "missing address"}
    refs = []
    for frm in list(idautils.DataRefsTo(ea))[:limit]:
        refs.append({
            "address": _hex(frm),
            "segment": _segment(frm),
            "name": ida_name.get_name(frm) or "",
            "function": _func_at(frm),
            "disassembly": _clean_line(idc.generate_disasm_line(frm, 0) or ""),
            "pointer_table_neighborhood": render_pointer_table_neighborhood(frm),
        })
    return {
        "ok": True,
        "address": _hex(ea),
        "function": _func_at(ea),
        "refs": refs,
        "count": len(refs),
    }


def expand_call_graph(address, depth=1, direction="both", limit=120):
    ea, func = _function(address)
    if ea is None:
        return {"ok": False, "error": "missing address"}
    if not func:
        return {"ok": False, "error": "no function at address", "address": _hex(ea)}
    depth = max(0, min(int(depth or 1), 4))
    limit = max(1, min(int(limit or 120), 1000))
    direction = str(direction or "both").lower()
    if direction not in {"both", "callers", "callees"}:
        direction = "both"
    nodes = {}
    edges = []
    queue = deque([(func.start_ea, 0)])
    nodes[func.start_ea] = _func_at(func.start_ea)
    seen_edges = set()
    while queue and len(nodes) < limit:
        current, level = queue.popleft()
        current_func = ida_funcs.get_func(current)
        if not current_func or level >= depth:
            continue
        if direction in {"both", "callers"}:
            for ref in list(idautils.CodeRefsTo(current_func.start_ea, 0))[:limit]:
                caller = ida_funcs.get_func(ref)
                if not caller:
                    continue
                if int(caller.start_ea) == int(current_func.start_ea):
                    continue
                edge_key = (caller.start_ea, current_func.start_ea, ref)
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    edges.append({"from": _hex(caller.start_ea), "to": _hex(current_func.start_ea), "site": _hex(ref), "direction": "caller"})
                if caller.start_ea not in nodes and len(nodes) < limit:
                    nodes[caller.start_ea] = _func_at(caller.start_ea)
                    queue.append((caller.start_ea, level + 1))
        if direction in {"both", "callees"}:
            for head in idautils.FuncItems(current_func.start_ea):
                for target in idautils.CodeRefsFrom(head, 0):
                    callee = ida_funcs.get_func(target)
                    if not callee:
                        continue
                    if int(callee.start_ea) == int(current_func.start_ea):
                        continue
                    edge_key = (current_func.start_ea, callee.start_ea, head)
                    if edge_key not in seen_edges:
                        seen_edges.add(edge_key)
                        edges.append({"from": _hex(current_func.start_ea), "to": _hex(callee.start_ea), "site": _hex(head), "direction": "callee"})
                    if callee.start_ea not in nodes and len(nodes) < limit:
                        nodes[callee.start_ea] = _func_at(callee.start_ea)
                        queue.append((callee.start_ea, level + 1))
                    if len(nodes) >= limit or len(edges) >= limit * 3:
                        break
                if len(nodes) >= limit or len(edges) >= limit * 3:
                    break
    return {
        "ok": True,
        "address": _hex(ea),
        "root": _function_bounds(func),
        "depth": depth,
        "direction": direction,
        "nodes": [value for _, value in sorted(nodes.items())],
        "edges": edges[:limit * 3],
        "node_count": len(nodes),
        "edge_count": min(len(edges), limit * 3),
    }


def render_stack_frame(address, limit=120, include_decompiler=True):
    ea, func = _function(address)
    if ea is None:
        return {"ok": False, "error": "missing address"}
    if not func:
        return {"ok": False, "error": "no function at address", "address": _hex(ea)}
    ctree_summary = (
        summarize_ctree(func.start_ea, limit=limit)
        if include_decompiler
        else {
            "ok": False,
            "error": "decompiler evidence requires an explicit gated request",
            "local_variables": [],
        }
    )
    members = []
    frame_id = idc.get_frame_id(func.start_ea)
    if frame_id is not None and frame_id != idc.BADADDR:
        member_qty = idc.get_member_qty(frame_id) if hasattr(idc, "get_member_qty") else 0
        member_count = min(member_qty or 0, limit)
        for index in range(member_count):
            member_name = idc.get_member_name(frame_id, index) or ""
            member_size = idc.get_member_size(frame_id, index)
            members.append({"index": index, "name": member_name, "size": member_size})
    return {
        "ok": True,
        "address": _hex(ea),
        "function": _function_bounds(func),
        "frame_id": _hex(frame_id),
        "members": members,
        "local_variables": (ctree_summary.get("local_variables") or [])[:limit],
        "ctree_ok": ctree_summary.get("ok"),
        "ctree_error": ctree_summary.get("error"),
        "count": len(members),
        "local_count": len(ctree_summary.get("local_variables") or []),
    }


def _expr_text(expr):
    try:
        import ida_hexrays  # noqa: F401
        return _clean_line(expr.print1(None))
    except Exception:
        return ""


def _ctype_name(op):
    try:
        import ida_hexrays
        name = ida_hexrays.get_ctype_name(op)
        if name:
            return str(name)
        for key, value in ida_hexrays.__dict__.items():
            if key.startswith("cot_") and value == op:
                return key
    except Exception:
        pass
    return str(op)


def _is_ctree_call(expr):
    try:
        import ida_hexrays
        cot_call = getattr(ida_hexrays, "cot_call", None)
        if cot_call is not None and expr.op == cot_call:
            return True
    except Exception:
        pass
    return _ctype_name(getattr(expr, "op", None)) in {"cot_call", "call"}


def _call_args(expr, limit=16):
    args = []
    try:
        for arg in list(expr.a)[:limit]:
            args.append(_expr_text(arg))
    except Exception:
        pass
    return args


def _callee_text(expr):
    try:
        text = _expr_text(expr.x)
        if text:
            return text
    except Exception:
        pass
    try:
        obj_ea = int(expr.x.obj_ea)
        if obj_ea and obj_ea != idc.BADADDR:
            return idc.get_func_name(obj_ea) or _hex(obj_ea) or ""
    except Exception:
        pass
    return ""


def query_callsite_arguments(address, limit=24):
    """Return Hex-Rays call arguments for a specific callsite.

    This is intentionally best-effort. Huge FORTRAN-like functions often have
    many calls, so render_function_context can truncate before the callsite of
    interest. This query walks all calls and returns exact or nearby matches.
    """
    ea = _parse_int(address)
    if ea is None:
        return {"ok": False, "error": "missing address"}
    func = ida_funcs.get_func(ea)
    if not func:
        return {"ok": False, "error": "no function at callsite", "address": _hex(ea)}
    window_before = []
    cursor = ea
    for _ in range(16):
        prev = idc.prev_head(cursor, func.start_ea)
        if prev == idc.BADADDR or prev < func.start_ea:
            break
        window_before.append(prev)
        cursor = prev
    window_after = []
    cursor = ea
    for _ in range(10):
        window_after.append(cursor)
        next_head = idc.next_head(cursor, func.end_ea)
        if next_head == idc.BADADDR or next_head >= func.end_ea:
            break
        cursor = next_head
    window_heads = list(reversed(window_before)) + window_after
    result = {
        "ok": False,
        "address": _hex(ea),
        "function": _function_bounds(func),
        "disassembly": _clean_line(idc.generate_disasm_line(ea, 0) or ""),
        "disassembly_window": [
            {
                "address": _hex(head),
                "mnemonic": idc.print_insn_mnem(head) or "",
                "disassembly": _clean_line(idc.generate_disasm_line(head, 0) or ""),
            }
            for head in window_heads
        ],
        "exact_matches": [],
        "nearby_calls": [],
    }
    try:
        import ida_hexrays
    except Exception as exc:
        result["error"] = "Hex-Rays module unavailable: %s" % exc
        return result
    try:
        if not ida_hexrays.init_hexrays_plugin():
            result["error"] = "Hex-Rays plugin is not initialized"
            return result
        cfunc = ida_hexrays.decompile(func.start_ea)
        if not cfunc:
            result["error"] = "Hex-Rays decompile returned no cfunc"
            return result
    except Exception as exc:
        result["error"] = "decompile failed: %s" % exc
        return result

    exact = []
    nearby = []
    limit = max(1, min(int(limit or 24), 200))

    class Visitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)

        def visit_expr(self, expr):
            if not _is_ctree_call(expr):
                return 0
            try:
                call_ea = int(expr.ea)
            except Exception:
                call_ea = None
            record = {
                "ea": _hex(call_ea),
                "callee": _callee_text(expr),
                "args": _call_args(expr, 24),
                "text": _expr_text(expr),
            }
            if call_ea == ea:
                exact.append(record)
            elif call_ea is not None and abs(call_ea - ea) <= 16 and len(nearby) < limit:
                nearby.append(record)
            return 0

    try:
        Visitor().apply_to(cfunc.body, None)
        result["exact_matches"] = exact[:limit]
        result["nearby_calls"] = nearby[:limit]
        result["ok"] = True
        if not exact:
            result["note"] = "no exact Hex-Rays call expression at this address; use disassembly/nearby_calls"
    except Exception as exc:
        result["error"] = "ctree visit failed: %s" % exc
    return result


def query_hook_entry_contract(address, limit=80):
    """Summarize entry/prologue state for a hook target function."""
    ea, func = _function(address)
    if ea is None:
        return {"ok": False, "error": "missing address"}
    if not func:
        return {"ok": False, "error": "no function at address", "address": _hex(ea)}
    stack = render_stack_frame(func.start_ea, limit)
    disasm = retrieve_disassembly(func.start_ea, min(limit or 80, 80))
    args = []
    for local in stack.get("local_variables") or []:
        if not local.get("is_arg"):
            continue
        args.append({
            "index": local.get("index"),
            "name": local.get("name"),
            "type": local.get("type"),
            "location": local.get("location"),
            "use_count": local.get("use_count"),
            "assignment_count": local.get("assignment_count"),
            "use_sites": local.get("use_sites"),
        })
    return {
        "ok": True,
        "address": _hex(ea),
        "function": _function_bounds(func),
        "entry_disassembly": (disasm.get("lines") or [])[:24],
        "arguments": args[:limit],
        "argument_count": len(args),
        "ctree_ok": stack.get("ctree_ok"),
        "ctree_error": stack.get("ctree_error"),
    }


def render_function_context(address, limit=120):
    ea, func = _function(address)
    if ea is None:
        return {"ok": False, "error": "missing address"}
    if not func:
        return {"ok": False, "error": "no function at address", "address": _hex(ea)}
    pseudocode = retrieve_pseudocode(func.start_ea, limit)
    disassembly = retrieve_disassembly(func.start_ea, limit)
    callers_callees = query_callers_callees(func.start_ea, limit)
    strings = render_strings(func.start_ea, min(limit or 80, 80))
    ctree_summary = summarize_ctree(func.start_ea, limit=min(limit or 80, 120))
    return {
        "ok": bool(disassembly.get("ok") or pseudocode.get("ok")),
        "address": _hex(ea),
        "function": _function_bounds(func),
        "pseudocode": pseudocode,
        "disassembly": disassembly,
        "callers_callees": callers_callees,
        "strings": strings,
        "ida_native_summary": ctree_summary,
    }


def render_function_context_low_level(address, limit=120):
    """Render function evidence without initializing or invoking Hex-Rays."""
    ea, func = _function(address)
    if ea is None:
        return {"ok": False, "error": "missing address"}
    if not func:
        return {"ok": False, "error": "no function at address", "address": _hex(ea)}
    disassembly = retrieve_disassembly(func.start_ea, limit)
    return {
        "ok": bool(disassembly.get("ok")),
        "address": _hex(ea),
        "function": _function_bounds(func),
        "disassembly": disassembly,
        "cfg": render_cfg(func.start_ea, min(limit or 120, 120)),
        "callers_callees": query_callers_callees(func.start_ea, limit),
        "strings": render_strings(func.start_ea, min(limit or 80, 80)),
    }


def inspect_function_identity(address):
    ea, func = _function(address)
    if ea is None:
        return {"ok": False, "error": "missing address"}
    if not func:
        return {"ok": False, "error": "no function at address", "address": _hex(ea)}
    return {
        "ok": True,
        "address": _hex(func.start_ea),
        "function": _function_bounds(func),
    }


def render_pe_inventory(
    limit=80,
    *,
    target=None,
    size=None,
    input_file_path=None,
):
    if target not in (None, ""):
        ea = _parse_int(target)
        requested_size = _parse_int(size)
        if ea is None:
            return {
                "ok": False,
                "code": "invalid_embedded_pe_address",
                "error": "embedded PE inventory requires a valid IDB address",
            }
        if requested_size is None or requested_size <= 0:
            return {
                "ok": False,
                "code": "embedded_pe_size_required",
                "error": "embedded PE inventory requires the byte size",
                "recovery": "Resubmit inspect_pe_inventory with target and options.size.",
            }
        if requested_size > 67108864:
            return {
                "ok": False,
                "code": "embedded_pe_size_exceeds_limit",
                "error": "embedded PE inventory is limited to 67108864 bytes",
            }
        data = ida_bytes.get_bytes(ea, requested_size)
        if data is None or len(data) != requested_size:
            return {
                "ok": False,
                "code": "embedded_pe_bytes_unavailable",
                "error": "IDA could not read the complete requested byte range",
                "address": _hex(ea),
                "requested_size": requested_size,
                "returned_size": len(data or b""),
            }
        inventory = build_pe_inventory_bytes(
            bytes(data),
            source="idb:%s+%s" % (_hex(ea), hex(requested_size)),
        )
        source = {
            "kind": "idb_bytes",
            "address": _hex(ea),
            "size": requested_size,
        }
    else:
        path = _registered_input_path(input_file_path)
        if not path:
            return {
                "ok": False,
                "code": "registered_input_unavailable",
                "error": "the host-registered component binary is unavailable",
                "historical_ida_input_path": idc.get_input_file_path(),
                "recovery": "Repair the component binary binding before retrying this query.",
            }
        inventory = build_pe_inventory(path)
        source = {"kind": "registered_component_binary", "path": path}
    if inventory.get("resources", {}).get("items"):
        inventory["resources"]["items"] = inventory["resources"]["items"][:limit]
    if inventory.get("imports"):
        inventory["imports"] = inventory["imports"][:limit]
    return {"ok": True, "inventory_source": source, **inventory}


def render_segments(limit=120):
    limit = max(1, min(int(limit or 120), 1000))
    items = []
    for index in range(min(ida_segment.get_segm_qty(), limit)):
        seg = ida_segment.getnseg(index)
        if not seg:
            continue
        start_off = _file_offset(seg.start_ea)
        end_off = _file_offset(seg.end_ea - 1) if seg.end_ea > seg.start_ea else None
        items.append({
            "index": index,
            "name": idc.get_segm_name(seg.start_ea),
            "start": _hex(seg.start_ea),
            "end": _hex(seg.end_ea),
            "size": int(seg.end_ea - seg.start_ea),
            "perm": int(seg.perm),
            "perm_text": _perm_text(int(seg.perm)),
            "type": int(seg.type),
            "file_offset_start": _hex(start_off),
            "file_offset_end": _hex(end_off),
        })
    return {"ok": True, "segments": items, "count": len(items)}


def render_names_types(address=None, prefix=None, limit=160):
    limit = max(1, min(int(limit or 160), 1000))
    ea, func = _function(address) if address else (None, None)
    prefix_text = str(prefix or "")
    items = []
    try:
        names = list(idautils.Names())
    except Exception:
        names = []
    for name_ea, name in names:
        if func and not (func.start_ea <= name_ea < func.end_ea):
            continue
        if prefix_text and not str(name).startswith(prefix_text):
            continue
        item = {
            "address": _hex(name_ea),
            "name": str(name),
            "segment": _segment_name(name_ea),
            "function": _func_at(name_ea),
            "type": idc.get_type(name_ea) or "",
            "is_code": bool(ida_bytes.is_code(ida_bytes.get_flags(name_ea))),
            "is_data": bool(ida_bytes.is_data(ida_bytes.get_flags(name_ea))),
        }
        items.append(item)
        if len(items) >= limit:
            break
    return {
        "ok": True,
        "address": _hex(ea) if ea is not None else None,
        "function": _function_bounds(func) if func else None,
        "prefix": prefix_text or None,
        "names": items,
        "count": len(items),
    }


def _parse_hex_pattern(pattern):
    if pattern is None:
        return None
    if isinstance(pattern, bytes):
        return pattern
    text = str(pattern).strip()
    if not text:
        return None
    text = text.replace("\\x", " ")
    text = re.sub(r"[^0-9a-fA-F]", "", text)
    if len(text) % 2:
        return None
    try:
        return bytes.fromhex(text)
    except ValueError:
        return None


def search_bytes(pattern, limit=80, max_scan_bytes=16777216):
    needle = _parse_hex_pattern(pattern)
    if not needle:
        return {"ok": False, "error": "missing or invalid hex byte pattern"}
    limit = max(1, min(int(limit or 80), 1000))
    max_scan_bytes = max(1, min(int(max_scan_bytes or 16777216), 67108864))
    hits = []
    scanned = 0
    for index in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(index)
        if not seg:
            continue
        seg_size = int(seg.end_ea - seg.start_ea)
        remaining = max_scan_bytes - scanned
        if remaining <= 0:
            break
        read_size = min(seg_size, remaining)
        data = ida_bytes.get_bytes(seg.start_ea, read_size) or b""
        scanned += len(data)
        pos = data.find(needle)
        while pos >= 0:
            ea = seg.start_ea + pos
            context_start = max(0, pos - 16)
            context_end = min(len(data), pos + len(needle) + 16)
            hits.append({
                "address": _hex(ea),
                "file_offset": _hex(_file_offset(ea)),
                "segment": _segment(ea),
                "context_hex": data[context_start:context_end].hex(),
                "function": _func_at(ea),
            })
            if len(hits) >= limit:
                break
            pos = data.find(needle, pos + 1)
        if len(hits) >= limit:
            break
    return {
        "ok": True,
        "pattern_hex": needle.hex(),
        "pattern_size": len(needle),
        "scanned_bytes": scanned,
        "hits": hits,
        "count": len(hits),
    }


def extract_resource_or_overlay(
    target=None,
    index=None,
    size=4096,
    *,
    input_file_path=None,
):
    path = _registered_input_path(input_file_path)
    if not path:
        return {
            "ok": False,
            "code": "registered_input_unavailable",
            "error": "the host-registered component binary is unavailable",
            "historical_ida_input_path": idc.get_input_file_path(),
        }
    inventory = build_pe_inventory(path)
    size = max(1, min(int(size or 4096), 1048576))
    target_text = str(target or "").lower()
    if target_text in {"overlay", "pe:overlay"}:
        overlay = inventory.get("overlay") or {}
        if not overlay.get("present"):
            return {
                "ok": False,
                "code": "overlay_not_present",
                "error": "overlay not present",
                "target": target,
            }
        file_offset = _parse_int(overlay.get("file_offset"))
        total_size = int(overlay.get("size") or 0)
        data = _bounded_file_read(
            file_offset or 0,
            min(size, total_size),
            input_file_path=path,
        )
        hashed_size = min(total_size, 67108864)
        return {
            "ok": True,
            "kind": "overlay",
            "file_offset": _hex(file_offset),
            "size": total_size,
            "returned_size": len(data),
            "truncated": total_size > len(data),
            "sha256": (
                _bounded_file_sha256(
                    file_offset or 0,
                    total_size,
                    input_file_path=path,
                )
                if total_size else None
            ),
            "sha256_truncated": total_size > hashed_size,
            "hashed_size": hashed_size,
            "magic": _magic(data),
            "hex_prefix": data[:256].hex(),
            "ascii_preview": "".join(chr(b) if 32 <= b < 127 else "." for b in data[:240]),
        }
    resources = ((inventory.get("resources") or {}).get("items") or [])
    selected = None
    if index is not None:
        try:
            selected = resources[int(index)]
        except Exception:
            selected = None
    elif target_text.startswith("resource:"):
        try:
            selected = resources[int(target_text.split(":", 1)[1])]
        except Exception:
            selected = None
    elif target_text:
        for item in resources:
            if target_text in "/".join(str(part).lower() for part in item.get("path") or []):
                selected = item
                break
    if not selected:
        return {
            "ok": False,
            "error": "resource not found",
            "target": target,
            "resource_count": len(resources),
            "available": [
                {"index": idx, "path": item.get("path"), "type": item.get("type"), "size": item.get("size")}
                for idx, item in enumerate(resources[:40])
            ],
        }
    file_offset = _parse_int(selected.get("file_offset"))
    total_size = int(selected.get("size") or 0)
    data = _bounded_file_read(
        file_offset or 0,
        min(size, total_size),
        input_file_path=path,
    )
    hashed_size = min(total_size, 67108864)
    return {
        "ok": True,
        "kind": "resource",
        "resource": selected,
        "file_offset": _hex(file_offset),
        "size": total_size,
        "returned_size": len(data),
        "truncated": total_size > len(data),
        "sha256": (
            _bounded_file_sha256(
                file_offset or 0,
                total_size,
                input_file_path=path,
            )
            if total_size else None
        ),
        "sha256_truncated": total_size > hashed_size,
        "hashed_size": hashed_size,
        "magic": _magic(data),
        "hex_prefix": data[:256].hex(),
        "ascii_preview": "".join(chr(b) if 32 <= b < 127 else "." for b in data[:240]),
    }


def search_constant(value, limit=120):
    needle = _parse_int(value)
    if needle is None:
        return {"ok": False, "error": "missing value"}
    hits = []
    for func_ea in idautils.Functions():
        for head in idautils.FuncItems(func_ea):
            for op_index in range(6):
                try:
                    if idc.get_operand_value(head, op_index) != needle:
                        continue
                except Exception:
                    continue
                hits.append({
                    "address": _hex(head),
                    "function": _func_at(head),
                    "operand": op_index,
                    "disassembly": idc.generate_disasm_line(head, 0) or "",
                })
                break
            if len(hits) >= limit:
                break
        if len(hits) >= limit:
            break
    return {"ok": True, "value": _hex(needle), "hits": hits, "count": len(hits)}


def search_instructions(query=None, limit=120):
    text = str(query or "").strip()
    if not text:
        return {"ok": False, "error": "missing instruction query"}
    needle = text.lower()
    hits = []
    row_limit = max(1, min(int(limit or 120), 1000))
    for func_ea in getattr(idautils, "Functions", lambda: [])():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
        for head in list(idautils.FuncItems(func.start_ea))[:4000]:
            line = _safe_disassembly(head)
            try:
                mnemonic = idc.print_insn_mnem(head) or ""
            except Exception:
                mnemonic = ""
            if needle in line.lower() or needle == mnemonic.lower():
                hits.append({
                    "address": _hex(head),
                    "function": _function_summary(func.start_ea),
                    "mnemonic": mnemonic,
                    "disassembly": line,
                })
                if len(hits) >= row_limit:
                    return {"ok": True, "query": text, "hits": hits, "count": len(hits)}
    return {"ok": True, "query": text, "hits": hits, "count": len(hits)}


def convert_int(value):
    parsed = _parse_int(value)
    if parsed is None:
        return {"ok": False, "error": "missing or invalid integer", "value": value}
    unsigned = parsed & 0xFFFFFFFFFFFFFFFF
    signed32 = parsed & 0xFFFFFFFF
    if signed32 & 0x80000000:
        signed32 -= 0x100000000
    signed64 = unsigned
    if signed64 & 0x8000000000000000:
        signed64 -= 0x10000000000000000
    width = 8 if parsed > 0xFFFFFFFF or parsed < -0x80000000 else 4
    mask = (1 << (width * 8)) - 1
    little = int(unsigned & mask).to_bytes(width, "little", signed=False)
    big = int(unsigned & mask).to_bytes(width, "big", signed=False)
    return {
        "ok": True,
        "input": value,
        "decimal": int(parsed),
        "hex": hex(parsed),
        "unsigned32": parsed & 0xFFFFFFFF,
        "signed32": signed32,
        "unsigned64": unsigned,
        "signed64": signed64,
        "bytes_little_endian": little.hex(),
        "bytes_big_endian": big.hex(),
        "ascii_little_endian": "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in little),
        "low16": hex(parsed & 0xFFFF),
        "low8": hex(parsed & 0xFF),
    }


def find_paths(source, target, direction="callees", depth=3, limit=40):
    src = _parse_int(source)
    dst = _parse_int(target)
    if src is None or dst is None:
        return {"ok": False, "error": "missing source or target"}
    src_func = ida_funcs.get_func(src)
    dst_func = ida_funcs.get_func(dst)
    if not src_func or not dst_func:
        return {"ok": False, "error": "source or target is not in a function", "source": _hex(src), "target": _hex(dst)}
    src_start = src_func.start_ea
    dst_start = dst_func.start_ea
    max_depth = max(1, min(int(depth or 3), 6))
    max_paths = max(1, min(int(limit or 40), 200))
    mode = str(direction or "callees").lower()
    queue = deque([(src_start, [src_start])])
    seen = {(src_start, 0)}
    paths = []
    while queue and len(paths) < max_paths:
        current, path = queue.popleft()
        if len(path) - 1 >= max_depth:
            continue
        func = ida_funcs.get_func(current)
        if not func:
            continue
        neighbors = []
        if mode in {"callees", "both"}:
            for head in list(idautils.FuncItems(func.start_ea))[:4000]:
                for callee in idautils.CodeRefsFrom(head, 0):
                    callee_func = ida_funcs.get_func(callee)
                    if callee_func:
                        neighbors.append(callee_func.start_ea)
        if mode in {"callers", "both"}:
            for ref in idautils.CodeRefsTo(func.start_ea, 0):
                caller_func = ida_funcs.get_func(ref)
                if caller_func:
                    neighbors.append(caller_func.start_ea)
        for neighbor in sorted(set(neighbors)):
            next_path = path + [neighbor]
            if neighbor == dst_start:
                paths.append([_function_summary(item) for item in next_path])
                if len(paths) >= max_paths:
                    break
            state = (neighbor, len(next_path))
            if state not in seen:
                seen.add(state)
                queue.append((neighbor, next_path))
    return {
        "ok": True,
        "source": _hex(src_start),
        "target": _hex(dst_start),
        "direction": mode,
        "max_depth": max_depth,
        "paths": paths,
        "count": len(paths),
    }


def run_readonly_report(report, target=None, limit=120, offset=None):
    report_name = str(report or "").strip()
    if not report_name:
        return {"ok": False, "error": "missing report name"}
    if report_name == "vtable_family_scan":
        if target:
            ea = _parse_int(target)
            if ea is None:
                return {"ok": False, "error": "invalid target", "report": report_name}
            func = ida_funcs.get_func(ea)
            if func:
                return {
                    "ok": True,
                    "report": report_name,
                    "target": _hex(ea),
                    "function_pointer_refs": render_function_pointer_refs(ea, limit),
                }
            return {
                "ok": True,
                "report": report_name,
                "target": _hex(ea),
                "pointer_table_neighborhood": render_pointer_table_neighborhood(ea),
            }
        rows = []
        for ea, name in getattr(idautils, "Names", lambda: [])():
            lowered = str(name).lower()
            if "??_7" not in str(name) and "vftable" not in lowered and "vtbl" not in lowered:
                continue
            rows.append({
                "address": _hex(ea),
                "name": str(name),
                "pointer_table_neighborhood": render_pointer_table_neighborhood(ea),
            })
            if len(rows) >= max(1, min(int(limit or 120), 1000)):
                break
        return {"ok": True, "report": report_name, "rows": rows, "count": len(rows)}
    if report_name == "struct_field_xrefs":
        return {"ok": True, "report": report_name, "field_xrefs": xrefs_to_field(target, offset=offset, limit=limit)}
    if report_name == "data_table_neighborhood_scan":
        ea = _parse_int(target)
        if ea is None:
            return {"ok": False, "error": "missing data/table target", "report": report_name}
        return {"ok": True, "report": report_name, "pointer_table_neighborhood": render_pointer_table_neighborhood(ea)}
    if report_name == "global_owner_scan":
        return {"ok": True, "report": report_name, "global_users": inspect_global_users(target, limit=limit)}
    return {
        "ok": False,
        "error": "unsupported read-only report template",
        "report": report_name,
        "supported_reports": [
            "vtable_family_scan",
            "struct_field_xrefs",
            "data_table_neighborhood_scan",
            "global_owner_scan",
        ],
    }


def infer_struct_context(address, size=256, limit=120, include_decompiler=True):
    ea = _parse_int(address)
    if ea is None:
        return {"ok": False, "error": "missing address"}
    func = ida_funcs.get_func(ea)
    if func:
        return {
            "ok": True,
            "address": _hex(ea),
            "target_kind": "function",
            "function": (
                render_function_context(func.start_ea, limit)
                if include_decompiler
                else render_function_context_low_level(func.start_ea, limit)
            ),
            "stack_frame": render_stack_frame(
                func.start_ea,
                limit,
                include_decompiler=include_decompiler,
            ),
            "data_refs": query_data_refs(func.start_ea),
            "callers_callees": query_callers_callees(func.start_ea, limit),
        }
    return {
        "ok": True,
        "address": _hex(ea),
        "target_kind": "data",
        "data_object": render_data_object(ea, size),
        "xrefs": query_xrefs(ea, limit),
    }


def inspect_call_direction(address, direction, limit=120):
    result = query_callers_callees(address, limit)
    if not result.get("ok"):
        return result
    direction = str(direction or "both").lower()
    if direction == "callers":
        return {
            "ok": True,
            "address": result.get("address"),
            "function": result.get("function"),
            "focus": "callers",
            "callers": result.get("callers") or [],
            "caller_count": result.get("caller_count") or 0,
        }
    if direction == "callees":
        return {
            "ok": True,
            "address": result.get("address"),
            "function": result.get("function"),
            "focus": "callees",
            "callees": result.get("callees") or [],
            "callee_count": result.get("callee_count") or 0,
        }
    return result


def inspect_global_users(address, size=256, limit=120):
    ea = _parse_int(address)
    if ea is None:
        return {"ok": False, "error": "missing address"}
    xrefs = query_xrefs(ea, limit)
    data_refs = query_data_refs(ea, limit)
    users = {}
    for collection in (xrefs.get("refs_to") or [], data_refs.get("refs_to") or []):
        if not isinstance(collection, dict):
            continue
        func = collection.get("function")
        if not isinstance(func, dict) or not func.get("address"):
            continue
        users[func["address"]] = func
    return {
        "ok": True,
        "address": _hex(ea),
        "name": ida_name.get_name(ea) or "",
        "data_object": render_data_object(ea, size),
        "xrefs": xrefs,
        "data_refs": data_refs,
        "function_pointer_refs": render_function_pointer_refs(ea, limit),
        "user_functions": [users[key] for key in sorted(users)],
        "user_function_count": len(users),
    }


def inspect_vtable_or_indirect_call(
    address,
    size=512,
    limit=120,
    include_decompiler=True,
):
    ea = _parse_int(address)
    if ea is None:
        return {"ok": False, "error": "missing address"}
    func = ida_funcs.get_func(ea)
    result = {
        "ok": True,
        "address": _hex(ea),
        "name": ida_name.get_name(ea) or "",
        "segment": _segment(ea),
        "function": _function_bounds(func) if func else None,
        "xrefs": query_xrefs(ea, limit),
        "data_refs": query_data_refs(ea, limit),
        "function_pointer_refs": render_function_pointer_refs(ea, limit),
    }
    if func:
        if include_decompiler:
            result["callsite_arguments"] = query_callsite_arguments(
                ea,
                min(int(limit or 120), 48),
            )
            result["function_context"] = render_function_context(
                func.start_ea,
                min(int(limit or 120), 120),
            )
        else:
            result["function_context"] = render_function_context_low_level(
                func.start_ea,
                min(int(limit or 120), 120),
            )
        result["stack_frame"] = render_stack_frame(
            func.start_ea,
            min(int(limit or 120), 120),
            include_decompiler=include_decompiler,
        )
    else:
        result["data_object"] = render_data_object(ea, size)
        result["vtable_entries"] = render_vtable_entries(
            ea,
            max_entries=min(int(limit or 120), 64),
        )
    return result


def execute_task(task, *, input_file_path=None):
    requested_kind = task.get("task_type") or task.get("kind")
    kind = normalize_capability_name(requested_kind) or requested_kind
    target = task.get("target") or task.get("address") or task.get("value")
    limit = task.get("limit")
    if kind == "describe_query_runtime":
        return describe_query_runtime()
    if kind == "survey_idb":
        return survey_idb()
    if kind == "query_functions":
        return query_functions_collection(
            filters=task.get("filters"),
            order=task.get("order") or "address",
            limit=limit or 100,
            offset=task.get("offset") or 0,
        )
    if kind == "query_symbols":
        return query_symbols_collection(
            filters=task.get("filters"),
            order=task.get("order") or "address",
            limit=limit or 100,
            offset=task.get("offset") or 0,
        )
    if kind == "query_strings":
        return query_strings_collection(
            filters=task.get("filters"),
            order=task.get("order") or "address",
            limit=limit or 100,
            offset=task.get("offset") or 0,
        )
    if kind == "query_types":
        return query_types_collection(
            filters=task.get("filters"),
            order=task.get("order") or "name",
            limit=limit or 100,
            offset=task.get("offset") or 0,
        )
    if kind == "inspect_function_summary":
        return inspect_function_summary(target, sample_limit=limit or 12)
    if kind == "inspect_idb_meta":
        return render_idb_meta(limit or 80)
    if kind == "list_functions":
        return list_functions(
            prefix=task.get("prefix"),
            limit=limit or 120,
            offset=task.get("offset") or 0,
        )
    if kind == "inspect_addr":
        return inspect_addr(target, size=task.get("size") or 32, limit=limit or 80)
    if kind == "list_exports":
        return list_exports(limit or 120)
    if kind == "list_entrypoints":
        return list_entrypoints(limit or 120)
    if kind == "list_globals":
        return list_globals(prefix=task.get("prefix"), limit=limit or 160)
    if kind == "list_local_types":
        return list_local_types(prefix=task.get("prefix"), limit=limit or 160)
    if kind == "inspect_struct":
        return inspect_struct(target or task.get("name"), limit=limit or 160)
    if kind == "read_struct":
        return read_struct(target or task.get("name"), limit=limit or 160)
    if kind == "xrefs_to_field":
        return xrefs_to_field(
            target or task.get("name"),
            offset=task.get("offset") or task.get("field_offset") or task.get("member_offset"),
            limit=limit or 120,
        )
    if kind == "find_paths":
        return find_paths(
            task.get("source") or task.get("from"),
            target,
            direction=task.get("direction") or "callees",
            depth=task.get("depth") or 3,
            limit=limit or 40,
        )
    if kind == "inspect_bytes":
        return inspect_bytes(target, task.get("size") or 256)
    if kind in {"linear_disassemble", "force_disassemble"}:
        return linear_disassemble(
            target,
            size=task.get("size") or 256,
            limit=limit or task.get("max_instructions") or 120,
            force=bool(task.get("force", True)),
        )
    if kind in {"inspect_cfg", "render_cfg", "render_basic_blocks"}:
        return render_cfg(target, limit or 120)
    if kind == "inspect_function_identity":
        return inspect_function_identity(target)
    if kind in {"inspect_function", "analyze_function", "render_function_context", "decompile", "pseudocode"}:
        if task.get("evidence_representation_policy") == "disassembly_first":
            return render_function_context_low_level(target, limit or 120)
        return render_function_context(target, limit or 120)
    if kind in {"inspect_ctree_summary", "summarize_ctree", "render_ctree_summary"}:
        ea = _parse_int(target)
        if ea is None:
            return {"ok": False, "error": "missing address"}
        return summarize_ctree(ea, limit=limit or 80)
    if kind in {"inspect_data_object", "render_data_object"}:
        return render_data_object(target, task.get("size") or 256)
    if kind in {"infer_struct_layout", "infer_struct"}:
        return infer_struct_context(
            target,
            size=task.get("size") or 256,
            limit=limit or 120,
            include_decompiler=(
                task.get("evidence_representation_policy")
                != "disassembly_first"
            ),
        )
    if kind in {"inspect_xrefs", "query_xrefs", "xrefs"}:
        return query_xrefs(target, limit or 80)
    if kind in {"inspect_data_refs", "query_data_refs", "data_refs"}:
        return query_data_refs(target, limit or 80)
    if kind in {"retrieve_hlil", "retrieve_pseudocode"}:
        return retrieve_pseudocode(target, limit or 240, offset=task.get("offset") or 0)
    if kind == "retrieve_disassembly":
        return retrieve_disassembly(target, limit or 120, offset=task.get("offset") or 0)
    if kind == "inspect_callers":
        return inspect_call_direction(target, "callers", limit or 120)
    if kind == "inspect_callees":
        return inspect_call_direction(target, "callees", limit or 120)
    if kind == "inspect_direct_call_edges":
        return inspect_direct_call_edges(target, limit or 4096)
    if kind in {"query_callers_callees", "calls", "callers_callees"}:
        return query_callers_callees(target, limit or 120)
    if kind in {"inspect_call_graph", "expand_call_graph", "callgraph", "call_graph"}:
        return expand_call_graph(
            target,
            depth=task.get("depth") or 1,
            direction=task.get("direction") or "both",
            limit=limit or 120,
        )
    if kind in {"inspect_callsite_arguments", "query_callsite_arguments"}:
        return query_callsite_arguments(target, limit or 24)
    if kind == "query_hook_entry_contract":
        return query_hook_entry_contract(target, limit or 80)
    if kind in {"resolve_table", "render_switch_table"}:
        return render_switch_table(target, limit or 80)
    if kind in {"discover_enum_candidates", "discover_domain_artifact_candidates"}:
        return discover_enum_candidates(
            limit=limit or 120,
            min_compare_values=task.get("min_compare_values") or 3,
        )
    if kind in {"inspect_imports", "render_imports", "imports"}:
        return render_imports(target, limit or 160)
    if kind in {"search_strings", "render_strings", "strings"}:
        return render_strings(target, limit or 80)
    if kind in {"inspect_function_pointer_refs", "render_function_pointer_refs"}:
        return render_function_pointer_refs(target, limit or 120)
    if kind == "inspect_global_users":
        return inspect_global_users(target, size=task.get("size") or 256, limit=limit or 120)
    if kind == "inspect_vtable_or_indirect_call":
        return inspect_vtable_or_indirect_call(
            target,
            size=task.get("size") or 512,
            limit=limit or 120,
            include_decompiler=(
                task.get("evidence_representation_policy")
                != "disassembly_first"
            ),
        )
    if kind in {"inspect_stack_frame", "render_stack_frame", "stack_frame", "stack"}:
        return render_stack_frame(
            target,
            limit or 120,
            include_decompiler=(
                task.get("evidence_representation_policy")
                != "disassembly_first"
            ),
        )
    if kind in {"inspect_pe_inventory", "render_pe_inventory"}:
        return render_pe_inventory(
            limit or 80,
            target=target,
            size=task.get("size"),
            input_file_path=input_file_path,
        )
    if kind in {"inspect_segments", "render_segments"}:
        return render_segments(limit or 120)
    if kind in {"search_names", "render_names_types", "render_names", "render_types", "names", "types", "names_types"}:
        return render_names_types(target, prefix=task.get("prefix"), limit=limit or 160)
    if kind == "search_bytes":
        return search_bytes(target, limit=limit or 80, max_scan_bytes=task.get("max_scan_bytes") or 16777216)
    if kind == "extract_resource_or_overlay":
        return extract_resource_or_overlay(
            target=target,
            index=task.get("index"),
            size=task.get("size") or 4096,
            input_file_path=input_file_path,
        )
    if kind in {"search_constants", "search_constant"}:
        return search_constant(target)
    if kind == "search_instructions":
        return search_instructions(
            task.get("query") or task.get("pattern") or target or task.get("prefix"),
            limit=limit or 120,
        )
    if kind == "convert_int":
        return convert_int(target)
    if kind == "run_readonly_report":
        return run_readonly_report(
            task.get("report") or task.get("script") or task.get("prefix") or target,
            target=target,
            limit=limit or 120,
            offset=task.get("offset") or task.get("field_offset") or task.get("member_offset"),
        )
    return {"ok": False, "error": "unsupported task type: %s" % kind}


def main(argv):
    args = parse_args(argv)
    load_binary(args.input)
    with open(args.tasks) as f:
        payload = json.load(f)
    if isinstance(payload, list):
        tasks = payload
    elif isinstance(payload, dict):
        tasks = payload.get("tasks") or []
    else:
        tasks = []
    results = []
    for task in tasks:
        try:
            result = execute_task(task)
        except Exception as exc:
            result = {"ok": False, "error": str(exc)}
        results.append({"task": task, "result": result})
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump({"version": "ida_structural_queries.v0", "results": results}, f, indent=2)
    print("Wrote %d structural query result(s) to: %s" % (len(results), args.output))
    return 0


if __name__ == "__main__":
    main(sys.argv[1:])
