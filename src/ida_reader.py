"""
IDA Reader — Structured JSON export of IDA database state for LLM consumption.

Mirrors bndb_reader.py from binja_harness. Produces identical JSON key structures
so the LLM analysis prompt and pipeline scripts work unchanged.

Requires IDA Pro 9.x with IDAPython. Works in idalib, idat, or embedded mode.
"""

from __future__ import annotations

import json
import math
import os
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, os.path.dirname(__file__))

import idaapi
import idautils
import idc
import ida_bytes
import ida_funcs
import ida_ida
import ida_loader
import ida_nalt
import ida_segment
import ida_lines

try:
    import ida_hexrays
    HAS_HEXRAYS = True
except ImportError:
    HAS_HEXRAYS = False

from ida_backend import open_database, save_database
from pe_inventory import build_pe_inventory


def load_binary(path: str) -> None:
    """Load a binary or IDB file, wait for analysis to complete.

    Unlike Binja which returns a BinaryView, IDA uses global state.
    This function opens the database and ensures analysis is complete.
    """
    open_database(path, auto_analysis=True)


def save_idb(output_path: str) -> None:
    """Save the current analysis state as an IDB file."""
    save_database(output_path)


def get_binary_metadata() -> dict:
    """Extract high-level binary metadata.

    Returns dict with identical keys to bndb_reader.get_binary_metadata().
    """
    filename = idc.get_input_file_path()

    # Architecture name
    proc_name = ida_ida.inf_get_procname()
    is_64bit = ida_ida.inf_is_64bit()
    is_32bit = getattr(ida_ida, "inf_is_32bit", lambda: not is_64bit)()
    bitness = 64 if is_64bit else (32 if is_32bit else 16)
    arch = f"{proc_name}_{bitness}" if proc_name else "unknown"

    # Platform
    file_type = ida_loader.get_file_type_name()
    platform = f"{file_type}-{arch}" if file_type else arch

    # Sections (segments in IDA terminology)
    sections = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg:
            sections.append({
                "name": idc.get_segm_name(seg_ea),
                "start": hex(seg.start_ea),
                "end": hex(seg.end_ea),
                "length": seg.end_ea - seg.start_ea,
                "semantics": _segment_semantics(seg),
            })

    start_ea = ida_ida.inf_get_start_ea()

    pe_inventory = get_pe_inventory(filename) if filename else {"is_pe": False, "error": "missing input path"}

    return {
        "filename": Path(filename).name if filename else "unknown",
        "file_path": filename or "unknown",
        "architecture": arch,
        "platform": platform,
        "entry_point": hex(start_ea) if start_ea != idaapi.BADADDR else "0x0",
        "total_functions": len(list(idautils.Functions())),
        "total_strings": len(list(idautils.Strings())),
        "sections": sections,
        "pe": {
            "is_pe": bool(pe_inventory.get("is_pe")),
            "bitness": pe_inventory.get("bitness"),
            "image_base": pe_inventory.get("image_base"),
            "overlay": pe_inventory.get("overlay"),
            "resource_count": (pe_inventory.get("resources") or {}).get("count"),
            "tls_callback_count": (pe_inventory.get("tls") or {}).get("callback_count"),
        },
    }


def get_pe_inventory(path: str | None = None) -> dict:
    filename = path or idc.get_input_file_path()
    if not filename:
        return {"version": "pe_inventory.v0", "is_pe": False, "error": "missing input path"}
    try:
        return build_pe_inventory(filename)
    except Exception as exc:
        return {"version": "pe_inventory.v0", "file": filename, "is_pe": False, "error": str(exc)}


def _segment_semantics(seg) -> str:
    """Map IDA segment permissions to a semantics string."""
    perms = seg.perm
    parts = []
    if perms & ida_segment.SEGPERM_EXEC or seg.type == ida_segment.SEG_CODE:
        parts.append("Code")
    if seg.type == ida_segment.SEG_DATA:
        parts.append("Data")
    if not parts:
        parts.append("Unknown")
    return ", ".join(parts)


def get_entry_points() -> list[dict]:
    """Enumerate all entry points: main, exports, etc."""
    entry_points = []
    seen = set()

    # Primary entry point
    start_ea = ida_ida.inf_get_start_ea()
    if start_ea != idaapi.BADADDR:
        func = ida_funcs.get_func(start_ea)
        if func:
            ea = func.start_ea
            entry_points.append({
                "address": hex(ea),
                "name": idc.get_func_name(ea) or f"sub_{ea:x}",
                "type": "entry_point",
            })
            seen.add(ea)

    # Exports
    for idx, ordinal, ea, name in idautils.Entries():
        if ea in seen:
            continue
        func = ida_funcs.get_func(ea)
        if func:
            entry_points.append({
                "address": hex(ea),
                "name": name or idc.get_func_name(ea) or f"sub_{ea:x}",
                "type": "export",
            })
            seen.add(ea)

    return entry_points


def get_imports() -> list[dict]:
    """Extract imported functions with reference counts."""
    imports = []

    def import_callback(ea, name, ordinal):
        if name and ea != idaapi.BADADDR:
            refs = list(idautils.XrefsTo(ea, 0))
            imports.append({
                "name": name,
                "address": hex(ea),
                "ref_count": len(refs),
            })
        return True  # Continue enumeration

    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
        ida_nalt.enum_import_names(i, import_callback)

    imports.sort(key=lambda x: x["ref_count"], reverse=True)
    return imports


def get_strings_summary(min_length: int = 4) -> list[dict]:
    """Extract strings with reference information.

    Returns strings sorted by reference count (most-referenced first).
    """
    strings = []
    for s in idautils.Strings():
        value = idc.get_strlit_contents(s.ea, s.length, s.strtype)
        if value is None:
            continue
        try:
            value = value.decode("utf-8", errors="replace")
        except AttributeError:
            value = str(value)

        if len(value) < min_length:
            continue

        refs = list(idautils.XrefsTo(s.ea, 0))
        strings.append({
            "value": value[:200],
            "address": hex(s.ea),
            "length": len(value),
            "ref_count": len(refs),
            "referenced_by": [hex(ref.frm) for ref in refs[:10]],
        })

    strings.sort(key=lambda x: x["ref_count"], reverse=True)
    return strings


def get_function_summary(func_ea: int) -> dict:
    """Extract a structured summary of a single function for LLM consumption.

    Produces identical JSON keys to bndb_reader.get_function_summary().
    """
    func = ida_funcs.get_func(func_ea)
    if func is None:
        return {"address": hex(func_ea), "name": f"sub_{func_ea:x}", "error": "not a function"}

    name = idc.get_func_name(func_ea) or f"sub_{func_ea:x}"
    size = func.end_ea - func.start_ea

    # Basic block count via FlowChart
    try:
        fc = idaapi.FlowChart(func)
        bb_count = sum(1 for _ in fc)
    except Exception:
        bb_count = 1

    # Library function heuristic
    is_library = bool(func.flags & idaapi.FUNC_LIB) or (
        name.startswith("_") and not name.startswith("__")
    )

    # Call graph: callers (xrefs TO this function)
    callers = []
    seen_callers = set()
    for xref in idautils.XrefsTo(func_ea, 0):
        caller_func = ida_funcs.get_func(xref.frm)
        if caller_func and caller_func.start_ea not in seen_callers:
            seen_callers.add(caller_func.start_ea)
            callers.append({
                "address": hex(caller_func.start_ea),
                "name": idc.get_func_name(caller_func.start_ea) or f"sub_{caller_func.start_ea:x}",
            })

    # Call graph: callees (code refs FROM this function to other function starts)
    callees = []
    seen_callees = set()
    for head in idautils.FuncItems(func_ea):
        for ref in idautils.CodeRefsFrom(head, 0):
            callee_func = ida_funcs.get_func(ref)
            if callee_func and callee_func.start_ea != func_ea and callee_func.start_ea not in seen_callees:
                # Only count if the ref is a call (not a fall-through or jump within function)
                if ref == callee_func.start_ea:
                    seen_callees.add(callee_func.start_ea)
                    callees.append({
                        "address": hex(callee_func.start_ea),
                        "name": idc.get_func_name(callee_func.start_ea) or f"sub_{callee_func.start_ea:x}",
                    })

    # Comments
    comments = {}
    func_cmt = idc.get_func_cmt(func_ea, 1)  # Repeatable
    if func_cmt:
        comments[hex(func_ea)] = func_cmt
    func_cmt_nr = idc.get_func_cmt(func_ea, 0)  # Non-repeatable
    if func_cmt_nr:
        comments[hex(func_ea)] = func_cmt_nr

    # Per-address comments within the function
    for head in idautils.FuncItems(func_ea):
        cmt = idc.get_cmt(head, 0) or idc.get_cmt(head, 1)
        if cmt:
            comments[hex(head)] = cmt

    has_annotations = bool(comments) or not name.startswith("sub_")

    # String references within this function
    func_strings = []
    for head in idautils.FuncItems(func_ea):
        for dref in idautils.DataRefsFrom(head):
            s = idc.get_strlit_contents(dref, -1, idc.STRTYPE_C)
            if s and len(s) >= 4:
                try:
                    func_strings.append(s.decode("utf-8", errors="replace")[:100])
                except AttributeError:
                    func_strings.append(str(s)[:100])

    return {
        "address": hex(func_ea),
        "name": name,
        "size": size,
        "basic_block_count": bb_count,
        "is_library": is_library,
        "callers": callers,
        "callees": callees,
        "caller_count": len(callers),
        "callee_count": len(callees),
        "comments": comments,
        "has_annotations": has_annotations,
        "string_refs": list(set(func_strings))[:20],
    }


def get_function_pseudocode(func_ea: int) -> Optional[str]:
    """Extract Hex-Rays decompiler pseudocode for a function.

    Returns the pseudocode as a string, or None if unavailable.
    Maps to the 'hlil' JSON key for compatibility with binja_harness.
    """
    if not HAS_HEXRAYS:
        return None

    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if cfunc is None:
            return None

        lines = []
        sv = cfunc.get_pseudocode()
        for i in range(sv.size()):
            line = ida_lines.tag_remove(sv[i].line)
            lines.append(line)

        return "\n".join(lines)
    except Exception:
        return None


# Alias for JSON contract compatibility
get_function_hlil = get_function_pseudocode


def get_function_context(func_ea: int, include_hlil: bool = True) -> dict:
    """Get full context for a function — used when presenting to LLM for analysis.

    Includes the function itself, its pseudocode, caller/callee summaries,
    and string refs. Produces identical keys to bndb_reader.get_function_context().
    """
    context = get_function_summary(func_ea)

    if include_hlil:
        hlil = get_function_pseudocode(func_ea)
        if hlil:
            context["hlil"] = hlil
        else:
            context["hlil"] = None
            if not HAS_HEXRAYS:
                context["hlil_error"] = "Hex-Rays decompiler not available"
            else:
                context["hlil_error"] = "Decompilation failed for this function"

    # Caller context: first 5 callers with pseudocode preview
    caller_context = []
    for caller in context.get("callers", [])[:5]:
        caller_ea = int(caller["address"], 16)
        caller_hlil = get_function_pseudocode(caller_ea)
        if caller_hlil:
            preview_lines = caller_hlil.split("\n")[:3]
            caller_context.append({
                "address": caller["address"],
                "name": caller["name"],
                "hlil_preview": "\n".join(preview_lines),
            })
    context["caller_context"] = caller_context

    # Callee context: first 10 callees with annotation info
    callee_context = []
    for callee in context.get("callees", [])[:10]:
        callee_context.append({
            "address": callee["address"],
            "name": callee["name"],
            "has_annotations": not callee["name"].startswith("sub_"),
        })
    context["callee_context"] = callee_context

    if not caller_context:
        try:
            ptr_entries = []
            for ref in idautils.DataRefsTo(func_ea):
                neighbours = []
                for offset in range(-16, 20, 4):
                    neighbour_ea = ref + offset
                    value = ida_bytes.get_dword(neighbour_ea)
                    nb_func = ida_funcs.get_func(value)
                    if nb_func:
                        neighbours.append({
                            "offset": offset,
                            "address": hex(neighbour_ea),
                            "points_to": idc.get_func_name(nb_func.start_ea) or f"sub_{nb_func.start_ea:x}",
                        })

                readers = []
                for xref in idautils.XrefsTo(ref, 0):
                    containing = ida_funcs.get_func(xref.frm)
                    if containing:
                        caller_name = idc.get_func_name(containing.start_ea) or f"sub_{containing.start_ea:x}"
                        readers.append(f"{caller_name} @ {hex(xref.frm)}")

                seg = ida_segment.getseg(ref)
                ptr_entries.append({
                    "table_address": hex(ref),
                    "section": idc.get_segm_name(ref) if seg else "unknown",
                    "neighbouring_function_pointers": neighbours[:8],
                    "read_by": readers[:3],
                })

            if ptr_entries:
                context["function_pointer_refs"] = ptr_entries[:8]
                context["note_no_direct_callers"] = (
                    "This function has no direct callers visible to static analysis. "
                    "It appears in data references above, so it may be reached through "
                    "a callback table or indirect dispatch."
                )
        except Exception:
            pass

    return context


def get_all_functions_summary() -> list[dict]:
    """Get summaries for all functions (without HLIL — too expensive for bulk export)."""
    return [get_function_summary(ea) for ea in idautils.Functions()]


def export_state() -> dict:
    """Export the full IDB state as a structured dict.

    Produces identical top-level keys to bndb_reader.export_state().
    """
    pe_inventory = get_pe_inventory()
    return {
        "metadata": get_binary_metadata(),
        "entry_points": get_entry_points(),
        "imports": get_imports(),
        "strings": get_strings_summary(),
        "functions": get_all_functions_summary(),
        "pe_inventory": pe_inventory,
    }


def compute_function_entropy(func_ea: int) -> float:
    """Compute Shannon entropy of a function's bytes."""
    try:
        func = ida_funcs.get_func(func_ea)
        if func is None:
            return 0.0

        size = func.end_ea - func.start_ea
        data = ida_bytes.get_bytes(func_ea, size)
        if not data:
            return 0.0

        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1

        entropy = 0.0
        length = len(data)
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)

        return round(entropy, 3)
    except Exception:
        return 0.0


# --- CLI interface for standalone use ---

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ida_reader.py <binary_or_idb> [--full|--metadata|--functions|--strings|--imports|--entry-points]")
        sys.exit(1)

    binary_path = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "--metadata"

    load_binary(binary_path)

    if mode == "--full":
        result = export_state()
    elif mode == "--functions":
        result = get_all_functions_summary()
    elif mode == "--metadata":
        result = get_binary_metadata()
    elif mode == "--entry-points":
        result = get_entry_points()
    elif mode == "--imports":
        result = get_imports()
    elif mode == "--strings":
        result = get_strings_summary()
    else:
        print(f"Unknown mode: {mode}")
        sys.exit(1)

    print(json.dumps(result, indent=2))
