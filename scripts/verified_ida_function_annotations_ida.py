"""
Apply host-produced program-model annotations to an IDA database.

This script runs inside IDA/idat under the no-network sandbox. It only mutates
the IDB/I64 based on an annotations JSON file produced by the host launcher.
"""

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import ida_bytes
try:
    import ida_dirtree
except Exception:
    ida_dirtree = None
import ida_funcs
import ida_segment
import idc

from ida_backend import save_database
from ida_reader import load_binary
from ida_writer import (
    TAG_ANALYZED,
    TAG_NEEDS_CONTEXT,
    rename_function,
    set_function_comment,
    tag_function,
)


NAME_RE = re.compile(r"[^0-9A-Za-z_$?@.]")


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Apply program-model IDA annotations.")
    parser.add_argument("input", help="IDB or I64 to annotate.")
    parser.add_argument("--annotations", required=True, help="Annotations JSON path.")
    parser.add_argument("--save-as", required=True, help="Output IDB/I64 path.")
    parser.add_argument("--summary-out", help="Optional JSON summary output path.")
    return parser.parse_args(argv)


def _clean_name(name):
    name = (name or "").strip()
    if not name:
        return ""
    name = NAME_RE.sub("_", name)
    if name[0].isdigit():
        name = "fn_" + name
    return name[:180]


def _load_annotations(path):
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, list):
        return data, [], [], []
    annotations = data.get("annotations", [])
    data_annotations = list(data.get("data_annotations") or [])
    if not data_annotations:
        data_annotations = [
            entry
            for item in annotations
            for entry in item.get("data_annotations", []) or []
        ]
    inline_comments = list(data.get("inline_comments") or [])
    folder_assignments = list(data.get("folder_assignments") or [])
    return annotations, data_annotations, inline_comments, folder_assignments


def _parse_addr(value):
    try:
        if isinstance(value, str):
            return int(value, 16)
        return int(value)
    except Exception:
        return None


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


def _is_loaded_address(ea):
    if ea is None:
        return False
    try:
        return ida_bytes.is_loaded(ea)
    except Exception:
        return ida_segment.getseg(ea) is not None


def _append_function_comment(ea, line):
    func = ida_funcs.get_func(ea)
    if not func:
        return False
    existing = idc.get_func_cmt(func.start_ea, 1) or idc.get_func_cmt(func.start_ea, 0) or ""
    text = str(line or "").strip()
    if not text:
        return True
    if text in existing:
        return True
    new_comment = (existing.rstrip() + "\n" + text).strip() if existing else text
    return bool(idc.set_func_cmt(func.start_ea, new_comment, 1))


def _folder_line(folder, reason=""):
    text = "[folder: %s]" % str(folder or "").strip().strip("/")
    reason = str(reason or "").strip()
    if reason:
        text += " %s" % reason
    return text


def _move_to_ida_folder(ea, folder):
    if ida_dirtree is None:
        return False
    func = ida_funcs.get_func(ea)
    if not func:
        return False
    name = idc.get_func_name(func.start_ea)
    if not name:
        return False
    folder = str(folder or "").strip().strip("/")
    if not folder:
        return False
    try:
        dt = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
        dt.load()
        current = ""
        for part in [p for p in folder.split("/") if p]:
            current = (current + "/" + part) if current else "/" + part
            try:
                dt.mkdir(current)
            except Exception:
                pass
        destination = "/" + folder + "/" + name
        entry = ida_dirtree.direntry_t(func.start_ea)
        cursor = dt.find_entry(entry)
        if cursor.valid():
            source = dt.get_abspath(cursor)
            if source == destination:
                return True
            moved = dt.rename(source, destination) == ida_dirtree.DTE_OK
        else:
            moved = False
            if dt.chdir("/" + folder) == ida_dirtree.DTE_OK:
                moved = dt.link(func.start_ea) == ida_dirtree.DTE_OK
                dt.chdir("/")
        if moved:
            dt.save()
        return moved or dt.isfile(destination)
    except Exception:
        return False


def apply_annotations(annotations):
    summary = {
        "renamed": 0,
        "commented": 0,
        "tagged_analyzed": 0,
        "tagged_needs_context": 0,
        "data_renamed": 0,
        "data_commented": 0,
        "data_typed": 0,
        "data_skipped_low_confidence": 0,
        "failed": 0,
        "errors": [],
    }

    for item in annotations:
        address = item.get("address")
        try:
            ea = int(address, 16)
        except (TypeError, ValueError):
            summary["failed"] += 1
            summary["errors"].append("Invalid address: %r" % (address,))
            continue

        proposed_name = _clean_name(item.get("proposed_name") or item.get("new_name") or item.get("name"))
        if proposed_name:
            if rename_function(ea, proposed_name):
                summary["renamed"] += 1
            else:
                summary["failed"] += 1
                summary["errors"].append("Rename failed at %s" % address)

        comment = item.get("analyst_comment") or item.get("comment") or ""
        if comment:
            if set_function_comment(ea, comment):
                summary["commented"] += 1
            else:
                summary["failed"] += 1
                summary["errors"].append("Comment failed at %s" % address)

        if item.get("needs_context"):
            if tag_function(ea, TAG_NEEDS_CONTEXT, item.get("context_reason", "")):
                summary["tagged_needs_context"] += 1
        else:
            confidence = item.get("confidence", "")
            if tag_function(ea, TAG_ANALYZED, "confidence:%s" % confidence):
                summary["tagged_analyzed"] += 1

    return summary


def apply_inline_comments(inline_comments):
    summary = {
        "inline_commented": 0,
        "failed": 0,
        "errors": [],
    }
    for item in inline_comments:
        ea = _parse_addr(item.get("address") or item.get("ea"))
        if not _is_loaded_address(ea):
            summary["failed"] += 1
            summary["errors"].append("Invalid inline comment address: %r" % (item.get("address") or item.get("ea"),))
            continue
        comment = str(item.get("comment") or item.get("text") or "").strip()
        if not comment:
            summary["failed"] += 1
            summary["errors"].append("Missing inline comment at %s" % (hex(ea),))
            continue
        repeatable = 1 if item.get("repeatable") else 0
        if idc.set_cmt(ea, comment, repeatable):
            summary["inline_commented"] += 1
        else:
            summary["failed"] += 1
            summary["errors"].append("Inline comment failed at %s" % (hex(ea),))
    return summary


def apply_folder_assignments(folder_assignments):
    summary = {
        "folders_moved": 0,
        "folders_tagged": 0,
        "folders_native_failed": 0,
        "folder_receipts": [],
        "failed": 0,
        "errors": [],
    }
    for item in folder_assignments:
        ea = _parse_addr(item.get("address") or item.get("ea") or item.get("function_ea"))
        func = ida_funcs.get_func(ea) if ea is not None else None
        if not func:
            summary["failed"] += 1
            summary["errors"].append("Invalid folder function address: %r" % (item.get("address") or item.get("ea") or item.get("function_ea"),))
            continue
        folder = str(item.get("folder") or item.get("folder_path") or "").strip().strip("/")
        if not folder:
            summary["failed"] += 1
            summary["errors"].append("Missing folder path at %s" % (hex(func.start_ea),))
            continue
        moved = _move_to_ida_folder(func.start_ea, folder)
        if moved:
            summary["folders_moved"] += 1
        else:
            summary["folders_native_failed"] += 1
        tagged = _append_function_comment(
            func.start_ea,
            _folder_line(folder, item.get("reason") or ""),
        )
        if tagged:
            summary["folders_tagged"] += 1
        elif not moved:
            summary["failed"] += 1
            summary["errors"].append("Folder assignment failed at %s" % (hex(func.start_ea),))
        summary["folder_receipts"].append({
            "address": hex(func.start_ea),
            "folder": folder,
            "native_status": "moved" if moved else "native_move_failed",
            "fallback_comment_tagged": bool(tagged),
            "effective_status": (
                "native_folder"
                if moved
                else "comment_tag_fallback"
                if tagged
                else "failed"
            ),
        })
    return summary


def apply_data_annotations(data_annotations):
    summary = {
        "data_renamed": 0,
        "data_commented": 0,
        "data_typed": 0,
        "data_skipped_low_confidence": 0,
        "failed": 0,
        "errors": [],
    }
    for item in data_annotations:
        ea = _parse_addr(item.get("address"))
        if not _is_valid_data_address(ea):
            summary["failed"] += 1
            summary["errors"].append("Invalid data address: %r" % (item.get("address"),))
            continue
        try:
            confidence = float(item.get("confidence") or 0.0)
        except Exception:
            confidence = 0.0
        if confidence < 0.72:
            summary["data_skipped_low_confidence"] += 1
            continue

        name = _clean_name(item.get("name") or "")
        if name:
            if idc.set_name(ea, name, idc.SN_NOCHECK):
                summary["data_renamed"] += 1
            else:
                summary["failed"] += 1
                summary["errors"].append("Data rename failed at %s" % item.get("address"))
        type_string = str(item.get("type") or "").strip()
        if type_string:
            if idc.SetType(ea, type_string):
                summary["data_typed"] += 1
            else:
                summary["failed"] += 1
                summary["errors"].append("Data type failed at %s" % item.get("address"))
        comment = str(item.get("comment") or "").strip()
        if comment:
            if idc.set_cmt(ea, comment, 0):
                summary["data_commented"] += 1
            else:
                summary["failed"] += 1
                summary["errors"].append("Data comment failed at %s" % item.get("address"))
    return summary


def main(argv):
    args = parse_args(argv)
    load_binary(args.input)
    annotations, data_annotations, inline_comments, folder_assignments = _load_annotations(args.annotations)
    summary = apply_annotations(annotations)
    data_summary = apply_data_annotations(data_annotations)
    inline_summary = apply_inline_comments(inline_comments)
    folder_summary = apply_folder_assignments(folder_assignments)
    for key, value in list(data_summary.items()) + list(inline_summary.items()) + list(folder_summary.items()):
        if isinstance(value, int):
            summary[key] = int(summary.get(key, 0)) + value
        elif isinstance(value, list):
            summary.setdefault(key, []).extend(value)
    save_database(args.save_as)
    if args.summary_out:
        with open(args.summary_out, "w") as f:
            json.dump(summary, f, indent=2, sort_keys=True)
    print(json.dumps(summary, indent=2))
    print("Saved annotated database to: %s" % args.save_as)
    return 0


if __name__ == "__main__":
    main(sys.argv[1:])
