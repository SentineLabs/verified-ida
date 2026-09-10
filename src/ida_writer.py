"""
IDA Writer — Apply LLM analysis decisions back to the IDA database.

Mirrors bndb_writer.py from binja_harness. The LLM produces structured
decisions (rename, comment, tag) and this module applies them to the IDB.

Key difference from Binja: has_tag() takes an address (int), not a function object.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import idaapi
import idc
import ida_funcs
import idautils

from ida_tags import (
    TAG_COLLAPSED, TAG_INTERESTING, TAG_ANALYZED,
    TAG_BLOCKED, TAG_NEEDS_CONTEXT,
    tag_function as _tag_function,
    remove_tag as _remove_tag,
    has_tag as _has_tag,
)
from ida_backend import save_database
from ida_reader import load_binary

# Re-export tag constants for callers
__all__ = [
    "TAG_COLLAPSED", "TAG_INTERESTING", "TAG_ANALYZED",
    "TAG_BLOCKED", "TAG_NEEDS_CONTEXT",
    "rename_function", "set_function_comment", "set_address_comment",
    "tag_function", "remove_tag", "has_tag",
    "set_function_type", "apply_actions", "get_analysis_stats",
]


def rename_function(ea: int, new_name: str) -> bool:
    """Rename a function in the IDB. Returns True on success."""
    func = ida_funcs.get_func(ea)
    if func is None:
        return False
    return idc.set_name(ea, new_name, idc.SN_NOCHECK)


def set_function_comment(ea: int, comment: str) -> bool:
    """Set a repeatable comment on a function (at its start address)."""
    func = ida_funcs.get_func(ea)
    if func is None:
        return False
    return idc.set_func_cmt(ea, comment, 1)  # 1 = repeatable


def set_address_comment(func_ea: int, target_ea: int, comment: str) -> bool:
    """Set a comment at a specific address within a function."""
    func = ida_funcs.get_func(func_ea)
    if func is None:
        return False
    if not (func.start_ea <= target_ea < func.end_ea):
        return False
    return idc.set_cmt(target_ea, comment, 0)  # 0 = non-repeatable


def tag_function(ea: int, tag_name: str, data: str = "") -> bool:
    """Add a tag to a function. Tags track analysis state."""
    return _tag_function(ea, tag_name, data)


def remove_tag(ea: int, tag_name: str) -> bool:
    """Remove a specific tag from a function."""
    return _remove_tag(ea, tag_name)


def has_tag(ea: int, tag_name: str) -> bool:
    """Check if a function has a specific tag.

    Note: Unlike Binja's has_tag(func, tag_name), this takes an address (int).
    """
    return _has_tag(ea, tag_name)


def set_function_type(ea: int, type_string: str) -> bool:
    """Set the type signature of a function from a C-style type string."""
    func = ida_funcs.get_func(ea)
    if func is None:
        return False
    try:
        return idc.SetType(ea, type_string)
    except Exception:
        return False


def apply_actions(actions: list[dict]) -> dict:
    """Apply a batch of LLM-produced actions to the IDB.

    Each action is a dict with:
        - action: "rename" | "comment" | "tag" | "set_type"
        - address: hex string (e.g., "0x401000")
        - value: the new name, comment text, tag name, or type string
        - data: optional additional data (for tags)

    Returns a summary of results.
    """
    results = {"applied": 0, "failed": 0, "errors": []}

    for act in actions:
        action_type = act.get("action")
        addr = int(act.get("address", "0"), 16)
        value = act.get("value", "")

        success = False
        if action_type == "rename":
            success = rename_function(addr, value)
        elif action_type == "comment":
            success = set_function_comment(addr, value)
        elif action_type == "tag":
            data = act.get("data", "")
            success = tag_function(addr, value, data)
        elif action_type == "set_type":
            success = set_function_type(addr, value)
        else:
            results["errors"].append(f"Unknown action: {action_type} at {hex(addr)}")
            results["failed"] += 1
            continue

        if success:
            results["applied"] += 1
        else:
            results["errors"].append(f"Failed: {action_type} at {hex(addr)}")
            results["failed"] += 1

    return results


def get_analysis_stats() -> dict:
    """Get current analysis state counts from the IDB."""
    stats = {
        "total_functions": 0,
        "collapsed": 0,
        "interesting": 0,
        "analyzed": 0,
        "blocked": 0,
        "needs_context": 0,
        "untagged": 0,
        "renamed": 0,
        "commented": 0,
    }

    for func_ea in idautils.Functions():
        stats["total_functions"] += 1

        tagged = False
        for tag_name in [TAG_COLLAPSED, TAG_INTERESTING, TAG_ANALYZED, TAG_BLOCKED, TAG_NEEDS_CONTEXT]:
            if has_tag(func_ea, tag_name):
                stats[tag_name] += 1
                tagged = True
        if not tagged:
            stats["untagged"] += 1

        name = idc.get_func_name(func_ea)
        if name and not name.startswith("sub_"):
            stats["renamed"] += 1

        if idc.get_func_cmt(func_ea, 0) or idc.get_func_cmt(func_ea, 1):
            stats["commented"] += 1

    return stats


# --- CLI interface ---

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: ida_writer.py <idb_path> <actions.json> [--save-as <output.idb>]")
        print("       ida_writer.py <idb_path> --stats")
        sys.exit(1)

    idb_path = sys.argv[1]
    load_binary(idb_path)

    if sys.argv[2] == "--stats":
        stats = get_analysis_stats()
        print(json.dumps(stats, indent=2))
    else:
        actions_path = sys.argv[2]
        with open(actions_path) as f:
            actions = json.load(f)

        results = apply_actions(actions)
        print(json.dumps(results, indent=2))

        output_path = idb_path
        if "--save-as" in sys.argv:
            idx = sys.argv.index("--save-as")
            output_path = sys.argv[idx + 1]

        save_database(output_path)
        print(f"Saved to: {output_path}")
