"""Small stdlib PE inventory parser for IDA harness context."""

from __future__ import annotations

import math
import struct
from pathlib import Path
from typing import Any


MAX_RESOURCE_DEPTH = 5
MAX_RESOURCE_DIRECTORY_ENTRIES = 200
MAX_RESOURCE_ITEMS = 200
MAX_RESOURCE_WORK = 10_000


RESOURCE_TYPES = {
    1: "cursor",
    2: "bitmap",
    3: "icon",
    4: "menu",
    5: "dialog",
    6: "string",
    7: "font_directory",
    8: "font",
    9: "accelerator",
    10: "rcdata",
    11: "message_table",
    12: "group_cursor",
    14: "group_icon",
    16: "version",
    24: "manifest",
}


def _u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def _u64(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    size = len(data)
    for count in counts:
        if count:
            p = count / size
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def _cstring(data: bytes, off: int, limit: int = 512) -> str:
    if off < 0 or off >= len(data):
        return ""
    end = off
    max_end = min(len(data), off + limit)
    while end < max_end and data[end] != 0:
        end += 1
    return data[off:end].decode("utf-8", errors="replace")


def _read_utf16_name(data: bytes, off: int, limit: int = 256) -> str:
    if off < 0 or off + 2 > len(data):
        return ""
    length = min(_u16(data, off), limit)
    raw = data[off + 2: off + 2 + length * 2]
    return raw.decode("utf-16le", errors="replace")


def _rva_to_offset(rva: int, sections: list[dict[str, Any]]) -> int | None:
    for section in sections:
        va = section["virtual_address"]
        size = max(section["virtual_size"], section["raw_size"])
        if va <= rva < va + size:
            return section["raw_ptr"] + (rva - va)
    return None


def _parse_resource_dir(data: bytes, base_off: int, rva: int, sections: list[dict[str, Any]]) -> dict[str, Any]:
    root_off = _rva_to_offset(rva, sections)
    if root_off is None or root_off + 16 > len(data):
        return {"present": False, "error": "resource directory not mapped",
                "scan": {"complete": False, "reasons": ["unmapped_directory"]}}
    items = []
    type_counts: dict[str, int] = {}
    issues: set[str] = set()
    entries_scanned = 0
    directory_visits = 0

    def walk(dir_off: int, level: int, path: list[str], ancestors: frozenset[int]) -> None:
        nonlocal entries_scanned, directory_visits
        if dir_off in ancestors:
            issues.add("directory_cycle")
            return
        if level > MAX_RESOURCE_DEPTH:
            issues.add("depth_limit")
            return
        if dir_off < 0 or dir_off + 16 > len(data):
            issues.add("truncated_directory")
            return
        directory_visits += 1
        named = _u16(data, dir_off + 12)
        ids = _u16(data, dir_off + 14)
        count = min(named + ids, MAX_RESOURCE_DIRECTORY_ENTRIES)
        if count < named + ids:
            issues.add("directory_entry_limit")
        entry_off = dir_off + 16
        for index in range(count):
            if entries_scanned >= MAX_RESOURCE_WORK:
                issues.add("work_limit")
                return
            if len(items) >= MAX_RESOURCE_ITEMS:
                issues.add("item_limit")
                return
            off = entry_off + index * 8
            if off + 8 > len(data):
                issues.add("truncated_directory_entry")
                break
            entries_scanned += 1
            name_raw = _u32(data, off)
            value_raw = _u32(data, off + 4)
            if name_raw & 0x80000000:
                name = _read_utf16_name(data, root_off + (name_raw & 0x7FFFFFFF))
            else:
                name_id = name_raw & 0xFFFF
                name = RESOURCE_TYPES.get(name_id, str(name_id)) if level == 0 else str(name_id)
            next_path = path + [name]
            if value_raw & 0x80000000:
                # Path-local identity detects cycles while retaining distinct
                # resource paths through a legitimately shared directory.
                walk(root_off + (value_raw & 0x7FFFFFFF), level + 1,
                     next_path, ancestors | {dir_off})
            else:
                data_entry = root_off + value_raw
                if data_entry + 16 > len(data):
                    issues.add("truncated_data_entry")
                    continue
                data_rva = _u32(data, data_entry)
                size = _u32(data, data_entry + 4)
                item = {
                    "path": next_path,
                    "type": next_path[0] if next_path else "",
                    "rva": hex(data_rva),
                    "file_offset": hex(_rva_to_offset(data_rva, sections) or 0),
                    "size": size,
                }
                items.append(item)
                type_counts[item["type"]] = type_counts.get(item["type"], 0) + 1

    walk(root_off, 0, [], frozenset())
    return {
        "present": True,
        "rva": hex(rva),
        "file_offset": hex(root_off),
        "count": len(items),
        "count_relation": "lower_bound" if issues else "exact",
        "returned": min(80, len(items)),
        "items_truncated": len(items) > 80,
        "scan": {
            "complete": not issues,
            "reasons": sorted(issues),
            "entries_scanned": entries_scanned,
            "directory_visits": directory_visits,
            "work_limit": MAX_RESOURCE_WORK,
        },
        "type_counts": dict(sorted(type_counts.items())),
        "items": items[:80],
    }


def _parse_imports(data: bytes, rva: int, sections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    off = _rva_to_offset(rva, sections)
    if off is None:
        return []
    imports = []
    for index in range(256):
        desc = off + index * 20
        if desc + 20 > len(data):
            break
        original_thunk = _u32(data, desc)
        name_rva = _u32(data, desc + 12)
        first_thunk = _u32(data, desc + 16)
        if not any([original_thunk, name_rva, first_thunk]):
            break
        name_off = _rva_to_offset(name_rva, sections)
        imports.append({
            "dll": _cstring(data, name_off) if name_off is not None else "",
            "original_thunk_rva": hex(original_thunk),
            "first_thunk_rva": hex(first_thunk),
        })
    return imports


def _parse_exports(data: bytes, rva: int, sections: list[dict[str, Any]]) -> dict[str, Any]:
    off = _rva_to_offset(rva, sections)
    if off is None or off + 40 > len(data):
        return {"present": False}
    name_rva = _u32(data, off + 12)
    name_off = _rva_to_offset(name_rva, sections)
    number_of_functions = _u32(data, off + 20)
    number_of_names = _u32(data, off + 24)
    return {
        "present": True,
        "dll_name": _cstring(data, name_off) if name_off is not None else "",
        "function_count": number_of_functions,
        "name_count": number_of_names,
    }


def _parse_tls(data: bytes, rva: int, sections: list[dict[str, Any]], image_base: int, is_64: bool) -> dict[str, Any]:
    off = _rva_to_offset(rva, sections)
    if off is None:
        return {"present": False}
    entry_size = 40 if is_64 else 24
    if off + entry_size > len(data):
        return {"present": False, "error": "TLS directory truncated"}
    callbacks_va = _u64(data, off + 24) if is_64 else _u32(data, off + 12)
    callbacks = []
    cb_off = _rva_to_offset(callbacks_va - image_base, sections) if callbacks_va else None
    if cb_off is not None:
        pointer_size = 8 if is_64 else 4
        for index in range(32):
            item_off = cb_off + index * pointer_size
            if item_off + pointer_size > len(data):
                break
            value = _u64(data, item_off) if is_64 else _u32(data, item_off)
            if not value:
                break
            callbacks.append(hex(value))
    return {
        "present": True,
        "callbacks_va": hex(callbacks_va) if callbacks_va else None,
        "callbacks": callbacks,
        "callback_count": len(callbacks),
    }


def build_pe_inventory_bytes(
    data: bytes,
    *,
    source: str = "memory",
) -> dict[str, Any]:
    """Build a PE inventory from an explicit byte sequence.

    Keeping the parser independent of a filesystem path lets an IDA query
    inventory an embedded PE directly from the bytes in the database.  It
    also prevents migrated IDBs from accidentally reopening the historical
    input path recorded by IDA.
    """

    result: dict[str, Any] = {
        "version": "pe_inventory.v0",
        "file": str(source),
        "file_size": len(data),
        "is_pe": False,
    }
    if len(data) < 0x40 or data[:2] != b"MZ":
        result["error"] = "missing MZ header"
        return result
    pe_off = _u32(data, 0x3C)
    if pe_off + 0x18 > len(data) or data[pe_off:pe_off + 4] != b"PE\0\0":
        result["error"] = "missing PE signature"
        return result

    machine = _u16(data, pe_off + 4)
    section_count = _u16(data, pe_off + 6)
    optional_size = _u16(data, pe_off + 20)
    opt_off = pe_off + 24
    magic = _u16(data, opt_off)
    is_64 = magic == 0x20B
    image_base = _u64(data, opt_off + 24) if is_64 else _u32(data, opt_off + 28)
    entry_rva = _u32(data, opt_off + 16)
    size_of_image = _u32(data, opt_off + 56)
    data_dir_off = opt_off + (112 if is_64 else 96)
    directories = []
    for index in range(16):
        off = data_dir_off + index * 8
        if off + 8 > pe_off + 24 + optional_size or off + 8 > len(data):
            break
        directories.append({"rva": _u32(data, off), "size": _u32(data, off + 4)})

    sections = []
    sec_off = opt_off + optional_size
    for index in range(section_count):
        off = sec_off + index * 40
        if off + 40 > len(data):
            break
        name = data[off:off + 8].split(b"\0", 1)[0].decode("utf-8", errors="replace")
        virtual_size = _u32(data, off + 8)
        virtual_address = _u32(data, off + 12)
        raw_size = _u32(data, off + 16)
        raw_ptr = _u32(data, off + 20)
        characteristics = _u32(data, off + 36)
        raw = data[raw_ptr: raw_ptr + raw_size] if raw_ptr < len(data) else b""
        sections.append({
            "name": name,
            "virtual_address": virtual_address,
            "virtual_size": virtual_size,
            "raw_ptr": raw_ptr,
            "raw_size": raw_size,
            "characteristics": hex(characteristics),
            "entropy": _entropy(raw),
        })

    overlay_offset = max((section["raw_ptr"] + section["raw_size"] for section in sections), default=0)
    overlay_size = max(0, len(data) - overlay_offset)
    result.update({
        "is_pe": True,
        "machine": hex(machine),
        "bitness": 64 if is_64 else 32,
        "image_base": hex(image_base),
        "entry_point_rva": hex(entry_rva),
        "entry_point_va": hex(image_base + entry_rva),
        "size_of_image": size_of_image,
        "sections": [
            {
                **section,
                "virtual_address": hex(section["virtual_address"]),
                "virtual_size": section["virtual_size"],
                "raw_ptr": hex(section["raw_ptr"]),
            }
            for section in sections
        ],
        "overlay": {
            "present": overlay_size > 0,
            "file_offset": hex(overlay_offset),
            "size": overlay_size,
            "entropy": _entropy(data[overlay_offset:]) if overlay_size else 0.0,
        },
    })
    result["imports"] = _parse_imports(data, directories[1]["rva"], sections) if len(directories) > 1 and directories[1]["rva"] else []
    result["exports"] = _parse_exports(data, directories[0]["rva"], sections) if directories and directories[0]["rva"] else {"present": False}
    result["resources"] = _parse_resource_dir(data, 0, directories[2]["rva"], sections) if len(directories) > 2 and directories[2]["rva"] else {"present": False}
    result["tls"] = _parse_tls(data, directories[9]["rva"], sections, image_base, is_64) if len(directories) > 9 and directories[9]["rva"] else {"present": False}
    return result


def build_pe_inventory(path: str | Path) -> dict[str, Any]:
    file_path = Path(path)
    return build_pe_inventory_bytes(
        file_path.read_bytes(),
        source=str(file_path),
    )
