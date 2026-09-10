"""
Prepare Analysis — Combined collapse, ranking, and ordering for IDA.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import idaapi
import ida_funcs
import ida_nalt
import idautils
import idc

from ida_backend import save_database
from ida_reader import (
    compute_function_entropy,
    get_binary_metadata,
    get_entry_points,
    get_function_summary,
    load_binary,
)
from ida_writer import (
    TAG_COLLAPSED,
    TAG_INTERESTING,
    TAG_NEEDS_CONTEXT,
    has_tag,
    tag_function,
)


LIBRARY_PREFIXES = [
    "__libc_", "_libc_", "__cxa_", "__gxx_", "__gcc_",
    "__stack_chk", "__fortify_", "__assert_",
    "std::", "__cxxabi", "_ZN", "_ZS", "_ZNS",
    "_CRT_", "__scrt_", "_onexit", "_atexit", "__dyn_tls",
    "_initterm", "__acrt_", "_cexit", "__telemetry",
    "__security_check", "__report_rangecheckfailure",
    "__GSHandlerCheck", "__C_specific_handler",
    "__do_global_", "__static_init", "_GLOBAL__",
    "__cxx_global_var_init",
    "objc_msgSend", "_objc_", "NSObject",
    "__imp_", "runtime.", "runtime/", "internal/",
    "core::", "alloc::",
]
LIBRARY_EXACT = {
    "_start", "__libc_start_main", "_init", "_fini",
    "frame_dummy", "register_tm_clones", "deregister_tm_clones",
    "__do_global_dtors_aux", "__libc_csu_init", "__libc_csu_fini",
}
ENTRY_POINTS = {"main", "_main", "wmain", "_wmain", "WinMain", "wWinMain", "DllMain"}

SUSPICIOUS_STRING_KEYWORDS = [
    "http", "https", "socket", "connect", "send", "recv", "url", "dns",
    "beacon", "callback", "c2", "command", "shell", "cmd", "powershell",
    "encrypt", "decrypt", "aes", "rsa", "xor", "base64", "key", "cipher",
    "create", "delete", "write", "read", "path", "file", "temp",
    "registry", "service", "startup", "autorun", "run",
    "debug", "sandbox", "virtual", "vmware", "sleep",
    "password", "credential", "token", "steal", "dump",
    "inject", "hollow", "thread", "process", "pid",
]

INTERESTING_APIS = {
    "CryptEncrypt": 10, "CryptDecrypt": 10, "CryptImportKey": 10,
    "VirtualAllocEx": 10, "WriteProcessMemory": 10, "CreateRemoteThread": 10,
    "NtUnmapViewOfSection": 10, "IsDebuggerPresent": 8,
    "InternetOpenA": 8, "InternetOpenW": 8, "HttpOpenRequestA": 8,
    "WSAStartup": 7, "connect": 7, "send": 6, "recv": 6,
    "URLDownloadToFileA": 9, "WinHttpOpen": 8,
    "CreateFileA": 5, "CreateFileW": 5, "WriteFile": 5, "ReadFile": 5,
    "CreateProcessA": 7, "CreateProcessW": 7, "OpenProcess": 6,
    "ShellExecuteA": 7, "WinExec": 7,
    "RegOpenKeyExA": 6, "RegSetValueExA": 7, "RegCreateKeyExA": 7,
    "CreateServiceA": 8, "StartServiceA": 7,
}

COMPLEXITY_INDICATORS = {
    "vtable_access": ["vfptr", "vtable", "__vftable"],
    "dynamic_dispatch": ["call_indirect", "indirect_call"],
    "crypto_operations": ["aes", "rsa", "rc4", "chacha"],
    "obfuscation": ["__obf", "decrypt_", "deobf"],
}


def get_import_addresses() -> set[int]:
    """Get all addresses that are imported functions."""
    imports = set()

    def import_cb(ea, name, ordinal):
        if ea != idaapi.BADADDR:
            imports.add(ea)
        return True

    for i in range(ida_nalt.get_import_module_qty()):
        ida_nalt.enum_import_names(i, import_cb)
    return imports


def get_data_refs_to(ea: int) -> list[int]:
    """Return data references to an address."""
    return list(idautils.DataRefsTo(ea))


def get_function_strings(func_ea: int) -> list[tuple[int, str]]:
    """Get strings referenced by this function."""
    strings = []
    for head in idautils.FuncItems(func_ea):
        for dref in idautils.DataRefsFrom(head):
            value = idc.get_strlit_contents(dref, -1, idc.STRTYPE_C)
            if value and len(value) >= 4:
                if isinstance(value, bytes):
                    value = value.decode("utf-8", errors="replace")
                strings.append((dref, str(value)))
    return strings


def get_callee_addresses(func_ea: int) -> list[int]:
    """Return direct callees for a function."""
    callees = []
    seen = set()
    for head in idautils.FuncItems(func_ea):
        for ref in idautils.CodeRefsFrom(head, 0):
            callee = ida_funcs.get_func(ref)
            if callee and callee.start_ea != func_ea and ref == callee.start_ea and callee.start_ea not in seen:
                seen.add(callee.start_ea)
                callees.append(callee.start_ea)
    return callees


def get_caller_addresses(func_ea: int) -> list[int]:
    """Return callers for a function."""
    callers = []
    seen = set()
    for xref in idautils.XrefsTo(func_ea, 0):
        caller = ida_funcs.get_func(xref.frm)
        if caller and caller.start_ea != func_ea and caller.start_ea not in seen:
            seen.add(caller.start_ea)
            callers.append(caller.start_ea)
    return callers


def should_collapse(func_ea: int, import_addrs: set[int]) -> tuple[bool, str]:
    """Determine if a function should be collapsed."""
    func = ida_funcs.get_func(func_ea)
    if func is None:
        return False, ""

    name = idc.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"
    size = func.end_ea - func.start_ea

    if name in ENTRY_POINTS:
        return False, ""
    if func.flags & idaapi.FUNC_LIB:
        return True, "library"
    if func.flags & idaapi.FUNC_THUNK:
        return True, "thunk"
    if func.start_ea in import_addrs:
        return True, "imported"

    for prefix in LIBRARY_PREFIXES:
        if name.startswith(prefix):
            return True, f"prefix:{prefix[:15]}"
    if name in LIBRARY_EXACT:
        return True, "known_runtime"
    if size <= 16 and len(list(idautils.FuncItems(func.start_ea))) <= 3:
        return True, "thunk"
    if not name.startswith("sub_") and size < 32:
        return True, "small_named"

    return False, ""


def score_function(func_ea: int) -> tuple[float, list[str], list[str]]:
    """Score a function's priority."""
    summary = get_function_summary(func_ea)
    score = 0.0
    reasons = []
    complexity = []

    string_score = 0
    for ref_ea, string_value in get_function_strings(func_ea):
        lowered = string_value.lower()
        keyword_match = False
        for keyword in SUSPICIOUS_STRING_KEYWORDS:
            if keyword in lowered:
                string_score += 3
                keyword_match = True
                if string_score <= 9:
                    reasons.append(f"str:'{keyword}'")
                break
        if keyword_match:
            xref_count = len(list(idautils.XrefsTo(ref_ea, 0)))
            if xref_count > 2:
                string_score += min(xref_count, 5)
    score += min(string_score, 35)

    api_score = 0
    for callee in summary["callees"]:
        callee_name = callee["name"]
        if callee_name in INTERESTING_APIS:
            api_score += INTERESTING_APIS[callee_name]
            reasons.append(f"api:{callee_name}")
    score += min(api_score, 30)

    caller_count = summary["caller_count"]
    callee_count = summary["callee_count"]
    if caller_count > 20 and api_score == 0 and string_score == 0:
        score -= 20
        reasons.append(f"penalty:{caller_count}_callers_no_signal")
    elif caller_count >= 10:
        score += 15
        reasons.append(f"hub:{caller_count}_callers")
    elif caller_count >= 5:
        score += 8
        reasons.append(f"popular:{caller_count}_callers")

    centrality = min(caller_count, 5) * 1.0 + min(callee_count, 10) * 0.5
    score += min(centrality, 10)

    data_refs = get_data_refs_to(func_ea)
    if data_refs:
        score += min(len(data_refs) * 3, 12)
        reasons.append(f"callback:{len(data_refs)}_ptrs")

    block_count = summary["basic_block_count"]
    if block_count > 5:
        score += min(block_count * 0.5, 15)
        if block_count > 20:
            complexity.append("complex_cfg")

    entropy = compute_function_entropy(func_ea)
    if entropy > 6.5:
        score += min((entropy - 6.0) * 5, 10)
        complexity.append("high_entropy")

    summary_text = str(summary).lower()
    for indicator_type, keywords in COMPLEXITY_INDICATORS.items():
        if any(keyword in summary_text for keyword in keywords):
            complexity.append(indicator_type)

    return round(score, 1), reasons, sorted(set(complexity))


def build_reachable_set(
    entry_addrs: list[int],
    collapsed_addrs: set[int],
    max_depth: int = 50,
) -> dict[int, dict]:
    """Build call graph from entry points, traversing through collapsed functions."""
    visited = {}
    traversed = set()
    queue = [(addr, 0) for addr in entry_addrs]

    while queue:
        addr, depth = queue.pop(0)
        if addr in traversed or depth > max_depth:
            continue
        traversed.add(addr)

        func = ida_funcs.get_func(addr)
        if func is None:
            continue

        all_callees = get_callee_addresses(func.start_ea)
        if func.start_ea not in collapsed_addrs:
            visited[func.start_ea] = {
                "name": idc.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}",
                "depth": depth,
                "callee_addrs": [ea for ea in all_callees if ea not in collapsed_addrs],
                "caller_addrs": [ea for ea in get_caller_addresses(func.start_ea) if ea not in collapsed_addrs],
            }

        for callee_addr in all_callees:
            if callee_addr not in traversed:
                queue.append((callee_addr, depth + 1))

    return visited


def find_callback_targets(collapsed_addrs: set[int]) -> list[int]:
    """Find functions referenced as data."""
    callbacks = []
    for func_ea in idautils.Functions():
        if func_ea in collapsed_addrs:
            continue
        if get_data_refs_to(func_ea):
            callbacks.append(func_ea)
    return callbacks


def topological_sort_callees_first(call_graph: dict[int, dict], scores: dict[int, float] = None) -> list[int]:
    """Sort so callees come before callers using score-based tie breaking."""
    out_degree = {
        addr: len([callee for callee in info["callee_addrs"] if callee in call_graph and callee != addr])
        for addr, info in call_graph.items()
    }

    def get_score(addr: int) -> float:
        return scores.get(addr, 0) if scores else 0

    ready = [addr for addr in call_graph if out_degree[addr] == 0]
    ready.sort(key=lambda addr: -get_score(addr))

    result = []
    processed = set()

    while ready:
        addr = ready.pop(0)
        if addr in processed:
            continue
        processed.add(addr)
        result.append(addr)

        for caller_addr, info in call_graph.items():
            if caller_addr in processed:
                continue
            if addr in info["callee_addrs"]:
                out_degree[caller_addr] -= 1
                if out_degree[caller_addr] <= 0 and caller_addr not in processed:
                    ready.append(caller_addr)
                    ready.sort(key=lambda item: -get_score(item))

    remaining = [addr for addr in call_graph if addr not in processed]
    remaining.sort(key=lambda addr: -get_score(addr))
    result.extend(remaining)
    return result


def prepare_analysis(max_functions: int = 100) -> dict:
    """Run the full preparation pipeline."""
    import_addrs = get_import_addresses()
    collapsed_addrs = set()
    collapse_reasons = {}

    for func_ea in idautils.Functions():
        if has_tag(func_ea, TAG_COLLAPSED):
            collapsed_addrs.add(func_ea)
            continue
        should, reason = should_collapse(func_ea, import_addrs)
        if should:
            tag_function(func_ea, TAG_COLLAPSED, reason)
            collapsed_addrs.add(func_ea)
            collapse_reasons[reason] = collapse_reasons.get(reason, 0) + 1

    for func_ea in idautils.Functions():
        if func_ea in collapsed_addrs or (idc.get_func_name(func_ea) or "") in ENTRY_POINTS:
            continue

        callers = get_caller_addresses(func_ea)
        callees = get_callee_addresses(func_ea)
        has_strings = bool(get_function_strings(func_ea))
        func = ida_funcs.get_func(func_ea)
        size = (func.end_ea - func.start_ea) if func else 0

        if len(callers) >= 15 and not has_strings:
            tag_function(func_ea, TAG_COLLAPSED, "high_fanin")
            collapsed_addrs.add(func_ea)
            collapse_reasons["high_fanin"] = collapse_reasons.get("high_fanin", 0) + 1
            continue

        if len(callers) >= 5 and not has_strings and size < 500:
            all_internal = all(
                callee in import_addrs or callee in collapsed_addrs or (idc.get_func_name(callee) or "").startswith("sub_")
                for callee in callees
            )
            if all_internal:
                tag_function(func_ea, TAG_COLLAPSED, "utility_internal")
                collapsed_addrs.add(func_ea)
                collapse_reasons["utility_internal"] = collapse_reasons.get("utility_internal", 0) + 1
                continue

        if callees and not has_strings and len(callers) >= 3:
            all_library = all(callee in import_addrs or callee in collapsed_addrs for callee in callees)
            if all_library:
                tag_function(func_ea, TAG_COLLAPSED, "transitive_library")
                collapsed_addrs.add(func_ea)
                collapse_reasons["transitive_library"] = collapse_reasons.get("transitive_library", 0) + 1

    scores = {}
    for func_ea in idautils.Functions():
        if func_ea in collapsed_addrs:
            continue

        score, reasons, complexity = score_function(func_ea)
        func = ida_funcs.get_func(func_ea)
        scores[func_ea] = {
            "score": score,
            "reasons": reasons,
            "complexity": complexity,
            "name": idc.get_func_name(func_ea) or f"sub_{func_ea:x}",
            "size": (func.end_ea - func.start_ea) if func else 0,
        }

        if complexity:
            tag_function(func_ea, TAG_NEEDS_CONTEXT, ",".join(complexity))

    entry_info = get_entry_points()
    entry_addrs = [int(item["address"], 16) for item in entry_info]
    callback_addrs = find_callback_targets(collapsed_addrs)
    entry_addrs = list(set(entry_addrs + callback_addrs))

    if not entry_addrs:
        top_by_score = sorted(scores.items(), key=lambda item: -item[1]["score"])[:5]
        entry_addrs = [addr for addr, _ in top_by_score]

    reachable = build_reachable_set(entry_addrs, collapsed_addrs)
    score_map = {addr: info["score"] for addr, info in scores.items()}
    ordered_addrs = topological_sort_callees_first(reachable, score_map)

    final_order = []
    for addr in ordered_addrs:
        if addr not in scores:
            continue
        info = scores[addr]
        final_order.append({
            "address": hex(addr),
            "name": info["name"],
            "score": info["score"],
            "depth": reachable.get(addr, {}).get("depth", 0),
            "reasons": info["reasons"],
            "complexity": info["complexity"],
            "size": info["size"],
        })

    final_order = final_order[:max_functions]
    for priority, entry in enumerate(final_order):
        tag_function(int(entry["address"], 16), TAG_INTERESTING, f"priority:{priority}")

    callback_info = [
        {"address": hex(addr), "name": idc.get_func_name(addr) or f"sub_{addr:x}"}
        for addr in callback_addrs
    ]

    return {
        "summary": {
            "total_functions": len(list(idautils.Functions())),
            "collapsed": len(collapsed_addrs),
            "scored": len(scores),
            "callbacks_detected": len(callback_addrs),
            "reachable_from_entry": len(reachable),
            "ordered_for_analysis": len(final_order),
        },
        "collapse_reasons": collapse_reasons,
        "entry_points": entry_info,
        "callbacks": callback_info,
        "analysis_order": final_order,
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ida_python prepare_analysis.py <binary_or_idb> [--max N] [--save-as PATH] [--output JSON]")
        sys.exit(1)

    binary_path = sys.argv[1]
    max_functions = 100
    if "--max" in sys.argv:
        idx = sys.argv.index("--max")
        max_functions = int(sys.argv[idx + 1])

    load_binary(binary_path)
    metadata = get_binary_metadata()
    print(f"Loaded: {metadata['filename']} ({metadata['architecture']})")
    print(f"Total functions: {metadata['total_functions']}")
    print()

    result = prepare_analysis(max_functions=max_functions)
    summary = result["summary"]
    print(f"Stage 1 - Collapsed: {summary['collapsed']}")
    print(f"Stage 2 - Scored: {summary['scored']}")
    print(f"Stage 3 - Reachable from entry: {summary['reachable_from_entry']}")
    print(f"Stage 4+5 - Ordered for analysis: {summary['ordered_for_analysis']}")

    print("\nEntry points:")
    for ep in result["entry_points"][:5]:
        print(f"  {ep['name']} @ {ep['address']}")

    if result["callbacks"]:
        print(f"\nCallbacks detected: {len(result['callbacks'])}")
        for cb in result["callbacks"][:5]:
            print(f"  {cb['name']} @ {cb['address']}")

    print("\nTop 10 functions to analyze:")
    for i, entry in enumerate(result["analysis_order"][:10]):
        complexity = f" [{','.join(entry['complexity'])}]" if entry["complexity"] else ""
        print(f"  {i + 1:2d}. {entry['name']} (score={entry['score']}, depth={entry['depth']}){complexity}")

    output_idb = binary_path
    if "--save-as" in sys.argv:
        idx = sys.argv.index("--save-as")
        output_idb = sys.argv[idx + 1]
    elif not binary_path.endswith((".idb", ".i64")):
        output_idb = binary_path + ".i64"
    save_database(output_idb)
    print(f"\nIDB saved to: {output_idb}")

    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        output_json = sys.argv[idx + 1]
        with open(output_json, "w") as f:
            json.dump(result, f, indent=2)
        print(f"JSON saved to: {output_json}")
