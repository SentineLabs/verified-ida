"""Shared analyst-facing IDA capability catalog.

The workbench prompts, validators, and IDA query runner should expose the same
small vocabulary.  Legacy harness task names remain accepted as aliases so old
manifests and model habits keep working while new prompts use clearer analyst
verbs.
"""

from __future__ import annotations

from typing import Any


ANALYST_CAPABILITIES: tuple[dict[str, Any], ...] = (
    {
        "name": "inspect_function",
        "description": "Render pseudocode, disassembly summaries, calls, refs, strings, and visible locals for a function.",
        "aliases": (
            "analyze_function",
            "render_function_context",
            "decompile",
            "decompile_function",
            "pseudocode",
            "render_pseudocode",
            "function",
            "inspect_callee",
            "inspect_caller",
            "inspect_helper",
            "disassemble_function",
        ),
        "requires_target": True,
        "example": {"task_type": "inspect_function", "target": "0x401000"},
    },
    {
        "name": "inspect_function_identity",
        "description": "Return function boundaries and a byte hash without decompiling the function.",
        "aliases": ("function_identity",),
        "requires_target": True,
        "example": {
            "task_type": "inspect_function_identity",
            "target": "0x401000",
        },
    },
    {
        "name": "retrieve_disassembly",
        "description": "Render bounded IDA disassembly for a function without invoking Hex-Rays.",
        "aliases": ("disassembly", "render_disassembly"),
        "requires_target": True,
        "example": {"task_type": "retrieve_disassembly", "target": "0x401000"},
    },
    {
        "name": "inspect_cfg",
        "description": "Render bounded basic blocks, control-flow edges, and instructions for a function.",
        "aliases": ("render_cfg", "render_basic_blocks"),
        "requires_target": True,
        "example": {"task_type": "inspect_cfg", "target": "0x401000"},
    },
    {
        "name": "retrieve_pseudocode",
        "description": "Request bounded Hex-Rays pseudocode for a function as a secondary, best-effort representation.",
        "aliases": (),
        "requires_target": True,
        "example": {
            "task_type": "retrieve_pseudocode",
            "target": "0x401000",
            "reason": "Resolve the remaining ownership and argument-flow question.",
        },
    },
    {
        "name": "inspect_ctree_summary",
        "description": "Summarize Hex-Rays ctree operations for a function.",
        "aliases": ("summarize_ctree", "render_ctree_summary", "ctree_summary"),
        "requires_target": True,
        "example": {"task_type": "inspect_ctree_summary", "target": "0x401000"},
    },
    {
        "name": "inspect_callers",
        "description": "Find functions and callsites that call the target function.",
        "aliases": ("callers", "caller", "callers_of"),
        "requires_target": True,
        "example": {"task_type": "inspect_callers", "target": "0x401000"},
    },
    {
        "name": "inspect_callees",
        "description": "Find functions called by the target function.",
        "aliases": ("callees", "callee", "callees_of"),
        "requires_target": True,
        "example": {"task_type": "inspect_callees", "target": "0x401000"},
    },
    {
        "name": "inspect_call_graph",
        "description": "Expand a bounded caller/callee neighborhood around a function.",
        "aliases": (
            "calls",
            "callgraph",
            "call_graph",
            "query_callers_callees",
            "callers_callees",
            "expand_call_graph",
        ),
        "requires_target": True,
        "example": {"task_type": "inspect_call_graph", "target": "0x401000", "depth": 1},
    },
    {
        "name": "inspect_callsite_arguments",
        "description": "Inspect arguments and local context at a specific callsite.",
        "aliases": ("callsite_args", "query_callsite_arguments"),
        "requires_target": True,
        "example": {"task_type": "inspect_callsite_arguments", "target": "0x401234"},
    },
    {
        "name": "inspect_xrefs",
        "description": "List code and data cross-references to and from an address.",
        "aliases": ("xrefs", "xrefs_to", "xrefs_from", "query_xrefs", "refs"),
        "requires_target": True,
        "example": {"task_type": "inspect_xrefs", "target": "0x46dbb4"},
    },
    {
        "name": "inspect_data_refs",
        "description": "List data references used by a function or address.",
        "aliases": ("data_refs", "query_data_refs"),
        "requires_target": True,
        "example": {"task_type": "inspect_data_refs", "target": "0x401000"},
    },
    {
        "name": "inspect_data_object",
        "description": "Render bytes, names, comments, and decoded values for a data object.",
        "aliases": (
            "data",
            "inspect_data",
            "data_object",
            "render_data_object",
            "global",
            "global_object",
        ),
        "requires_target": True,
        "example": {"task_type": "inspect_data_object", "target": "0x46dbb4", "size": 256},
    },
    {
        "name": "inspect_global_users",
        "description": "Inspect a global or data object and the functions that reference it.",
        "aliases": ("global_users", "global_xrefs", "users_of_global", "inspect_global", "xrefs_to_global"),
        "requires_target": True,
        "example": {"task_type": "inspect_global_users", "target": "0x46dbb4"},
    },
    {
        "name": "inspect_function_pointer_refs",
        "description": "Find data references that point at a function pointer target, including nearby table rows.",
        "aliases": ("function_pointer_refs", "funcptr_refs", "render_function_pointer_refs"),
        "requires_target": True,
        "example": {"task_type": "inspect_function_pointer_refs", "target": "0x401000"},
    },
    {
        "name": "inspect_vtable_or_indirect_call",
        "description": "Best-effort inspection of a vtable-like object, function-pointer table, or indirect callsite, including architecture-aware contiguous slot decoding and pointer-table neighborhood context.",
        "aliases": (
            "vtable",
            "vtable_inspect",
            "inspect_vtable",
            "indirect_call",
            "resolve_indirect_caller",
            "resolve_virtual_call",
        ),
        "requires_target": True,
        "example": {"task_type": "inspect_vtable_or_indirect_call", "target": "0x401234"},
    },
    {
        "name": "inspect_stack_frame",
        "description": "Render a function stack frame, visible arguments, locals, and frame members.",
        "aliases": ("stack", "stack_frame", "render_stack_frame"),
        "requires_target": True,
        "example": {"task_type": "inspect_stack_frame", "target": "0x401000"},
    },
    {
        "name": "infer_struct_layout",
        "description": "Collect function/data evidence useful for inferring a struct layout.",
        "aliases": (
            "struct",
            "infer_struct",
            "struct_reconstruct",
            "struct_reconstruction",
            "reconstruct_struct",
            "infer_layout",
            "scan_struct_offsets",
        ),
        "requires_target": True,
        "example": {"task_type": "infer_struct_layout", "target": "0x401000"},
    },
    {
        "name": "search_names",
        "description": "Search or list IDA names and known types.",
        "aliases": ("names", "types", "names_types", "render_names_types", "render_names", "render_types"),
        "requires_target": False,
        "example": {"task_type": "search_names", "prefix": "Queue"},
    },
    {
        "name": "inspect_idb_meta",
        "description": "Render IDB metadata, input path, processor, image base, entry point, analysis status, and coarse counts.",
        "aliases": ("idb_meta", "metadata", "analysis_status", "database_info"),
        "requires_target": False,
        "example": {"task_type": "inspect_idb_meta"},
    },
    {
        "name": "list_functions",
        "description": "List functions with addresses, names, sizes, flags, segments, and optional name prefix filtering.",
        "aliases": ("functions", "enumerate_functions", "function_list", "paged_functions"),
        "requires_target": False,
        "example": {"task_type": "list_functions", "prefix": "Process"},
    },
    {
        "name": "inspect_addr",
        "description": "Inspect an address with segment, name, type, comments, bytes, function ownership, and xrefs.",
        "aliases": (
            "addr_info",
            "address_info",
            "inspect_address",
            "inspect_instruction_context",
        ),
        "requires_target": True,
        "example": {"task_type": "inspect_addr", "target": "0x401000"},
    },
    {
        "name": "inspect_bytes",
        "description": "Read a bounded byte range for static decoding or host-side emulation.",
        "aliases": ("bytes", "read_bytes", "render_bytes"),
        "requires_target": True,
        "example": {"task_type": "inspect_bytes", "target": "0x401000", "size": 128},
    },
    {
        "name": "list_exports",
        "description": "List IDA/PE exports with ordinals, addresses, names, and function ownership.",
        "aliases": ("exports", "render_exports", "inspect_exports"),
        "requires_target": False,
        "example": {"task_type": "list_exports"},
    },
    {
        "name": "list_entrypoints",
        "description": "List IDA entry points including the image start and exported function entry points.",
        "aliases": ("entrypoints", "entry_points", "render_entrypoints", "inspect_entrypoints"),
        "requires_target": False,
        "example": {"task_type": "list_entrypoints"},
    },
    {
        "name": "list_globals",
        "description": "List named non-function globals/data items with type, segment, comments, and xref counts.",
        "aliases": ("globals", "global_list", "list_data_names", "named_globals"),
        "requires_target": False,
        "example": {"task_type": "list_globals", "prefix": "g_"},
    },
    {
        "name": "list_local_types",
        "description": "List IDA local named structs/enums/typedefs when local type information is available.",
        "aliases": ("local_types", "types_local", "list_types"),
        "requires_target": False,
        "example": {"task_type": "list_local_types", "prefix": "Object"},
    },
    {
        "name": "inspect_struct",
        "description": "Look up one exact, case-sensitive local type name and inspect its native kind and members.",
        "aliases": ("struct_info", "type_info", "inspect_type"),
        "requires_target": True,
        "example": {"task_type": "inspect_struct", "target": "ObjectContext"},
    },
    {
        "name": "read_struct",
        "description": "Read IDA's native declaration for an exact local type name, preserving unions and aliases.",
        "aliases": ("read_type", "render_struct", "struct_declaration"),
        "requires_target": True,
        "example": {"task_type": "read_struct", "target": "ObjectContext"},
    },
    {
        "name": "xrefs_to_field",
        "description": "Scan for a byte offset in decoded memory displacements. Separate native structure-offset bindings from unbound candidates; check scan completeness and verify candidate object identity.",
        "aliases": ("field_xrefs", "xrefs_to_struct_field", "xrefs_to_member"),
        "requires_target": True,
        "example": {"task_type": "xrefs_to_field", "target": "ObjectContext", "offset": "0x28"},
    },
    {
        "name": "find_paths",
        "description": "Find bounded caller/callee graph paths between source and target functions.",
        "aliases": ("path_finding", "find_call_paths", "call_paths"),
        "requires_target": True,
        "example": {"task_type": "find_paths", "source": "0x401000", "target": "0x402000"},
    },
    {
        "name": "search_strings",
        "description": "Search or list strings in the IDB.",
        "aliases": ("strings", "render_strings"),
        "requires_target": False,
        "example": {"task_type": "search_strings", "target": "mutex"},
    },
    {
        "name": "search_constants",
        "description": "Search for immediate constants across code.",
        "aliases": ("search_constant", "constant"),
        "requires_target": True,
        "example": {"task_type": "search_constants", "target": "0x1000"},
    },
    {
        "name": "search_instructions",
        "description": "Search disassembly text or mnemonics across functions.",
        "aliases": ("instruction_search", "search_disasm", "search_mnemonics"),
        "requires_target": False,
        "example": {"task_type": "search_instructions", "target": "call eax"},
    },
    {
        "name": "convert_int",
        "description": "Convert an integer value across hex, decimal, signed, bytes, ASCII, and bit views.",
        "aliases": ("int_convert", "integer_conversion", "number_info"),
        "requires_target": True,
        "example": {"task_type": "convert_int", "target": "0x467d1c"},
    },
    {
        "name": "run_readonly_report",
        "description": "Run a named, bounded, read-only analyst report template and return JSON evidence.",
        "aliases": ("readonly_report", "run_report", "analyst_report"),
        "requires_target": False,
        "example": {"task_type": "run_readonly_report", "report": "vtable_family_scan", "target": "0x42c810"},
    },
    {
        "name": "inspect_imports",
        "description": "List imported APIs and modules.",
        "aliases": ("imports", "render_imports"),
        "requires_target": False,
        "example": {"task_type": "inspect_imports", "target": "ws2_32"},
    },
    {
        "name": "inspect_segments",
        "description": "List IDB segments and address ranges.",
        "aliases": ("segments", "render_segments"),
        "requires_target": False,
        "example": {"task_type": "inspect_segments"},
    },
    {
        "name": "inspect_pe_inventory",
        "description": "Render bounded PE inventory metadata.",
        "aliases": ("pe_inventory", "render_pe_inventory"),
        "requires_target": False,
        "example": {"task_type": "inspect_pe_inventory"},
    },
)


_CAPABILITY_BY_NAME = {item["name"]: item for item in ANALYST_CAPABILITIES}
_ALIAS_TO_NAME: dict[str, str] = {}
for capability in ANALYST_CAPABILITIES:
    name = capability["name"]
    _ALIAS_TO_NAME[name] = name
    for alias in capability.get("aliases") or ():
        _ALIAS_TO_NAME[str(alias)] = name


def canonical_capability_names() -> list[str]:
    """Return model-facing canonical capability names."""

    return [item["name"] for item in ANALYST_CAPABILITIES]


def capability_aliases() -> dict[str, str]:
    """Return alias-to-canonical mappings."""

    return dict(_ALIAS_TO_NAME)


def normalize_capability_name(name: str | None) -> str | None:
    """Normalize an analyst capability or legacy query name."""

    text = str(name or "").strip()
    if not text:
        return None
    return _ALIAS_TO_NAME.get(text)


def capability_requires_target(name: str | None) -> bool:
    """Return whether a canonical or alias task requires a target address/value."""

    canonical = normalize_capability_name(name)
    if not canonical:
        return True
    return bool(_CAPABILITY_BY_NAME[canonical].get("requires_target", True))


def capability_schema_enum() -> list[str]:
    """Return schema enum values for model-facing task types."""

    return canonical_capability_names()


def capability_prompt_catalog(
    evidence_representation_policy: str = "pseudocode_first",
) -> list[dict[str, Any]]:
    """Return a compact model-visible catalog."""

    catalog = []
    for capability in ANALYST_CAPABILITIES:
        description = capability["description"]
        aliases = list(capability.get("aliases") or ())[:8]
        example = capability.get("example") or {}
        if (
            evidence_representation_policy == "disassembly_first"
            and capability["name"] == "inspect_function"
        ):
            description = (
                "Inspect bounded disassembly, control flow, calls, references, "
                "strings, and low-level function evidence without Hex-Rays pseudocode."
            )
            aliases = [
                alias
                for alias in aliases
                if alias
                not in {
                    "decompile",
                    "decompile_function",
                    "pseudocode",
                    "render_pseudocode",
                }
            ]
        if (
            evidence_representation_policy == "disassembly_first"
            and capability["name"] == "retrieve_pseudocode"
        ):
            description = (
                "Request bounded Hex-Rays pseudocode only after inspecting that "
                "function's disassembly or CFG; include a short reason naming the "
                "unresolved question."
            )
        catalog.append({
            "task_type": capability["name"],
            "description": description,
            "aliases_accepted": aliases,
            "requires_target": bool(capability.get("requires_target", True)),
            "example": example,
        })
    return catalog
