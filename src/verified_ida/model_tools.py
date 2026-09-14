"""Compact model-facing tool contract for a Verified IDA investigation.

The model supplies semantic intent and opaque references.  The host binds
database identity, live target anchors, operation identifiers, and receipts.
No model-authored JSON proposal or campaign ledger is required.
"""

from __future__ import annotations

from typing import Any

from .contracts import MODEL_MUTATION_CONTRACTS
from .workspace import (
    CURRENT_STATE_SECTIONS,
    DEFAULT_JOURNAL_LIMIT,
    MAX_JOURNAL_ENTRY_BYTES,
    MAX_JOURNAL_LIMIT,
    MAX_JOURNAL_TITLE_BYTES,
    MAX_SECTION_BYTES,
)


IDAPYTHON_TOPICS = [
    "catalogs",
    "decompiler",
    "functions",
    "instructions",
    "metadata",
    "references",
    "types",
]

READ_ONLY_QUERY_LIMITS = {
    "inspect_idb_meta": 200,
    "list_functions": 1000,
    "inspect_addr": 200,
    "list_exports": 1000,
    "list_entrypoints": 1000,
    "list_globals": 1000,
    "list_local_types": 1000,
    "inspect_struct": 400,
    "read_struct": 400,
    "xrefs_to_field": 200,
    "find_paths": 100,
    "inspect_bytes": 400,
    "inspect_cfg": 200,
    "inspect_function_identity": 20,
    "inspect_function": 120,
    "inspect_ctree_summary": 200,
    "inspect_data_object": 400,
    "infer_struct_layout": 200,
    "inspect_xrefs": 200,
    "inspect_data_refs": 200,
    "retrieve_pseudocode": 400,
    "retrieve_disassembly": 400,
    "inspect_callers": 200,
    "inspect_callees": 200,
    "query_callers_callees": 200,
    "inspect_call_graph": 200,
    "inspect_callsite_arguments": 100,
    "query_hook_entry_contract": 100,
    "render_switch_table": 200,
    "discover_enum_candidates": 200,
    "inspect_imports": 1000,
    "search_strings": 400,
    "inspect_function_pointer_refs": 200,
    "inspect_global_users": 200,
    "inspect_vtable_or_indirect_call": 200,
    "inspect_stack_frame": 160,
    "inspect_pe_inventory": 400,
    "inspect_segments": 200,
    "search_names": 400,
    "search_bytes": 400,
    "extract_resource_or_overlay": 400,
    "search_constants": 400,
    "search_instructions": 400,
    "convert_int": 20,
    "run_readonly_report": 200,
}
READ_ONLY_QUERIES = frozenset(READ_ONLY_QUERY_LIMITS)

# The worker also serves these host-built typed queries. Reuse the public
# catalog so adding a model query cannot silently bypass the worker boundary.
READ_ONLY_SESSION_QUERIES = READ_ONLY_QUERIES | frozenset({
    "describe_query_runtime", "survey_idb", "query_functions", "query_symbols",
    "query_strings", "query_types", "inspect_function_summary",
    "inspect_direct_call_edges",
})
RESERVED_QUERY_OPTIONS = frozenset({
    "task_type", "kind", "target", "address", "value", "limit",
    "component_id", "artifact", "project_id", "revision",
})


ADDRESS = {
    "oneOf": [
        {"type": "integer", "minimum": 0},
        {"type": "string", "pattern": "^(0[xX][0-9a-fA-F]+|[0-9]+)$"},
    ]
}

SOURCE_LOCATOR = {
    "oneOf": [
        {
            "type": "object",
            "required": ["kind", "ea", "size"],
            "properties": {
                "kind": {"const": "idb_ea"},
                "ea": ADDRESS,
                "size": {"type": "integer", "minimum": 1},
            },
            "additionalProperties": False,
        },
        {
            "type": "object",
            "required": ["kind", "file_offset", "size"],
            "properties": {
                "kind": {"const": "file_offset"},
                "file_offset": ADDRESS,
                "size": {"type": "integer", "minimum": 1},
            },
            "additionalProperties": False,
        },
    ],
}


def model_tool_declarations() -> list[dict[str, Any]]:
    """Return the complete narrow schema shown to the model by the SDK."""

    reference = {"type": "string", "minLength": 1}
    component = {"type": ["string", "null"], "default": None}
    evidence = {
        "type": "array",
        "items": {"type": "string", "minLength": 1},
        "uniqueItems": True,
        "default": [],
    }
    return [
        {
            "name": "read_reversing_log",
            "description": (
                "Read every current project-state section plus a bounded page "
                "of recent investigation-journal entries. Use next_cursor to "
                "page backward through older entries. Issued notebook_ref values "
                "belong in review notebook_refs; they prove what was recorded, "
                "not binary behavior, and cannot support IDA edits."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "journal_limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_JOURNAL_LIMIT,
                        "default": DEFAULT_JOURNAL_LIMIT,
                    },
                    "journal_cursor": {"type": ["string", "null"]},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "update_reversing_log_section",
            "description": (
                "Replace one protected Current Project State section with exact "
                "model-authored Markdown. H1/H2/H3 headings are host-owned; use "
                "H4 for ordinary subheadings. Pass the digest returned by the "
                "latest read to prevent stale overwrites. Write component-qualified "
                "function addresses canonically as `component::0xADDRESS` (for "
                "example, `root::0x180010000`)."
            ),
            "input_schema": {
                "type": "object",
                "required": ["section", "content", "expected_digest"],
                "properties": {
                    "section": {"enum": list(CURRENT_STATE_SECTIONS)},
                    "content": {
                        "type": "string",
                        "maxLength": MAX_SECTION_BYTES,
                    },
                    "expected_digest": {
                        "type": "string",
                        "pattern": "^[a-f0-9]{64}$",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "append_reversing_log_journal",
            "description": (
                "Append one material discovery, revision, rejected hypothesis, "
                "component decision, or analytically significant recovery to the "
                "Investigation Journal. Pass the current journal digest to "
                "prevent concurrent stale appends."
            ),
            "input_schema": {
                "type": "object",
                "required": ["title", "content", "expected_journal_digest"],
                "properties": {
                    "title": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_JOURNAL_TITLE_BYTES,
                    },
                    "content": {
                        "type": "string",
                        "maxLength": MAX_JOURNAL_ENTRY_BYTES,
                    },
                    "expected_journal_digest": {
                        "type": "string",
                        "pattern": "^[a-f0-9]{64}$",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "describe_ida_capabilities",
            "description": (
                "Return the active backend/version, architecture, typed query "
                "families, exact filters and ordering, page limits, supported "
                "mutations, and backend extensions."
            ),
            "input_schema": {"type": "object", "additionalProperties": False},
        },
        {
            "name": "survey_idb",
            "description": (
                "Return a compact IDA-like overview: artifact identity, binary "
                "format and architecture, inventory counts, segments, imports "
                "by module, and analysis/decompiler availability."
            ),
            "input_schema": {
                "type": "object",
                "properties": {"component_id": component},
                "additionalProperties": False,
            },
        },
        {
            "name": "query_ida_functions",
            "description": (
                "Query functions with explicit filters. Returns a uniform page "
                "with exact total, returned count, has_more, and a revision-bound cursor."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "segment": {"type": ["string", "null"]},
                    "name_class": {"enum": ["all", "anonymous", "named"]},
                    "name_prefix": {"type": ["string", "null"]},
                    "address_start": {"anyOf": [ADDRESS, {"type": "null"}]},
                    "address_end": {"anyOf": [ADDRESS, {"type": "null"}]},
                    "minimum_size": {"type": ["integer", "null"], "minimum": 0},
                    "maximum_size": {"type": ["integer", "null"], "minimum": 0},
                    "minimum_callers": {"type": ["integer", "null"], "minimum": 0},
                    "minimum_callees": {"type": ["integer", "null"], "minimum": 0},
                    "minimum_xrefs": {"type": ["integer", "null"], "minimum": 0},
                    "has_comment": {"type": ["boolean", "null"]},
                    "has_prototype": {"type": ["boolean", "null"]},
                    "order": {
                        "enum": ["address", "name", "size_ascending", "size_descending"]
                    },
                    "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                    "cursor": {"type": ["string", "null"]},
                    "component_id": component,
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "query_ida_symbols",
            "description": (
                "Query names, imports, exports, entrypoints, or globals with a "
                "uniform exact-total page and revision-bound continuation cursor."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "kind": {"enum": ["names", "imports", "exports", "entrypoints", "globals"]},
                    "name_prefix": {"type": ["string", "null"]},
                    "module": {"type": ["string", "null"]},
                    "segment": {"type": ["string", "null"]},
                    "order": {"enum": ["address", "name"]},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                    "cursor": {"type": ["string", "null"]},
                    "component_id": component,
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "query_ida_strings",
            "description": (
                "Query detected strings with explicit filters and a uniform "
                "exact-total page with a revision-bound continuation cursor."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "needle": {"type": ["string", "null"]},
                    "segment": {"type": ["string", "null"]},
                    "minimum_length": {"type": ["integer", "null"], "minimum": 0},
                    "referenced": {"type": ["boolean", "null"]},
                    "order": {"enum": ["address", "length_descending", "text"]},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                    "cursor": {"type": ["string", "null"]},
                    "component_id": component,
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "query_ida_types",
            "description": (
                "Query local named types with explicit filters and a "
                "uniform page with a revision-bound continuation cursor. "
                "An incomplete scan reports a lower-bound total, not absence."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "kind": {"enum": ["all", "struct", "union", "enum", "typedef"]},
                    "name_prefix": {"type": ["string", "null"]},
                    "order": {"enum": ["name", "kind"]},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                    "cursor": {"type": ["string", "null"]},
                    "component_id": component,
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "inspect_ida_function",
            "description": (
                "Inspect neutral function metadata, relationships, referenced "
                "strings/globals/imports, CFG summary, and code availability. "
                "Does not return pseudocode or disassembly implicitly."
            ),
            "input_schema": {
                "type": "object",
                "required": ["address"],
                "properties": {"address": ADDRESS},
                "additionalProperties": False,
            },
        },
        {
            "name": "read_ida_function_code",
            "description": (
                "Explicitly read disassembly or pseudocode for an inspected "
                "function using a uniform revision-bound paging contract."
            ),
            "input_schema": {
                "type": "object",
                "required": ["function_ref", "representation"],
                "properties": {
                    "function_ref": reference,
                    "representation": {"enum": ["disassembly", "pseudocode"]},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                    "cursor": {"type": ["string", "null"]},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "inspect_ida",
            "description": (
                "Run one bounded read-only IDA query. Returns the evidence and, "
                "when the target is editable, a host-issued opaque reference. "
                "Choose the exact query identifier from the schema; do not write "
                "a natural-language query. The legacy inspect_function query may "
                "include pseudocode; for representation-controlled function review, "
                "use inspect_ida_function followed by read_ida_function_code."
            ),
            "input_schema": {
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": {"enum": sorted(READ_ONLY_QUERIES)},
                    "target": {"anyOf": [ADDRESS, {"type": "string"}]},
                    "component_id": component,
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
                    "offset": {"type": "integer", "minimum": 0, "default": 0},
                    "options": {
                        "type": "object", "default": {},
                        "description": (
                            "Query-specific options such as size, depth, or prefix. "
                            "Set query, target, component_id, and limit in their "
                            "top-level fields; options cannot override host dispatch "
                            "or artifact identity."
                        ),
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "inspect_ida_local",
            "description": "Inspect and bind one current Hex-Rays local or parameter.",
            "input_schema": {
                "type": "object",
                "required": ["function_ref"],
                "properties": {
                    "function_ref": reference,
                    "current_name": {"type": ["string", "null"]},
                    "lvar_index": {"type": ["integer", "null"], "minimum": 0},
                },
                "anyOf": [
                    {"required": ["current_name"]},
                    {"required": ["lvar_index"]},
                ],
                "additionalProperties": False,
            },
        },
        {
            "name": "describe_idapython_capabilities",
            "description": (
                "Describe the exact version-matched read-only IDAPython helpers, "
                "allowlisted raw APIs, examples, and resource limits. Use this "
                "before run_idapython_readonly when normal IDA queries cannot "
                "express a sample-specific aggregate question."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "topic": {
                        "anyOf": [
                            {"enum": IDAPYTHON_TOPICS},
                            {"type": "null"},
                        ],
                        "default": None,
                    }
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "run_idapython_readonly",
            "description": (
                "Run one validated, bounded aggregate IDAPython query against a "
                "disposable copy of the current IDB. The script receives params, "
                "the documented verified helper, and allowlisted read-only IDA "
                "module proxies; it must assign JSON-compatible result. Durable "
                "changes are impossible here and must use edit_ida."
            ),
            "input_schema": {
                "type": "object",
                "required": ["source", "purpose", "capability_gap"],
                "properties": {
                    "source": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 32768,
                    },
                    "parameters": {"type": "object", "default": {}},
                    "purpose": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 1000,
                    },
                    "capability_gap": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 1000,
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "inspect_ida_relationship",
            "description": "Bind a direct relationship between two inspected functions.",
            "input_schema": {
                "type": "object",
                "required": ["source_ref", "destination_ref", "relationship_kind"],
                "properties": {
                    "source_ref": reference,
                    "destination_ref": reference,
                    "relationship_kind": {"type": "string", "minLength": 1},
                    "callsite_address": {
                        "type": "string",
                        "pattern": "^(?:0[xX][0-9A-Fa-f]+|[0-9]+)$",
                        "description": (
                            "Optional exact call instruction. Required only when "
                            "the source calls the destination at multiple sites."
                        ),
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "edit_ida",
            "description": (
                "Apply one semantic edit to an inspected target. The host returns "
                "a compact verified result, refreshed references, and local gaps. "
                "References expire when their component revision changes; use "
                "the latest refreshed reference or inspect again. Additional "
                "evidence_refs must identify current inspections, including "
                "when supporting evidence comes from another function/component. "
                "Consult describe_ida_capabilities.mutation_contracts for the "
                "required value fields and target-reference source for each kind."
            ),
            "input_schema": {
                "type": "object",
                "required": ["target_ref", "kind", "value"],
                "properties": {
                    "target_ref": reference,
                    "kind": {
                        "enum": list(MODEL_MUTATION_CONTRACTS),
                    },
                    "value": {
                        "type": "object",
                        "minProperties": 1,
                        "description": (
                            "Kind-specific semantic fields. Required fields are "
                            "advertised by describe_ida_capabilities. Common forms: "
                            "{name}, {comment}, {declaration}, "
                            "{type_kind,declaration}, or {description}."
                        ),
                        "properties": {
                            "name": {"type": "string"},
                            "comment": {"type": "string"},
                            "repeatable": {"type": "boolean"},
                            "declaration": {"type": "string"},
                            "type_kind": {
                                "enum": ["struct", "union", "enum", "typedef"]
                            },
                            "description": {"type": "string"},
                            "flow": {"type": "string"},
                            "ownership": {"type": "string"},
                        },
                        "additionalProperties": False,
                    },
                    "evidence_refs": evidence,
                    "reason": {"type": ["string", "null"]},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "inspect_ida_operation",
            "description": (
                "Retrieve the complete stored request and receipt history for one "
                "operation when the compact edit result is insufficient."
            ),
            "input_schema": {
                "type": "object",
                "required": ["operation_id"],
                "properties": {
                    "operation_id": {"type": "string", "minLength": 1},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "review_ida_frontier",
            "description": (
                "Review one bounded collection. must_review contains blocking direct "
                "closure checks caused by deliberate edits; suggested_next contains "
                "nonblocking navigation and discovery hints."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "collection": {
                        "enum": ["must_review", "suggested_next"],
                        "default": "must_review",
                    },
                    "component_id": component,
                    "limit": {"type": "integer", "minimum": 1, "maximum": 20},
                    "offset": {"type": "integer", "minimum": 0},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "disposition_ida_candidate",
            "description": (
                "Record an evidence-backed outcome using an exact-target inspection "
                "from the candidate component's current database revision."
            ),
            "input_schema": {
                "type": "object",
                "required": ["candidate_id", "outcome", "rationale", "evidence_refs"],
                "properties": {
                    "candidate_id": {"type": "string", "minLength": 1},
                    "outcome": {
                        "enum": ["addressed", "nonmaterial", "deferred", "uncertain"]
                    },
                    "rationale": {"type": "string", "minLength": 1},
                    "evidence_refs": evidence,
                    "operation_ids": {
                        "type": "array",
                        "items": {"type": "string", "minLength": 1},
                        "uniqueItems": True,
                        "default": [],
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "read_ida_reconciliation",
            "description": (
                "Read the current bounded coverage-reconciliation wave. Findings "
                "were selected from a frozen read-only project review and must be "
                "verified against live IDA before disposition."
            ),
            "input_schema": {"type": "object", "additionalProperties": False},
        },
        {
            "name": "open_ida_reconciliation_call_flow",
            "description": (
                "For one active reconciliation finding, open a mandatory depth-first "
                "scope over exact IDA-native direct callees named by that finding. "
                "Ordinary edits cannot open this scope."
            ),
            "input_schema": {
                "type": "object",
                "required": ["finding_id", "root_address", "boundary_callees"],
                "properties": {
                    "finding_id": {"type": "string", "minLength": 1},
                    "root_address": ADDRESS,
                    "boundary_callees": {
                        "type": "array",
                        "items": ADDRESS,
                        "minItems": 1,
                        "uniqueItems": True,
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "disposition_ida_reconciliation_finding",
            "description": (
                "Close or narrow one finding in the current reconciliation wave. "
                "Applied requires verified operations or a closed linked call-flow "
                "scope; rejected and deferred preserve the evidence-backed rationale."
            ),
            "input_schema": {
                "type": "object",
                "required": [
                    "finding_id", "outcome", "rationale", "evidence_refs"
                ],
                "properties": {
                    "finding_id": {"type": "string", "minLength": 1},
                    "outcome": {
                        "enum": ["applied", "rejected", "revised", "deferred"]
                    },
                    "rationale": {"type": "string", "minLength": 1},
                    "evidence_refs": {
                        "type": "array",
                        "items": {"type": "string", "minLength": 1},
                        "minItems": 1,
                        "uniqueItems": True,
                    },
                    "operation_ids": {
                        "type": "array",
                        "items": {"type": "string", "minLength": 1},
                        "uniqueItems": True,
                        "default": [],
                    },
                    "revised_title": {"type": "string"},
                    "revised_verification": {"type": "string"},
                    "revised_targets": {
                        "type": "array",
                        "items": {"type": "object"},
                        "default": [],
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "read_ida_call_flow_scope",
            "description": (
                "List active claim-scoped direct-call investigations when scope_id "
                "is omitted, or read one bounded scope. Open nodes are exact "
                "internal callees that require inspection and a claim-impact "
                "disposition before the parent can be revalidated."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "scope_id": {"type": ["string", "null"], "minLength": 1},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 50},
                    "offset": {"type": "integer", "minimum": 0},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "disposition_ida_call_flow_node",
            "description": (
                "Triage the current depth-first callee, or reconcile an expanded "
                "boundary after its descendants close. supports_parent_claim is "
                "terminal. unresolved_boundary alone expands and requires the "
                "question, claim impact, evidence gap, expected evidence, and exact "
                "direct callees to admit. If terminal support depends on another "
                "function, open that boundary even if it was inspected earlier. "
                "The host validates exact target identity and current topology."
            ),
            "input_schema": {
                "type": "object",
                "required": [
                    "scope_id", "node_id", "outcome", "rationale",
                    "evidence_refs",
                ],
                "properties": {
                    "scope_id": {"type": "string", "minLength": 1},
                    "node_id": {"type": "string", "minLength": 1},
                    "outcome": {
                        "enum": [
                            "supports_parent_claim",
                            "unresolved_boundary",
                            "contradicts_parent_claim",
                            "nonmaterial",
                            "deferred",
                            "uncertain",
                        ]
                    },
                    "rationale": {"type": "string", "minLength": 1},
                    "evidence_refs": {
                        "type": "array",
                        "items": {"type": "string", "minLength": 1},
                        "minItems": 1,
                        "uniqueItems": True,
                    },
                    "boundary_question": {"type": "string"},
                    "claim_impact": {"type": "string"},
                    "evidence_gap": {"type": "string"},
                    "expected_evidence": {"type": "string"},
                    "boundary_callees": {
                        "type": "array",
                        "items": {"type": "string", "minLength": 1},
                        "minItems": 1,
                        "uniqueItems": True,
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "revalidate_ida_function_claim",
            "description": (
                "Reinspect and disposition the scoped parent after all admitted "
                "direct callees have been triaged. Confirmation needs fresh parent "
                "evidence; revision or narrowing also needs the verified parent "
                "operation IDs."
            ),
            "input_schema": {
                "type": "object",
                "required": [
                    "scope_id", "outcome", "parent_evidence_id", "rationale"
                ],
                "properties": {
                    "scope_id": {"type": "string", "minLength": 1},
                    "outcome": {
                        "enum": [
                            "confirmed", "revised", "narrowed", "open_uncertainty"
                        ]
                    },
                    "parent_evidence_id": {"type": "string", "minLength": 1},
                    "rationale": {"type": "string", "minLength": 1},
                    "operation_ids": {
                        "type": "array",
                        "items": {"type": "string", "minLength": 1},
                        "uniqueItems": True,
                        "default": [],
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "promote_ida_suggestion",
            "description": (
                "Explicitly promote one suggested_next item into blocking must_review "
                "because the model intends to investigate it."
            ),
            "input_schema": {
                "type": "object",
                "required": ["candidate_id", "rationale"],
                "properties": {
                    "candidate_id": {"type": "string", "minLength": 1},
                    "rationale": {"type": "string", "minLength": 1},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "abandon_ida_operation",
            "description": (
                "Explicitly abandon the intent of a current failed mechanical "
                "operation. The failed request and receipt remain in SQLite history. "
                "A successful same-surface retry supersedes earlier failed attempts; "
                "check operation_resolution in the edit result. Superseded failures "
                "need no abandonment. Repeatable and nonrepeatable comments are separate surfaces."
            ),
            "input_schema": {
                "type": "object",
                "required": ["operation_id", "rationale"],
                "properties": {
                    "operation_id": {"type": "string", "minLength": 1},
                    "rationale": {"type": "string", "minLength": 1},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "list_ida_components",
            "description": (
                "List the root and recovered child binaries and their separate IDBs. "
                "Recovery evidence retained in component provenance is labeled "
                "historical_evidence_refs and is lineage only; reacquire current "
                "evidence before using it to support a new claim."
            ),
            "input_schema": {"type": "object", "additionalProperties": False},
        },
        {
            "name": "recover_ida_component",
            "description": (
                "Recover and structurally validate a suspected child artifact from "
                "one or more parent byte ranges. Use extraction.method='copy' for "
                "identity carving; consult describe_ida_capabilities.component_recovery "
                "for transforms, limits, and examples. The host does not decide its role."
            ),
            "input_schema": {
                "type": "object",
                "required": [
                    "parent_component_id",
                    "locators",
                    "extraction",
                    "expected_result",
                    "loader_decoder",
                    "evidence_refs",
                ],
                "properties": {
                    "parent_component_id": {"type": "string", "minLength": 1},
                    "locators": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 16,
                        "items": SOURCE_LOCATOR,
                    },
                    "extraction": {
                        "type": "object",
                        "required": ["method"],
                        "properties": {
                            "method": {
                                "enum": [
                                    "copy", "raw", "xor", "zlib", "gzip", "bz2",
                                    "lzma", "base64", "hex", "bounded_emulation",
                                    "python_static",
                                ]
                            },
                            "parameters": {"type": "object"},
                            "script_path": {"type": "string"},
                            "inputs": {
                                "type": "array",
                                "maxItems": 15,
                                "items": {
                                    "type": "object",
                                    "required": ["name", "locator"],
                                    "properties": {
                                        "name": {
                                            "type": "string",
                                            "pattern": "^[A-Za-z][A-Za-z0-9_]{0,63}$",
                                        },
                                        "locator": SOURCE_LOCATOR,
                                    },
                                    "additionalProperties": False,
                                },
                            },
                        },
                        "additionalProperties": False,
                    },
                    "expected_result": {
                        "type": "object",
                        "required": ["artifact_kind"],
                        "properties": {
                            "artifact_kind": {
                                "enum": [
                                    "pe", "elf", "macho", "shellcode", "archive",
                                    "script", "bytecode", "config", "data",
                                ]
                            },
                            "architecture": {"type": ["string", "null"]},
                            "description": {"type": ["string", "null"]},
                            "base_address": {"anyOf": [ADDRESS, {"type": "null"}]},
                            "entry_offset": {"anyOf": [ADDRESS, {"type": "null"}]},
                        },
                        "additionalProperties": False,
                    },
                    "loader_decoder": {
                        "type": "object",
                        "required": ["function_ea", "summary"],
                        "properties": {
                            "function_ea": ADDRESS,
                            "summary": {"type": "string", "minLength": 1},
                            "evidence_refs": evidence,
                        },
                        "additionalProperties": False,
                    },
                    "evidence_refs": {**evidence, "minItems": 1},
                    "reason": {"type": ["string", "null"]},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "write_static_extractor",
            "description": (
                "Validate and store one restricted model-authored Python byte "
                "transform for a later python_static component recovery request."
            ),
            "input_schema": {
                "type": "object",
                "required": ["relative_path", "source"],
                "properties": {
                    "relative_path": {
                        "type": "string",
                        "pattern": "^extractors/[A-Za-z0-9_.-]+[.]py$",
                    },
                    "source": {"type": "string", "minLength": 1},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "decide_ida_component",
            "description": (
                "Accept, revise, reject, or defer a recovered artifact. Acceptance verifies "
                "retained bytes. Loadable artifacts get a child IDB; non-loadable data "
                "remains linked to its parent without an IDB. Neither means analysis is complete."
            ),
            "input_schema": {
                "type": "object",
                "required": ["extraction_id", "decision", "rationale", "evidence_refs"],
                "properties": {
                    "extraction_id": {"type": "string", "minLength": 1},
                    "decision": {"enum": ["accept", "revise", "reject", "defer"]},
                    "rationale": {"type": "string", "minLength": 1},
                    "evidence_refs": evidence,
                    "next_request": {"type": ["object", "null"]},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "switch_ida_component",
            "description": "Checkpoint the current IDB and activate another accepted component IDB.",
            "input_schema": {
                "type": "object",
                "required": ["component_id"],
                "properties": {"component_id": {"type": "string", "minLength": 1}},
                "additionalProperties": False,
            },
        },
        {
            "name": "review_analysis_closure",
            "description": (
                "Assemble a read-only advisory review from the current objective, "
                "notebook, verified edits, component graph, exact operational "
                "frontier, and bounded live IDA evidence. It asks consistency "
                "questions only, creates no completion blocker, and requests an "
                "updated Closure Review notebook section before completion."
            ),
            "input_schema": {"type": "object", "additionalProperties": False},
        },
        {
            "name": "complete_ida_investigation",
            "description": (
                "Require no open must_review item, current mechanical failure, or "
                "undecided recovery, require a fresh notebook-to-IDB closure "
                "reconciliation, then freshly verify every component IDB. "
                "Unpromoted suggested_next items never block completion."
            ),
            "input_schema": {"type": "object", "additionalProperties": False},
        },
    ]
